import { getUserStatePath } from '@expo/config/build/getUserState';
import fs from 'fs-extra';
import { vol } from 'memfs';
import nock from 'nock';

import { getExpoApiBaseUrl } from '../../endpoint';
import { getSessionSecret } from '../sessionStorage';
import { Actor, getActorDisplayName, getUserAsync, loginAsync, logoutAsync } from '../user';

jest.mock('fs');
jest.mock('../../graphql/client', () => ({
  graphqlClient: {
    query: () => {
      return {
        toPromise: () =>
          Promise.resolve({ data: { viewer: { id: 'USER_ID', username: 'USERNAME' } } }),
      };
    },
  },
}));
jest.mock('../../graphql/queries/UserQuery', () => ({
  UserQuery: {
    currentUserAsync: async () => ({ __typename: 'User', username: 'USERNAME', id: 'USER_ID' }),
  },
}));

beforeEach(() => {
  vol.reset();
});

const userStub: Actor = {
  __typename: 'User',
  id: 'userId',
  username: 'username',
  accounts: [],
  isExpoAdmin: false,
};

const robotStub: Actor = {
  __typename: 'Robot',
  id: 'userId',
  firstName: 'GLaDOS',
  accounts: [],
  isExpoAdmin: false,
};

function mockLoginRequest() {
  nock(getExpoApiBaseUrl())
    .post('/v2/auth/loginAsync')
    .reply(200, { data: { sessionSecret: 'SESSION_SECRET' } });
}

describe(getUserAsync, () => {
  it('skips fetching user without access token or session secret', async () => {
    expect(await getUserAsync()).toBeUndefined();
  });

  it('fetches user when access token is defined', async () => {
    process.env.EXPO_TOKEN = 'accesstoken';
    expect(await getUserAsync()).toMatchObject({ __typename: 'User' });
  });

  it('fetches user when session secret is defined', async () => {
    mockLoginRequest();

    await loginAsync({ username: 'USERNAME', password: 'PASSWORD' });
    expect(await getUserAsync()).toMatchObject({ __typename: 'User' });
  });
});

describe(loginAsync, () => {
  it('saves user data to ~/.expo/state.json', async () => {
    mockLoginRequest();
    await loginAsync({ username: 'USERNAME', password: 'PASSWORD' });

    expect(await fs.readFile(getUserStatePath(), 'utf8')).toMatchInlineSnapshot(`
      "{
        \\"auth\\": {
          \\"sessionSecret\\": \\"SESSION_SECRET\\",
          \\"userId\\": \\"USER_ID\\",
          \\"username\\": \\"USERNAME\\",
          \\"currentConnection\\": \\"Username-Password-Authentication\\"
        }
      }
      "
    `);
  });
});

describe(logoutAsync, () => {
  it('removes the session secret', async () => {
    mockLoginRequest();
    await loginAsync({ username: 'USERNAME', password: 'PASSWORD' });
    expect(getSessionSecret()).toBe('SESSION_SECRET');

    await logoutAsync();
    expect(getSessionSecret()).toBe(null);
  });
});

describe(getActorDisplayName, () => {
  it('returns anonymous for unauthenticated users', () => {
    expect(getActorDisplayName()).toBe('anonymous');
  });

  it('returns username for user actors', () => {
    expect(getActorDisplayName(userStub)).toBe(userStub.username);
  });

  it('returns firstName with robot prefix for robot actors', () => {
    expect(getActorDisplayName(robotStub)).toBe(`${robotStub.firstName} (robot)`);
  });

  it('returns robot prefix only for robot actors without firstName', () => {
    expect(getActorDisplayName({ ...robotStub, firstName: undefined })).toBe('robot');
  });
});
