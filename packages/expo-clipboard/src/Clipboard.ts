import { EventEmitter, Subscription, UnavailabilityError, Platform } from 'expo-modules-core';

import ExpoClipboard from './ExpoClipboard';

const emitter = new EventEmitter(ExpoClipboard);

const onClipboardEventName = 'onClipboardChanged';

type ClipboardEvent = {
  /**
   * The new content of the user's clipboard.
   */
  content: string;
};

export { Subscription, EventEmitter, ClipboardEvent };

/**
 * Gets the content of the user's clipboard. Please note that calling this method on web will prompt
 * the user to grant your app permission to "see text and images copied to the clipboard."
 *
 * @returns A promise that resolves to the content of the clipboard.
 */
export async function getStringAsync(): Promise<string> {
  if (!ExpoClipboard.getStringAsync) {
    throw new UnavailabilityError('Clipboard', 'getStringAsync');
  }
  return await ExpoClipboard.getStringAsync();
}

/**
 * Sets the content of the user's clipboard.
 *
 * @param text The string to save to the clipboard.
 *
 * @returns On web, this returns a promise that fulfills to a boolean value indicating whether or not
 * the string was saved to the user's clipboard. On iOS and Android, the promise always resolves to `true`.
 */
export async function setStringAsync(text: string): Promise<boolean> {
  if (!ExpoClipboard.setStringAsync) {
    throw new UnavailabilityError('Clipboard', 'setStringAsync');
  }
  return ExpoClipboard.setStringAsync(text);
}

/**
 * Sets the content of the user's clipboard.
 * @deprecated Deprecated. Use [`setStringAsync()`](#setstringasynctext) instead.
 *
 * @returns On web, this returns a boolean value indicating whether or not the string was saved to
 * the user's clipboard. On iOS and Android, nothing is returned.
 */
export function setString(text: string): void {
  if (Platform.OS === 'web') {
    // on web, we need to return legacy method,
    // because of different return type
    return ExpoClipboard.setString(text);
  } else {
    setStringAsync(text);
  }
}

/**
 * Adds a listener that will fire whenever the content of the user's clipboard changes. This method
 * is a no-op on Web.
 *
 * @param listener Callback to execute when listener is triggered. The callback is provided a
 * single argument that is an object with a `content` key.
 *
 * @example
 * ```typescript
 * addClipboardListener(({ content }: ClipboardEvent) => {
 *   alert('Copy pasta! Here's the string that was copied: ' + content);
 * });
 * ```
 */
export function addClipboardListener(listener: (event: ClipboardEvent) => void): Subscription {
  return emitter.addListener<ClipboardEvent>(onClipboardEventName, listener);
}

/**
 * Removes the listener added by addClipboardListener. This method is a no-op on Web.
 *
 * @param subscription The subscription to remove (created by addClipboardListener).
 *
 * @example
 * ```typescript
 * const subscription = addClipboardListener(() => {
 *   alert('Copy pasta!');
 * });
 * removeClipboardListener(subscription);
 * ```
 */
export function removeClipboardListener(subscription: Subscription) {
  emitter.removeSubscription(subscription);
}
