function tryResolveModule(module) {
  try {
    return require.resolve(module);
  } catch (e) {
    console.error(`Couldn't resolve vendored module - ${module}.`);
    return null;
  }
}

module.exports = function (api) {
  api.cache(true);

  const gestureHandler = tryResolveModule(
    'expo-dev-menu/vendored/react-native-gesture-handler/src/index.js'
  );
  const safeAreaContext = tryResolveModule(
    'expo-dev-menu/vendored/react-native-safe-area-context/src/index.tsx'
  );

  const gestureHandlerJest = tryResolveModule(
    'expo-dev-menu/vendored/react-native-gesture-handler/src/jestSetup.js'
  );

  const alias = {};
  if (gestureHandler) {
    alias['react-native-gesture-handler/jestSetup'] = gestureHandlerJest;
    alias['react-native-gesture-handler'] = gestureHandler;
  }

  if (safeAreaContext) {
    alias['react-native-safe-area-context'] = safeAreaContext;
  }

  const moduleResolverConfig = {
    alias,
  };

  return {
    presets: ['babel-preset-expo'],
    plugins: [['babel-plugin-module-resolver', moduleResolverConfig]],
  };
};
