// torvex mobile - metro bundler configuration
// merges default rn config with project overrides

const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

module.exports = mergeConfig(getDefaultConfig(__dirname), {});
