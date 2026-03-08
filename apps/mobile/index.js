// torvex mobile - app entry with buffer polyfill
// registers root component for react native runtime

import { Buffer } from "buffer";
global.Buffer = Buffer;

import { AppRegistry } from "react-native";
import App from "./App";
import { name as appName } from "./app.json";

AppRegistry.registerComponent(appName, () => App);
