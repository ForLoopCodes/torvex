// torvex mobile - mmkv storage adapter
// replaces localStorage/sessionStorage for react native

import { MMKV } from "react-native-mmkv";

const store = new MMKV({ id: "torvex" });

export const storage = {
  getItem: (key) => store.getString(key) ?? null,
  setItem: (key, val) => store.set(key, val),
  removeItem: (key) => store.delete(key),
};
