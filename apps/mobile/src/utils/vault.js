// torvex mobile - pin-encrypted key vault
// pbkdf2 + aes-256-gcm via react-native-quick-crypto

import QuickCrypto from "react-native-quick-crypto";
import bs58 from "bs58";
import { storage } from "./storage";

const VAULT_KEY = "torvex_vault";
const DEVICE_KEY = "torvex_device_id";
const SALT = Buffer.from("torvex-vault-v1");
const ITERATIONS = 300000;

export function getDeviceId() {
  let id = storage.getItem(DEVICE_KEY);
  if (!id) {
    id = QuickCrypto.randomUUID();
    storage.setItem(DEVICE_KEY, id);
  }
  return id;
}

function deriveKey(pin) {
  return QuickCrypto.pbkdf2Sync(pin, SALT, ITERATIONS, 32, "sha256");
}

export function encryptVault(pin, mnemonic) {
  const key = deriveKey(pin);
  const iv = QuickCrypto.randomBytes(12);
  const cipher = QuickCrypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(mnemonic, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  const data = {
    iv: bs58.encode(iv),
    ct: bs58.encode(Buffer.concat([encrypted, tag])),
  };
  storage.setItem(VAULT_KEY, JSON.stringify(data));
}

export function decryptVault(pin) {
  const raw = storage.getItem(VAULT_KEY);
  if (!raw) return null;
  const { iv, ct } = JSON.parse(raw);
  const key = deriveKey(pin);
  const buf = Buffer.from(bs58.decode(ct));
  const encrypted = buf.slice(0, buf.length - 16);
  const tag = buf.slice(buf.length - 16);
  const decipher = QuickCrypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(bs58.decode(iv)),
  );
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]).toString("utf8");
}

export function hasVault() {
  return !!storage.getItem(VAULT_KEY);
}

export function clearVault() {
  storage.removeItem(VAULT_KEY);
}
