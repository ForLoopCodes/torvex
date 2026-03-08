// torvex crypto - bip44 hd key derivation
// slip-0010 ed25519 paths for signing and encryption

import * as bip39 from "bip39";
import { derivePath } from "ed25519-hd-key";
import nacl from "tweetnacl";
import bs58 from "bs58";

const PATHS = {
  solana: "m/44'/501'/0'/0'",
  torvexSign: "m/44'/888'/0'/0'",
  torvexEncrypt: "m/44'/888'/1'/0'",
  torvexPrekey: "m/44'/888'/2'/0'",
};

export function deriveAllKeys(mnemonic) {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const seedHex = seed.toString("hex");

  const signSeed = derivePath(PATHS.torvexSign, seedHex).key;
  const encSeed = derivePath(PATHS.torvexEncrypt, seedHex).key;
  const prekeySeed = derivePath(PATHS.torvexPrekey, seedHex).key;

  return {
    identity: nacl.sign.keyPair.fromSeed(new Uint8Array(signSeed)),
    encryption: nacl.box.keyPair.fromSecretKey(new Uint8Array(encSeed)),
    prekey: nacl.box.keyPair.fromSecretKey(new Uint8Array(prekeySeed)),
  };
}

export function pubkeyB58(keypair) {
  return bs58.encode(keypair.publicKey);
}

export function generateMnemonic() {
  return bip39.generateMnemonic(256);
}

export function validateMnemonic(phrase) {
  return bip39.validateMnemonic(phrase);
}
