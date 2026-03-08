// torvex crypto - bip44 hd key derivation
// pure browser slip-0010 ed25519 via noble hashes

import * as bip39 from "bip39";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import nacl from "tweetnacl";
import bs58 from "bs58";

const HARDENED = 0x80000000;
const PATHS = {
  torvexSign: [44, 888, 0, 0],
  torvexEncrypt: [44, 888, 1, 0],
  torvexPrekey: [44, 888, 2, 0],
};

function slip0010Derive(seed, path) {
  let I = hmac(sha512, new TextEncoder().encode("ed25519 seed"), seed);
  let key = I.slice(0, 32),
    chain = I.slice(32);
  for (const idx of path) {
    const data = new Uint8Array(37);
    data.set(key, 1);
    new DataView(data.buffer).setUint32(33, (idx | HARDENED) >>> 0);
    I = hmac(sha512, chain, data);
    key = I.slice(0, 32);
    chain = I.slice(32);
  }
  return key;
}

export function deriveAllKeys(mnemonic) {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  return {
    identity: nacl.sign.keyPair.fromSeed(
      slip0010Derive(seed, PATHS.torvexSign),
    ),
    encryption: nacl.box.keyPair.fromSecretKey(
      slip0010Derive(seed, PATHS.torvexEncrypt),
    ),
    prekey: nacl.box.keyPair.fromSecretKey(
      slip0010Derive(seed, PATHS.torvexPrekey),
    ),
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
