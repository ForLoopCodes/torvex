// torvex crypto - signal double ratchet protocol
// forward secrecy, post-compromise security, kdf chains

import nacl from "tweetnacl";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import bs58 from "bs58";

const KDF_INFO_ROOT = new TextEncoder().encode("torvex-root-v1");
const KDF_INFO_MSG = new TextEncoder().encode("torvex-msg-v1");
const SALT = new Uint8Array(32);
const MAX_SKIP = 256;

function kdfRoot(rootKey, dhOut) {
  const derived = hkdf(sha256, dhOut, rootKey, KDF_INFO_ROOT, 64);
  return { rootKey: derived.slice(0, 32), chainKey: derived.slice(32, 64) };
}

function kdfChain(chainKey) {
  const msgKey = hkdf(sha256, chainKey, SALT, KDF_INFO_MSG, 32);
  const nextChain = hkdf(sha256, chainKey, msgKey, KDF_INFO_MSG, 32);
  return { chainKey: nextChain, messageKey: msgKey };
}

function dhKeyPair() {
  return nacl.box.keyPair();
}

function dhShared(mySecret, theirPublic) {
  return nacl.box.before(theirPublic, mySecret);
}

function encrypt(key, plaintext) {
  const nonce = nacl.randomBytes(24);
  const ct = nacl.secretbox(new TextEncoder().encode(plaintext), nonce, key);
  return { nonce: bs58.encode(nonce), ciphertext: bs58.encode(ct) };
}

function decrypt(key, nonce, ciphertext) {
  const plain = nacl.secretbox.open(
    bs58.decode(ciphertext),
    bs58.decode(nonce),
    key,
  );
  if (!plain) throw new Error("decryption failed");
  return new TextDecoder().decode(plain);
}

export function initSender(sharedSecret, theirRatchetPub) {
  const dhSelf = dhKeyPair();
  const { rootKey, chainKey } = kdfRoot(
    new Uint8Array(sharedSecret),
    dhShared(dhSelf.secretKey, theirRatchetPub),
  );

  return {
    dhSelf,
    dhRemote: theirRatchetPub,
    rootKey,
    sendChain: { key: chainKey, n: 0 },
    recvChain: null,
    skippedKeys: new Map(),
    sendCount: 0,
    recvCount: 0,
    prevSendCount: 0,
  };
}

export function initReceiver(sharedSecret, dhSelf) {
  return {
    dhSelf,
    dhRemote: null,
    rootKey: new Uint8Array(sharedSecret),
    sendChain: null,
    recvChain: null,
    skippedKeys: new Map(),
    sendCount: 0,
    recvCount: 0,
    prevSendCount: 0,
  };
}

function skipKeys(state, until) {
  if (until - state.recvChain.n > MAX_SKIP)
    throw new Error("too many skipped messages");
  while (state.recvChain.n < until) {
    const { chainKey, messageKey } = kdfChain(state.recvChain.key);
    const skippedId = `${bs58.encode(state.dhRemote)}:${state.recvChain.n}`;
    state.skippedKeys.set(skippedId, messageKey);
    state.recvChain.key = chainKey;
    state.recvChain.n++;
  }
}

function dhRatchetStep(state, theirPub) {
  state.prevSendCount = state.sendChain ? state.sendChain.n : 0;
  state.dhRemote = theirPub;

  const recvDH = dhShared(state.dhSelf.secretKey, theirPub);
  const recvRoot = kdfRoot(state.rootKey, recvDH);
  state.rootKey = recvRoot.rootKey;
  state.recvChain = { key: recvRoot.chainKey, n: 0 };

  state.dhSelf = dhKeyPair();
  const sendDH = dhShared(state.dhSelf.secretKey, theirPub);
  const sendRoot = kdfRoot(state.rootKey, sendDH);
  state.rootKey = sendRoot.rootKey;
  state.sendChain = { key: sendRoot.chainKey, n: 0 };
}

export function ratchetEncrypt(state, plaintext) {
  const { chainKey, messageKey } = kdfChain(state.sendChain.key);
  state.sendChain.key = chainKey;
  const n = state.sendChain.n;
  state.sendChain.n++;
  state.sendCount++;

  const header = {
    dh: bs58.encode(state.dhSelf.publicKey),
    pn: state.prevSendCount,
    n,
  };

  const { nonce, ciphertext } = encrypt(messageKey, plaintext);
  return { header, nonce, ciphertext };
}

export function ratchetDecrypt(state, header, nonce, ciphertext) {
  const theirPub = bs58.decode(header.dh);
  const skippedId = `${header.dh}:${header.n}`;

  if (state.skippedKeys.has(skippedId)) {
    const mk = state.skippedKeys.get(skippedId);
    state.skippedKeys.delete(skippedId);
    state.recvCount++;
    return decrypt(mk, nonce, ciphertext);
  }

  const isNewRatchet =
    !state.dhRemote || !arraysEqual(theirPub, state.dhRemote);

  if (isNewRatchet) {
    if (state.recvChain) skipKeys(state, header.pn);
    dhRatchetStep(state, theirPub);
  }

  skipKeys(state, header.n);

  const { chainKey, messageKey } = kdfChain(state.recvChain.key);
  state.recvChain.key = chainKey;
  state.recvChain.n++;
  state.recvCount++;

  return decrypt(messageKey, nonce, ciphertext);
}

function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function serializeState(state) {
  const skipped = {};
  for (const [k, v] of state.skippedKeys) skipped[k] = bs58.encode(v);

  return JSON.stringify({
    dhSelfPub: bs58.encode(state.dhSelf.publicKey),
    dhSelfSec: bs58.encode(state.dhSelf.secretKey),
    dhRemote: state.dhRemote ? bs58.encode(state.dhRemote) : null,
    rootKey: bs58.encode(state.rootKey),
    sendChain: state.sendChain
      ? { key: bs58.encode(state.sendChain.key), n: state.sendChain.n }
      : null,
    recvChain: state.recvChain
      ? { key: bs58.encode(state.recvChain.key), n: state.recvChain.n }
      : null,
    skipped,
    sendCount: state.sendCount,
    recvCount: state.recvCount,
    prevSendCount: state.prevSendCount,
  });
}

export function deserializeState(json) {
  const d = JSON.parse(json);
  const skippedKeys = new Map();
  for (const [k, v] of Object.entries(d.skipped))
    skippedKeys.set(k, bs58.decode(v));

  return {
    dhSelf: {
      publicKey: bs58.decode(d.dhSelfPub),
      secretKey: bs58.decode(d.dhSelfSec),
    },
    dhRemote: d.dhRemote ? bs58.decode(d.dhRemote) : null,
    rootKey: bs58.decode(d.rootKey),
    sendChain: d.sendChain
      ? { key: bs58.decode(d.sendChain.key), n: d.sendChain.n }
      : null,
    recvChain: d.recvChain
      ? { key: bs58.decode(d.recvChain.key), n: d.recvChain.n }
      : null,
    skippedKeys,
    sendCount: d.sendCount,
    recvCount: d.recvCount,
    prevSendCount: d.prevSendCount,
  };
}
