// torvex crypto - x3dh initial key agreement
// extended triple diffie-hellman for session setup

import nacl from "tweetnacl";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

const INFO = new TextEncoder().encode("torvex-x3dh-v1");
const SALT = new Uint8Array(32);

export function generateEphemeralKey() {
  return nacl.box.keyPair();
}

export function generateSignedPrekey(identitySecret) {
  const prekey = nacl.box.keyPair();
  const signature = nacl.sign.detached(prekey.publicKey, identitySecret);
  return { keyPair: prekey, signature };
}

export function generateOneTimePrekeys(count = 10) {
  return Array.from({ length: count }, (_, i) => ({
    id: i,
    keyPair: nacl.box.keyPair(),
  }));
}

export function createPrekeyBundle(identity, signedPrekey, oneTimePrekeys) {
  return {
    identityKey: identity.publicKey,
    signedPrekey: signedPrekey.keyPair.publicKey,
    signedPrekeySignature: signedPrekey.signature,
    oneTimePrekeys: oneTimePrekeys.map((k) => ({
      id: k.id,
      publicKey: k.keyPair.publicKey,
    })),
  };
}

function dh(secretKey, publicKey) {
  return nacl.box.before(publicKey, secretKey);
}

function kdf(dh1, dh2, dh3, dh4) {
  const input = new Uint8Array(
    dh1.length + dh2.length + dh3.length + (dh4 ? dh4.length : 0),
  );
  let offset = 0;
  input.set(dh1, offset);
  offset += dh1.length;
  input.set(dh2, offset);
  offset += dh2.length;
  input.set(dh3, offset);
  offset += dh3.length;
  if (dh4) input.set(dh4, offset);
  return hkdf(sha256, input, SALT, INFO, 32);
}

export function x3dhInitiator(myIdentity, myEphemeral, theirBundle) {
  if (
    !nacl.sign.detached.verify(
      theirBundle.signedPrekey,
      theirBundle.signedPrekeySignature,
      theirBundle.identityKey,
    )
  )
    throw new Error("invalid signed prekey signature");

  const identityDHSecret = nacl.box.keyPair.fromSecretKey(
    myIdentity.secretKey.slice(0, 32),
  ).secretKey;
  const dh1 = dh(identityDHSecret, theirBundle.signedPrekey);
  const dh2 = dh(myEphemeral.secretKey, theirBundle.identityKey);
  const dh3 = dh(myEphemeral.secretKey, theirBundle.signedPrekey);
  const dh4 = theirBundle.usedOneTimePrekey
    ? dh(myEphemeral.secretKey, theirBundle.usedOneTimePrekey)
    : null;

  return {
    sharedSecret: kdf(dh1, dh2, dh3, dh4),
    ephemeralPublic: myEphemeral.publicKey,
    usedOnePrekeyId: theirBundle.usedOnePrekeyId ?? null,
  };
}

export function x3dhResponder(
  myIdentity,
  mySignedPrekey,
  myOneTimePrekey,
  theirIdentityKey,
  theirEphemeralKey,
) {
  const identityDHSecret = nacl.box.keyPair.fromSecretKey(
    myIdentity.secretKey.slice(0, 32),
  ).secretKey;
  const dh1 = dh(mySignedPrekey.secretKey, theirIdentityKey);
  const dh2 = dh(identityDHSecret, theirEphemeralKey);
  const dh3 = dh(mySignedPrekey.secretKey, theirEphemeralKey);
  const dh4 = myOneTimePrekey
    ? dh(myOneTimePrekey.secretKey, theirEphemeralKey)
    : null;

  return kdf(dh1, dh2, dh3, dh4);
}
