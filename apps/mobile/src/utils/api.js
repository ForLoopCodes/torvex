// torvex mobile - api client for auth and keys
// shared fetch helpers for server communication

import bs58 from "bs58";
import nacl from "tweetnacl";
import {
  deriveAllKeys,
  pubkeyB58,
  generateMnemonic,
  validateMnemonic,
} from "../crypto/keys";
import {
  generateSignedPrekey,
  generateOneTimePrekeys,
  createPrekeyBundle,
} from "../crypto/x3dh";

const API = "http://10.0.2.2:4400";

export async function authenticate(mnemonic) {
  const keys = deriveAllKeys(mnemonic);
  const pubkey = pubkeyB58(keys.identity);

  const challengeRes = await fetch(`${API}/auth/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pubkey }),
  });
  const { challenge } = await challengeRes.json();
  if (!challenge) throw new Error("failed to get challenge");

  const signature = bs58.encode(
    nacl.sign.detached(
      new TextEncoder().encode(challenge),
      keys.identity.secretKey,
    ),
  );

  const verifyRes = await fetch(`${API}/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pubkey, signature }),
  });
  const data = await verifyRes.json();
  if (!verifyRes.ok) throw new Error(data.error);

  const signedPre = generateSignedPrekey(keys.identity.secretKey);
  const otps = generateOneTimePrekeys(10);
  const bundle = createPrekeyBundle(keys.identity, signedPre, otps);

  await fetch(`${API}/keys/bundle`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${data.token}`,
    },
    body: JSON.stringify({
      identityKey: bs58.encode(bundle.identityKey),
      signedPrekey: bs58.encode(bundle.signedPrekey),
      signedPrekeySig: bs58.encode(bundle.signedPrekeySignature),
      oneTimePrekeys: bundle.oneTimePrekeys.map((k) => ({
        id: k.id,
        publicKey: bs58.encode(k.publicKey),
      })),
    }),
  });

  return {
    token: data.token,
    pubkey: data.pubkey,
    keys,
    signedPrekey: signedPre,
    oneTimePrekeys: otps,
  };
}

export async function fetchPrekeyBundle(token, pubkey) {
  const res = await fetch(`${API}/keys/bundle/${pubkey}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  const d = await res.json();
  return {
    identityKey: bs58.decode(d.identityKey),
    signedPrekey: bs58.decode(d.signedPrekey),
    signedPrekeySignature: bs58.decode(d.signedPrekeySig),
    usedOneTimePrekey: d.oneTimePrekey
      ? bs58.decode(d.oneTimePrekey.publicKey)
      : null,
    usedOnePrekeyId: d.oneTimePrekey?.id ?? null,
  };
}

export async function fetchPendingMessages(token) {
  const res = await fetch(`${API}/messages/pending`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return [];
  const { messages } = await res.json();
  return messages || [];
}

export async function checkAndReplenishOtps(token) {
  try {
    const res = await fetch(`${API}/keys/count`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return;
    const { count } = await res.json();
    if (count >= 5) return;
    const otps = generateOneTimePrekeys(10);
    await fetch(`${API}/keys/replenish`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        oneTimePrekeys: otps.map((k) => ({
          id: k.id,
          publicKey: bs58.encode(k.keyPair.publicKey),
        })),
      }),
    });
  } catch {}
}

export async function setDisplayName(token, name) {
  const res = await fetch(`${API}/profile/name`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ displayName: name }),
  });
  return res.ok ? (await res.json()).displayName : null;
}

export async function fetchDisplayName(token, pubkey) {
  try {
    const res = await fetch(`${API}/profile/${pubkey}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    return (await res.json()).displayName;
  } catch {
    return null;
  }
}

export { generateMnemonic, validateMnemonic };
