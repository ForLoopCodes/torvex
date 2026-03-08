# AGENTS.md — torvex project context

## project overview

torvex is a zero-knowledge encrypted chat app with wallet-based auth. no passwords, no emails, no plaintext on server. messages are end-to-end encrypted with nacl.box (Curve25519-XSalsa20-Poly1305). the server is a dumb relay that never sees message content.

## architecture

- **monorepo**: npm workspaces + turborepo
- **apps/api**: node.js express + websocket relay (port 4400)
- **apps/web**: react + vite frontend (port 6767)
- **database**: supabase postgresql via drizzle orm (ssl enforced)

## current phase: 1.5+ (hardened auth + e2e encryption)

### what's built

- bip39 24-word seed phrase wallet generation
- phantom (solana) + metamask (ethereum) wallet extension sign-in
- ed25519 + secp256k1 challenge-response auth
- jwt tokens with hs256, jti, 24h expiry, revocation
- rate limiting (10/min on auth endpoints)
- e2e encrypted chat — nacl.box per-recipient encryption
- x25519 key exchange via websocket
- zero-knowledge server — db stores only `[e2e:N]`
- websocket rate limiting (10 msg/sec), payload limits (32kb)
- per-ip connection limiting (5 max)
- helmet security headers (csp, hsts, referrer-policy)
- graceful shutdown handlers

### auth flow

1. user generates/restores 24-word bip39 mnemonic, or connects phantom/metamask
2. derives ed25519 signing keypair + x25519 encryption keypair from seed (wallet extensions get ephemeral x25519)
3. sends identity (pubkey or eth address) to `POST /auth/challenge`
4. server returns `torvex-auth:{32-byte-nonce}:{timestamp}` (30s ttl, one-time)
5. client signs challenge with private key (ed25519 or personal_sign)
6. sends to `POST /auth/verify` — server validates signature type (0x prefix = eth, else ed25519)
7. server returns jwt (hs256, jti, 24h expiry)
8. client connects websocket with `?token=jwt&encPub=x25519PublicKey`
9. server broadcasts x25519 pubkeys to all peers for key exchange

### e2e encryption flow

1. each client generates x25519 keypair (deterministic from seed, or ephemeral for wallet extensions)
2. on ws connect, x25519 pubkeys exchanged via `key_announce` messages
3. sender encrypts message per-recipient: `nacl.box(msg, nonce, recipientPub, senderSecret)`
4. server relays encrypted blobs to each recipient, stores only `[e2e:N]` in db
5. recipient decrypts: `nacl.box.open(ciphertext, nonce, senderPub, recipientSecret)`
6. server sends `chat_ack` to sender (no plaintext echoed back)

## file structure

```
torvex/
├── plan.md                      (full 5-phase roadmap, DO NOT EDIT)
├── AGENTS.md
├── README.md
├── LICENSE                      (source available license)
├── turbo.json
├── package.json                 (npm workspaces root)
├── apps/
│   ├── api/
│   │   ├── .env                 (PORT, DATABASE_URL, JWT_SECRET, ALLOWED_ORIGINS)
│   │   ├── drizzle.config.js
│   │   ├── package.json
│   │   └── src/
│   │       ├── server.js        (express + ws + hardened auth + encrypted relay)
│   │       └── db/
│   │           ├── index.js     (drizzle client, ssl, pooling)
│   │           └── schema.js    (users, messages tables)
│   └── web/
│       ├── .env                 (VITE_API_URL, VITE_WS_URL)
│       ├── vite.config.js       (buffer polyfill, proxy)
│       ├── index.html
│       ├── package.json
│       └── src/
│           ├── polyfills.js     (buffer global for browser crypto)
│           ├── main.jsx
│           ├── App.jsx
│           ├── styles.css       (dark theme, wallet buttons)
│           └── views/
│               ├── Auth.jsx     (seed + phantom + metamask auth)
│               └── Chat.jsx     (e2e encrypted ws chat)
```

## security features

| layer | protection |
|---|---|
| auth | jwt hs256 + jti + revocation, 30s one-time challenges, csprng nonces |
| http | helmet (csp, hsts, xss, clickjack), cors lockdown, 8kb body limit, rate limiting |
| websocket | 10 msg/sec rate limit, 32kb max payload, 5 conn/ip, encpub validation |
| encryption | nacl.box (curve25519-xsalsa20-poly1305), per-recipient, client-side only |
| database | ssl enforced, only `[e2e:N]` stored, connection pooling (max 10) |
| operational | graceful shutdown, request id tracing, no error detail leakage |

## key conventions

- all file comments: exactly 2 lines at top, 10 words each
- no redundant variables — chain calls when possible
- functions <20 lines used once = inline them
- strict ordering: imports → enums → structs → logic
- env vars: backend uses `dotenv/config`, frontend uses `import.meta.env.VITE_*`
- identity = base58 ed25519 pubkey OR 0x eth address

## env vars

### apps/api/.env
- `PORT` — server port (default 4400)
- `DATABASE_URL` — supabase postgres connection string
- `JWT_SECRET` — 64+ char hex secret for jwt signing
- `ALLOWED_ORIGINS` — comma-separated cors origins (optional)
- `NODE_ENV` — set to `production` for hsts + trust proxy

### apps/web/.env
- `VITE_API_URL` — backend http url
- `VITE_WS_URL` — backend websocket url

## api endpoints

- `POST /auth/challenge` — get one-time challenge for pubkey
- `POST /auth/verify` — submit signed challenge for jwt
- `GET /auth/me` — verify jwt, get pubkey
- `POST /auth/revoke` — revoke current jwt

## ws message types

- `user_joined` — new user connected (includes encPub)
- `user_left` — user disconnected
- `key_announce` — x25519 key exchange
- `chat` — encrypted message (nonce + ciphertext per recipient)
- `chat_ack` — server confirms message relay
- `error` — rate limit or validation error

## next phases (from plan.md)

- **phase 2**: react native android port + qr code scanning
- **phase 3**: rewrite backend in rust + cassandra
- **phase 4**: tor hidden service routing (paid tier)
- **phase 5**: native swift ios + post-quantum crypto (ml-kem)

## running the project

```bash
npm install
cd apps/api && node src/server.js
cd apps/web && npx vite --host
```
