# AGENTS.md — torchat project context

## project overview

torchat is an encrypted anonymous chat app using wallet-based authentication (BIP39 seed phrases + Ed25519 keypairs). no passwords, no emails. your private key IS your identity.

## architecture

- **monorepo**: npm workspaces + turborepo
- **apps/api**: node.js express + websocket signaling server (port 4400)
- **apps/web**: react + vite frontend (port 6767)
- **database**: supabase postgresql via drizzle orm

## current phase: 1.5 (wallet auth complete)

### what's built

- bip39 24-word seed phrase wallet generation in browser
- ed25519 challenge-response auth (no passwords)
- websocket chat relay with pubkey identity
- drizzle orm schema (users + messages tables)
- dark theme chat ui

### auth flow

1. frontend generates/restores 24-word bip39 mnemonic
2. derives ed25519 keypair from seed (first 32 bytes)
3. sends pubkey to `POST /auth/challenge`
4. server returns a random challenge string
5. frontend signs challenge with private key
6. sends signature to `POST /auth/verify`
7. server verifies ed25519 signature, returns session token
8. frontend connects websocket with `?token=xxx`

## file structure

```
torchat/
├── plan.md                      (full 5-phase roadmap, DO NOT EDIT)
├── turbo.json
├── package.json                 (npm workspaces root)
├── apps/
│   ├── api/
│   │   ├── .env                 (DATABASE_URL, PORT)
│   │   ├── drizzle.config.js
│   │   └── src/
│   │       ├── server.js        (express + ws + wallet auth)
│   │       └── db/
│   │           ├── index.js     (drizzle client)
│   │           └── schema.js    (users, messages tables)
│   └── web/
│       ├── .env                 (VITE_API_URL, VITE_WS_URL)
│       ├── vite.config.js
│       ├── index.html
│       └── src/
│           ├── main.jsx
│           ├── App.jsx
│           ├── styles.css
│           └── views/
│               ├── Auth.jsx     (wallet generation + challenge sign)
│               └── Chat.jsx     (websocket chat ui)
```

## key conventions

- all file comments: exactly 2 lines at top, 10 words each
- no redundant variables — chain calls when possible
- functions <20 lines used once = inline them
- strict ordering: imports → enums → structs → logic
- env vars: backend uses `dotenv/config`, frontend uses `import.meta.env.VITE_*`
- identity = base58-encoded ed25519 public key (no usernames)

## next phases (from plan.md)

- **phase 2**: react native android port + qr code scanning
- **phase 3**: rewrite backend in rust + cassandra
- **phase 4**: tor hidden service routing (paid tier)
- **phase 5**: native swift ios + post-quantum crypto (ml-kem)

## api keys needed

- **supabase**: project url + anon key from https://supabase.com/dashboard
- set `DATABASE_URL` in `apps/api/.env` to your supabase postgres connection string

## running the project

```bash
npm install          # install all workspace deps
cd apps/api && node src/server.js   # start backend on :4400
cd apps/web && npx vite --port 6767 # start frontend on :6767
```
