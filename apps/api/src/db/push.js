// torvex db - manual schema push for supabase
// workaround for drizzle-kit bug with node v24

import "dotenv/config";
import postgres from "postgres";

const sql = postgres(process.env.DATABASE_URL, { ssl: "require" });

await sql`
  CREATE TABLE IF NOT EXISTS users (
    pubkey TEXT PRIMARY KEY,
    display_name TEXT,
    identity_key TEXT,
    signed_prekey TEXT,
    signed_prekey_sig TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  )
`;

await sql`
  ALTER TABLE users
    ADD COLUMN IF NOT EXISTS identity_key TEXT,
    ADD COLUMN IF NOT EXISTS signed_prekey TEXT,
    ADD COLUMN IF NOT EXISTS signed_prekey_sig TEXT
`;

await sql`
  CREATE TABLE IF NOT EXISTS one_time_prekeys (
    id TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL REFERENCES users(pubkey),
    prekey_index INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  )
`;

await sql`
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    from_pubkey TEXT NOT NULL REFERENCES users(pubkey),
    to_pubkey TEXT REFERENCES users(pubkey),
    ciphertext TEXT NOT NULL,
    delivered BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  )
`;

const tables = await sql`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`;
console.log("synced:", tables.map((t) => t.table_name).join(", "));
await sql.end();
