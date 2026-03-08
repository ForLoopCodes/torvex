// torvex db - schema for users, messages, and prekeys
// supports x3dh prekey bundles and encrypted message store

import {
  pgTable,
  text,
  timestamp,
  boolean,
  integer,
} from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  pubkey: text("pubkey").primaryKey(),
  displayName: text("display_name"),
  identityKey: text("identity_key"),
  signedPrekey: text("signed_prekey"),
  signedPrekeySig: text("signed_prekey_sig"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const oneTimePrekeys = pgTable("one_time_prekeys", {
  id: text("id").primaryKey(),
  pubkey: text("pubkey")
    .notNull()
    .references(() => users.pubkey),
  prekeyIndex: integer("prekey_index").notNull(),
  publicKey: text("public_key").notNull(),
  used: boolean("used").default(false),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const messages = pgTable("messages", {
  id: text("id").primaryKey(),
  fromPubkey: text("from_pubkey")
    .notNull()
    .references(() => users.pubkey),
  toPubkey: text("to_pubkey").references(() => users.pubkey),
  ciphertext: text("ciphertext").notNull(),
  delivered: boolean("delivered").default(false),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
