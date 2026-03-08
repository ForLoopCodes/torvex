// torchat db - drizzle schema for users and messages
// stores wallet pubkeys and encrypted message queue

import { pgTable, text, timestamp, boolean } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  pubkey: text("pubkey").primaryKey(),
  displayName: text("display_name"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const messages = pgTable("messages", {
  id: text("id").primaryKey(),
  fromPubkey: text("from_pubkey").notNull().references(() => users.pubkey),
  toPubkey: text("to_pubkey").references(() => users.pubkey),
  ciphertext: text("ciphertext").notNull(),
  delivered: boolean("delivered").default(false),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
