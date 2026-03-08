// torvex db - hardened drizzle client
// ssl-enforced postgres connection with pool limits

import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema.js";

const client = postgres(process.env.DATABASE_URL, {
  max: 10,
  idle_timeout: 30,
  connect_timeout: 10,
  ssl: "require",
  prepare: false,
});

export const db = drizzle(client, { schema });
