import { open, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { databaseCommand } from "./compose-database.mjs";

const [destination, ...extra] = process.argv.slice(2);
if (!destination || extra.length) throw new Error("Usage : npm run db:backup -- /chemin/sauvegarde.dump");
const path = resolve(destination);
// Refuse to replace an existing archive; restrict access to its owner.
const file = await open(path, "wx", 0o600);
let complete = false;
try {
  await databaseCommand([
    "pg_dump", "--username=africheck", "--dbname=africheck", "--format=custom",
    "--no-acl", "--exclude-table-data=public.api_rate_limits",
  ], { output: file.fd });
  await file.sync();
  complete = true;
} finally {
  await file.close();
  if (!complete) await unlink(path).catch(() => undefined);
}
console.info(JSON.stringify({ event: "database.backup_completed", path }));
