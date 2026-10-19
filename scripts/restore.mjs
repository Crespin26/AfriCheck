/**
 * Restaure une archive custom dans une nouvelle base ; refuse tout remplacement de base existante.
 */
import { open } from "node:fs/promises";
import { databaseCommand } from "./compose-database.mjs";

const [source, database, ...extra] = process.argv.slice(2);
if (!source || !database || extra.length || !/^[a-z][a-z0-9_]{0,62}$/.test(database)) {
  throw new Error("Usage : npm run db:restore -- /chemin/sauvegarde.dump nouvelle_base (lettres minuscules, chiffres et _).");
}
const file = await open(source, "r");
try {
  const header = Buffer.alloc(5);
  await file.read(header, 0, 5, 0);
  if (header.toString() !== "PGDMP") throw new Error("Archive PostgreSQL au format custom requise.");
  // createdb refuse une destination existante ; aucune base n’est supprimée ou remplacée.
  await databaseCommand(["createdb", "--username=africheck", "--template=template0", database]);
  try {
    await databaseCommand([
      "pg_restore", "--username=africheck", `--dbname=${database}`,
      "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl",
    ], { input: file.fd });
  } catch (error) {
    console.error(`La restauration a échoué ; la nouvelle base ${database} est conservée pour inspection.`);
    throw error;
  }
} finally {
  await file.close();
}
console.info(JSON.stringify({ event: "database.restore_completed", database }));
