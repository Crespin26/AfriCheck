import { access, cp } from "node:fs/promises";

await access(".next/standalone/server.js").catch(() => {
  throw new Error("Compilez d’abord l’application avec npm run build.");
});
await cp("public", ".next/standalone/public", { recursive: true });
await cp(".next/static", ".next/standalone/.next/static", { recursive: true });
