import { spawn } from "node:child_process";

/**
 * Exécute un outil PostgreSQL dans le service Docker Compose sans passer par un interpréteur shell.
 */
export function databaseCommand(args, { input = "ignore", output = "inherit" } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", ["compose", "exec", "-T", "database", ...args], {
      stdio: [input, output, "inherit"],
    });
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? resolve() : reject(new Error(`Commande PostgreSQL échouée (code ${code}).`)));
  });
}
