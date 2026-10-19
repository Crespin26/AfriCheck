import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:https";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const image = process.argv[2] ?? "africheck:ci";
const directory = await mkdtemp(join(tmpdir(), "africheck-proxy-"));
const override = join(directory, "compose.test.yaml");
process.env.COMPOSE_FILE = [resolve("compose.yaml"), resolve("compose.production.yaml"), override].join(delimiter);
process.env.COMPOSE_PROJECT_NAME = `africheck-proxy-${randomBytes(6).toString("hex")}`;
process.env.AFRICHECK_DOMAIN = "localhost";
for (const key of ["POSTGRES_PASSWORD", "DOMAIN_VERIFICATION_KEY", "REPORT_SIGNING_KEY", "LOG_HASH_KEY"]) {
  process.env[key] = randomBytes(32).toString("hex");
}
await writeFile(override, `services:
  database:
    volumes: !reset []
    tmpfs:
      - /var/lib/postgresql/data
    healthcheck:
      interval: 1s
  app:
    image: ${JSON.stringify(image)}
    healthcheck:
      interval: 1s
  proxy:
    ports: !override
      - "127.0.0.1::80"
      - "127.0.0.1::443"
  client:
    image: ${JSON.stringify(image)}
    networks:
      - edge
`, { mode: 0o600 });

const compose = (...args) => exec("docker", ["compose", ...args], { maxBuffer: 2_000_000 });
const port = async (number) => Number((await compose("port", "proxy", String(number))).stdout.trim().split(":").at(-1));
let client;

try {
  const config = JSON.parse((await compose("config", "--format", "json")).stdout);
  assert.ok(!config.services.app.ports?.length, "Le port applicatif ne doit pas être publié.");
  assert.ok(!config.services.database.ports?.length, "Le port PostgreSQL ne doit pas être publié.");
  assert.equal(config.services.app.environment.TRUST_PROXY_HEADERS, "true");
  assert.equal(config.services.app.environment.CLIENT_IP_HEADER, "x-forwarded-for");
  assert.equal(config.networks.backend.internal, true);
  assert.deepEqual(Object.keys(config.services.proxy.networks), ["edge"]);
  await compose("up", "--detach", "--no-build", "--wait", "--wait-timeout", "60", "proxy");

  const ca = (await compose("exec", "-T", "proxy", "cat", "/data/caddy/pki/authorities/local/root.crt")).stdout;
  const httpsPort = await port(443);
  const secureGet = (path) => new Promise((resolveRequest, reject) => {
    const req = request({ hostname: "127.0.0.1", port: httpsPort, servername: "localhost", ca, path,
      headers: { host: "localhost" } }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; });
      response.on("end", () => resolveRequest({ status: response.statusCode, headers: response.headers, body }));
    });
    req.on("error", reject);
    req.end();
  });
  const ready = await secureGet("/api/ready");
  assert.equal(ready.status, 200);
  assert.equal(JSON.parse(ready.body).checks.history, "ok");
  const home = await secureGet("/");
  assert.equal(home.status, 200);
  assert.match(home.body, /AfriCheck/);
  assert.ok(home.headers["strict-transport-security"]);
  const httpPort = await port(80);
  const redirect = await new Promise((resolveRequest, reject) => {
    const req = httpRequest({ hostname: "127.0.0.1", port: httpPort, path: "/", headers: { host: "localhost" } }, (response) => {
      response.resume();
      response.on("end", () => resolveRequest({ status: response.statusCode, location: response.headers.location }));
    });
    req.on("error", reject);
    req.end();
  });
  assert.equal(redirect.status, 308);
  assert.equal(redirect.location, "https://localhost/");

  // Keep the first client alive so the second receives a different network IP.
  client = (await compose("run", "--detach", "--no-deps", "client", "node", "-e", "setInterval(() => {}, 1000)")).stdout.trim();
  const caEnv = `TEST_CA=${Buffer.from(ca).toString("base64")}`;
  const sender = `const https=require("node:https");(async()=>{const statuses=[];for(let i=0;i<Number(process.env.REQUEST_COUNT);i++){statuses.push(await new Promise((resolve,reject)=>{const req=https.request({hostname:"proxy",servername:"localhost",ca:Buffer.from(process.env.TEST_CA,"base64"),path:"/api/scan",method:"POST",headers:{host:"localhost","content-type":"application/json","x-forwarded-for":"203.0.113."+(i+1),"cf-connecting-ip":"198.51.100."+(i+1),"x-vercel-forwarded-for":"192.0.2."+(i+1)}},res=>{res.resume();res.on("end",()=>resolve(res.statusCode))});req.on("error",reject);req.end(JSON.stringify({url:"http://127.0.0.1"}))}))}console.log(JSON.stringify(statuses))})().catch(e=>{console.error(e.message);process.exitCode=1})`;
  const first = await exec("docker", ["exec", "--env", caEnv, "--env", "REQUEST_COUNT=6", client, "node", "-e", sender]);
  assert.deepEqual(JSON.parse(first.stdout), [422, 422, 422, 422, 422, 429]);
  const second = await compose("run", "--rm", "--no-deps", "--env", caEnv, "--env", "REQUEST_COUNT=1", "client", "node", "-e", sender);
  assert.deepEqual(JSON.parse(second.stdout), [422]);
  console.info(JSON.stringify({ event: "proxy.test_passed", tlsValidated: true, httpsRedirect: true, privateApplication: true, spoofedHeadersIgnored: true, separateClientQuotas: true }));
} finally {
  try {
    if (client) await exec("docker", ["rm", "--force", client]).catch(() => undefined);
    await compose("down", "--volumes", "--remove-orphans");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
