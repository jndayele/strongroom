import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const EXE_EXT = process.platform === "win32" ? ".exe" : "";
const DEFAULT_APP_DB_URL =
  "postgres://vault_app:local_app_password_only@127.0.0.1:5432/vault_dev";
const DEFAULT_MIGRATOR_DB_URL =
  "postgres://vault_migrator:local_migrator_password_only@127.0.0.1:5432/vault_dev";

function getBinaryPath(name) {
  const targetRoot = process.env.CARGO_TARGET_DIR
    ? path.resolve(repoRoot, process.env.CARGO_TARGET_DIR)
    : path.join(repoRoot, "target");
  return path.join(targetRoot, "debug", `${name}${EXE_EXT}`);
}

function parsePgHostPort(connectionUrl) {
  let parsed;
  try {
    parsed = new URL(connectionUrl);
  } catch {
    throw new Error("Invalid PostgreSQL connection URL.");
  }
  const host = parsed.hostname || "127.0.0.1";
  const port = parsed.port ? Number.parseInt(parsed.port, 10) : 5432;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid PostgreSQL port in URL: ${String(parsed.port)}`);
  }
  return { host, port };
}

function checkPostgresReachable(host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    const timeoutMs = 2000;

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => {
      socket.destroy();
      resolve();
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error(`Timed out connecting to PostgreSQL at ${host}:${port}`));
    });
    socket.once("error", (err) => {
      socket.destroy();
      reject(err);
    });
  });
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close(() => reject(new Error("Failed to determine free port")));
        return;
      }
      const { port } = address;
      server.close((closeErr) => {
        if (closeErr) {
          reject(closeErr);
        } else {
          resolve(port);
        }
      });
    });
  });
}

function parseSecretsOutput(output) {
  const secrets = {};
  for (const rawLine of output.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const eqIndex = line.indexOf("=");
    if (eqIndex <= 0) continue;
    const key = line.slice(0, eqIndex);
    const val = line.slice(eqIndex + 1);
    secrets[key] = val;
  }

  for (const required of [
    "OPAQUE_SERVER_SETUP",
    "CREDENTIAL_ID_KEY",
    "EMAIL_HASH_KEY",
  ]) {
    if (!secrets[required]) {
      throw new Error(`gen-secrets output missing ${required}`);
    }
  }

  return {
    OPAQUE_SERVER_SETUP: secrets.OPAQUE_SERVER_SETUP,
    CREDENTIAL_ID_KEY: secrets.CREDENTIAL_ID_KEY,
    EMAIL_HASH_KEY: secrets.EMAIL_HASH_KEY,
  };
}

async function waitForHealthz(baseUrl, childProcess) {
  const deadline = Date.now() + 15_000;
  let lastError = "unknown error";

  while (Date.now() < deadline) {
    if (childProcess.exitCode !== null) {
      throw new Error(
        `strongroom-api exited prematurely with code ${String(childProcess.exitCode)}`
      );
    }

    try {
      const response = await fetch(`${baseUrl}/healthz`, {
        credentials: "omit",
      });
      if (response.ok) {
        const body = await response.json();
        if (
          typeof body === "object" &&
          body !== null &&
          body.status === "ok"
        ) {
          return;
        }
      }
      lastError = `HTTP ${String(response.status)}`;
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }

    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  throw new Error(
    `Timed out waiting for ${baseUrl}/healthz (last error: ${lastError})`
  );
}

function runChildAsync(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (signal) {
        reject(new Error(`Process ${command} terminated by signal ${signal}`));
      } else {
        resolve(code ?? 1);
      }
    });
  });
}

async function killServer(childProcess) {
  if (!childProcess || childProcess.exitCode !== null) {
    return;
  }

  await new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (!settled) {
        settled = true;
        resolve();
      }
    };

    childProcess.once("exit", finish);

    try {
      childProcess.kill("SIGTERM");
    } catch {
      finish();
      return;
    }

    const forceTimer = setTimeout(() => {
      if (childProcess.exitCode === null) {
        try {
          childProcess.kill("SIGKILL");
        } catch {
          // ignore
        }
      }
      finish();
    }, 3000);
    forceTimer.unref();
  });
}

async function main() {
  const databaseUrl = process.env.DATABASE_URL || DEFAULT_APP_DB_URL;
  const migratorDatabaseUrl =
    process.env.MIGRATOR_DATABASE_URL || DEFAULT_MIGRATOR_DB_URL;

  // (a) Check Postgres is up before building/running anything
  const { host, port: pgPort } = parsePgHostPort(migratorDatabaseUrl);
  try {
    await checkPostgresReachable(host, pgPort);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    console.error(
      `[integration] PostgreSQL is not reachable at ${host}:${pgPort} (${reason}).`
    );
    console.error(
      "[integration] Start local PostgreSQL (for example: `docker compose -f infra/docker-compose.yml up -d`) and retry."
    );
    process.exitCode = 1;
    return;
  }
  console.log(`[integration] PostgreSQL reachable at ${host}:${pgPort}.`);

  // Build Rust binaries (API, migrate, gen-secrets, server-public-key)
  console.log("[integration] Building Rust binaries (strongroom-api)...");
  const buildArgs = ["build", "-p", "strongroom-api", "--bins"];
  if (process.platform === "win32" && !process.env.CARGO_BUILD_JOBS) {
    buildArgs.push("-j", "1");
  }
  execFileSync("cargo", buildArgs, {
    cwd: repoRoot,
    stdio: "inherit",
    env: {
      ...process.env,
      SQLX_OFFLINE: process.env.SQLX_OFFLINE ?? "true",
    },
  });

  const migrateBin = getBinaryPath("migrate");
  const genSecretsBin = getBinaryPath("gen-secrets");
  const serverPublicKeyBin = getBinaryPath("server-public-key");
  const apiBin = getBinaryPath("strongroom-api");

  for (const binPath of [
    migrateBin,
    genSecretsBin,
    serverPublicKeyBin,
    apiBin,
  ]) {
    if (!fs.existsSync(binPath)) {
      throw new Error(`Expected built binary not found: ${binPath}`);
    }
  }

  // (b) Apply migrations with the migrate binary
  console.log("[integration] Applying database migrations...");
  try {
    execFileSync(migrateBin, [], {
      cwd: repoRoot,
      stdio: "inherit",
      env: {
        ...process.env,
        MIGRATOR_DATABASE_URL: migratorDatabaseUrl,
      },
    });
  } catch {
    console.error(
      "[integration] Database migration failed. Ensure Postgres roles (`vault_migrator`, `vault_app`) and database (`vault_dev`) are initialized."
    );
    process.exitCode = 1;
    return;
  }

  // (c) Generate fresh secrets IN MEMORY via gen-secrets (never written to disk, never printed)
  console.log("[integration] Generating ephemeral server secrets in memory...");
  const secretsStdout = execFileSync(genSecretsBin, [], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const secrets = parseSecretsOutput(secretsStdout);

  const expectedServerPublicKey = execFileSync(serverPublicKeyBin, [], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      OPAQUE_SERVER_SETUP: secrets.OPAQUE_SERVER_SETUP,
    },
  }).trim();

  if (!expectedServerPublicKey) {
    throw new Error("server-public-key returned empty output");
  }

  // (d) Start the built API on a random port and wait for /healthz
  const apiPort = await getFreePort();
  const baseUrl = `http://127.0.0.1:${String(apiPort)}`;
  console.log(`[integration] Starting strongroom-api on ${baseUrl}...`);

  const apiProcess = spawn(apiBin, [], {
    cwd: repoRoot,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      API_HOST: "127.0.0.1",
      API_PORT: String(apiPort),
      APP_ORIGIN: "http://localhost:5173",
      DATABASE_URL: databaseUrl,
      OPAQUE_SERVER_SETUP: secrets.OPAQUE_SERVER_SETUP,
      CREDENTIAL_ID_KEY: secrets.CREDENTIAL_ID_KEY,
      EMAIL_HASH_KEY: secrets.EMAIL_HASH_KEY,
      LOG_LEVEL: "warn",
    },
  });

  // Forward API stderr/stdout diagnostics without ever storing/printing secret env vars
  const apiStderrChunks = [];
  apiProcess.stderr?.on("data", (chunk) => {
    apiStderrChunks.push(chunk.toString("utf8"));
  });

  const onSignal = () => {
    void killServer(apiProcess).finally(() => process.exit(130));
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  try {
    try {
      await waitForHealthz(baseUrl, apiProcess);
    } catch (err) {
      const stderrText = apiStderrChunks.join("").trim();
      if (stderrText) {
        console.error(`[integration] strongroom-api stderr:\n${stderrText}`);
      }
      throw err;
    }
    console.log("[integration] API /healthz is ready. Running Vitest suite...");

    // (e) Run the vitest integration suite
    const vitestEntrypoint = path.join(
      repoRoot,
      "node_modules",
      "vitest",
      "vitest.mjs"
    );
    const authClientDir = path.join(repoRoot, "packages", "auth-client");
    const exitCode = await runChildAsync(
      process.execPath,
      [
        vitestEntrypoint,
        "run",
        "--config",
        "vitest.integration.config.ts",
      ],
      {
        cwd: authClientDir,
        stdio: "inherit",
        env: {
          ...process.env,
          STRONGROOM_API_URL: baseUrl,
          STRONGROOM_EXPECTED_SERVER_PUBLIC_KEY: expectedServerPublicKey,
        },
      }
    );

    process.exitCode = exitCode;
  } finally {
    process.removeListener("SIGINT", onSignal);
    process.removeListener("SIGTERM", onSignal);
    // (f) Always kill the server
    await killServer(apiProcess);
    console.log("[integration] Stopped strongroom-api.");
  }
}

main().catch((err) => {
  console.error(
    `[integration] Fatal error: ${err instanceof Error ? err.message : String(err)}`
  );
  process.exitCode = 1;
});
