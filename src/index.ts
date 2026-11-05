import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { createApp } from "./app.js";
import { loadConfig, watchConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { createSigningKeys } from "./oidc/keys.js";
import { MfaStore } from "./oidc/mfa.js";
import { PasskeyStore } from "./oidc/passkeys.js";
import { PasswordStore } from "./oidc/passwords.js";
import { OidcState } from "./oidc/state.js";
import { loadTlsOptions } from "./tls.js";
import { loadOrCreateSessionSecret } from "./oidc/session.js";
import {
  ClientSecretRotationStore,
  loadOrCreateClientSecretRotationKey,
  parseClientSecretRotationAllowlist
} from "./oidc/client-secret-rotation.js";

const configPath = process.env.CONFIG_PATH ?? "config.json";
const refreshTokenStorePath = path.join(path.dirname(path.resolve(configPath)), "refresh-tokens.json");
const passwdPath = path.join(path.dirname(path.resolve(configPath)), "passwd");
const passkeyStorePath = path.join(path.dirname(path.resolve(configPath)), "passkeys.json");
const mfaStorePath = path.join(path.dirname(path.resolve(configPath)), "mfa.json");
const adminToken = process.env.OIDC_MOCK_ADMIN_TOKEN;
if (process.env.OIDC_MOCK_ROTATION_API_TOKEN) {
  throw new Error("OIDC_MOCK_ROTATION_API_TOKEN is no longer supported; use client-authenticated rotation tokens");
}
const rotationManagerId = process.env.OIDC_MOCK_ROTATION_MANAGER_ID || "configured-secret-manager";
const rotationApiAllowlist = parseClientSecretRotationAllowlist(process.env.OIDC_MOCK_ROTATION_ALLOWLIST);
const sessionSecret = process.env.OIDC_MOCK_SESSION_SECRET ?? loadOrCreateSessionSecret(
  path.join(path.dirname(path.resolve(configPath)), "session-secret")
);
let config = loadConfig(configPath);
const rotationStorePath = path.join(path.dirname(path.resolve(configPath)), "client-secret-rotations.json");
const rotationStoreExists = fs.existsSync(rotationStorePath);
const rotationStoreKeyPath = path.join(path.dirname(path.resolve(configPath)), "client-secret-rotation.key");
const clientSecretRotationStore = rotationApiAllowlist.length > 0 || rotationStoreExists
  ? new ClientSecretRotationStore(
    rotationStorePath,
    loadOrCreateClientSecretRotationKey(rotationStoreKeyPath, rotationStoreExists)
  )
  : undefined;
clientSecretRotationStore?.synchronizeConfig(config);
const keys = await createSigningKeys();
const logger = createLogger();
const state = new OidcState(refreshTokenStorePath);
const passwordStore = new PasswordStore(passwdPath);
const passkeyStore = new PasskeyStore(passkeyStorePath);
const mfaStore = new MfaStore(mfaStorePath);
const app = createApp({
  config: () => config,
  keys,
  logger,
  state,
  passwordStore,
  passkeyStore,
  mfaStore,
  adminToken,
  rotationManagerId,
  rotationApiAllowlist,
  clientSecretRotationStore,
  sessionSecret,
  configPath,
  // Keeps the in-process config in sync when the admin UI writes a valid file.
  onConfigSaved: (saved) => {
    config = saved;
    try {
      clientSecretRotationStore?.synchronizeConfig(saved);
    } catch (error) {
      logger.error("client secret rotation config synchronization failed", {
        error: error instanceof Error ? error.message : "unknown error"
      });
    }
  }
});

watchConfig(configPath, (reloaded) => {
  // Hot reload publishes only configs that passed validation.
  config = reloaded;
  try {
    clientSecretRotationStore?.synchronizeConfig(reloaded);
  } catch (error) {
    logger.error("config reloaded but client secret rotation synchronization failed", {
      configPath,
      error: error instanceof Error ? error.message : String(error)
    });
  }
  logger.info("config reloaded", {
    configPath,
    tenantCount: config.tenants.length,
    verbose: config.verbose
  });
}, (error) => {
  // Invalid file changes are logged while the last known-good config remains active.
  logger.error("config reload failed; keeping last valid config", {
    configPath,
    error: error instanceof Error ? error.message : String(error)
  });
});

const port = Number(process.env.PORT ?? config.port);
const server = config.tls
  ? https.createServer(loadTlsOptions(config.tls, configPath), app)
  : app;

server.listen(port, () => {
  // Startup log includes all persistence paths operators may need to mount or inspect.
  logger.info("Azure OIDC mock listening", {
    baseUrl: config.baseUrl.replace(/\/$/, ""),
    port,
    protocol: config.tls ? "https" : "http",
    tenantCount: config.tenants.length,
    refreshTokenStorePath,
    passwdPath,
    passkeyStorePath,
    mfaStorePath,
    verbose: config.verbose
  });
});
