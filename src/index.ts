import https from "node:https";
import path from "node:path";
import { createApp } from "./app.js";
import { loadConfig, watchConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { createSigningKeys } from "./oidc/keys.js";
import { PasswordStore } from "./oidc/passwords.js";
import { OidcState } from "./oidc/state.js";
import { loadTlsOptions } from "./tls.js";

const configPath = process.env.CONFIG_PATH ?? "config.json";
const refreshTokenStorePath = path.join(path.dirname(path.resolve(configPath)), "refresh-tokens.json");
const passwdPath = path.join(path.dirname(path.resolve(configPath)), "passwd");
const adminToken = process.env.OIDC_MOCK_ADMIN_TOKEN;
const sessionSecret = process.env.OIDC_MOCK_SESSION_SECRET;
let config = loadConfig(configPath);
const keys = await createSigningKeys();
const logger = createLogger();
const state = new OidcState(refreshTokenStorePath);
const passwordStore = new PasswordStore(passwdPath);
const app = createApp({
  config: () => config,
  keys,
  logger,
  state,
  passwordStore,
  adminToken,
  sessionSecret,
  configPath,
  onConfigSaved: (saved) => {
    config = saved;
  }
});

watchConfig(configPath, (reloaded) => {
  config = reloaded;
  logger.info("config reloaded", {
    configPath,
    tenantCount: config.tenants.length,
    verbose: config.verbose
  });
}, (error) => {
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
  logger.info("Azure OIDC mock listening", {
    baseUrl: config.baseUrl.replace(/\/$/, ""),
    port,
    protocol: config.tls ? "https" : "http",
    tenantCount: config.tenants.length,
    refreshTokenStorePath,
    passwdPath,
    verbose: config.verbose
  });
});
