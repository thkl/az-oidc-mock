import express from "express";
import type { AppConfig } from "./config.js";
import { createLogger, type Logger } from "./logger.js";
import type { SigningKeys } from "./oidc/keys.js";
import { MfaStore } from "./oidc/mfa.js";
import { PasswordStore } from "./oidc/passwords.js";
import { createDefaultSessionSecret } from "./oidc/session.js";
import { OidcState } from "./oidc/state.js";
import { registerAdminRoutes } from "./routes/admin.js";
import { registerInternalRoutes } from "./routes/internal.js";
import { registerOidcRoutes } from "./routes/oidc.js";
import type { RouteContext } from "./routes/types.js";

type AppDeps = {
  config: AppConfig | (() => AppConfig);
  keys: SigningKeys;
  logger?: Logger;
  state?: OidcState;
  passwordStore?: PasswordStore;
  mfaStore?: MfaStore;
  adminToken?: string;
  sessionSecret?: string;
  configPath?: string;
  onConfigSaved?: (config: AppConfig) => void;
};

/**
 * Creates the Express application and wires all tenant-aware OIDC routes.
 */
export function createApp({
  config,
  keys,
  logger = createLogger(),
  state = new OidcState(),
  passwordStore = new PasswordStore(),
  mfaStore = new MfaStore(),
  adminToken,
  sessionSecret = createDefaultSessionSecret(),
  configPath,
  onConfigSaved
}: AppDeps): express.Express {
  const app = express();
  const getConfig = typeof config === "function" ? config : () => config;
  const routeContext: RouteContext = {
    getConfig,
    keys,
    logger,
    state,
    passwordStore,
    mfaStore,
    adminToken,
    sessionSecret,
    configPath,
    onConfigSaved
  };

  app.disable("x-powered-by");
  app.use(express.urlencoded({ extended: false, limit: "100kb" }));
  app.use(express.json({ limit: "100kb" }));
  app.use((req, res, next) => {
    const startedAt = Date.now();
    res.on("finish", () => {
      logger.verbose(getConfig(), "request completed", {
        method: req.method,
        path: req.path,
        status: res.statusCode,
        durationMs: Date.now() - startedAt
      });
    });
    next();
  });

  app.get("/", (_req, res) => {
    res.redirect("/internal/admin");
  });

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  registerAdminRoutes(app, routeContext);
  registerOidcRoutes(app, routeContext);
  registerInternalRoutes(app, routeContext);

  return app;
}
