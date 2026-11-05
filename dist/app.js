import express from "express";
import { createLogger } from "./logger.js";
import { MfaStore } from "./oidc/mfa.js";
import { PasskeyStore } from "./oidc/passkeys.js";
import { PasswordStore } from "./oidc/passwords.js";
import { createDefaultSessionSecret } from "./oidc/session.js";
import { OidcState } from "./oidc/state.js";
import { registerAdminRoutes } from "./routes/admin.js";
import { registerClientSecretRotationRoutes } from "./routes/client-secret-rotation.js";
import { registerInternalRoutes } from "./routes/internal.js";
import { registerOidcRoutes } from "./routes/oidc.js";
/**
 * Creates the Express application and wires all tenant-aware OIDC routes.
 */
export function createApp({ config, keys, logger = createLogger(), state = new OidcState(), passwordStore = new PasswordStore(), passkeyStore = new PasskeyStore(), mfaStore = new MfaStore(), adminToken, rotationManagerId, rotationApiAllowlist, clientSecretRotationStore, sessionSecret = createDefaultSessionSecret(), configPath, onConfigSaved }) {
    const app = express();
    const getConfig = typeof config === "function" ? config : () => config;
    // Route context keeps request handlers independent from process-level startup.
    const routeContext = {
        getConfig,
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
        onConfigSaved
    };
    app.disable("x-powered-by");
    // Keep form and JSON bodies bounded because config and login endpoints accept user input.
    app.use(express.urlencoded({ extended: false, limit: "100kb" }));
    app.use(express.json({ limit: "100kb" }));
    // Emit request logs after responses so status and duration are available.
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
    registerClientSecretRotationRoutes(app, routeContext);
    registerOidcRoutes(app, routeContext);
    registerInternalRoutes(app, routeContext);
    return app;
}
