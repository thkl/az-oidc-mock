import crypto from "node:crypto";
import { saveConfig } from "../config.js";
import { constantTimeEqual, getSessionUser, setSessionUser } from "../oidc/session.js";
import { resolveEffectiveUser } from "../oidc/users.js";
import { findClient, findTenant, findUser, validateRedirectUri, validateScopes } from "../oidc/validation.js";
import { renderAdminPage, renderAdminSetupPage } from "../views/admin.js";
import { readObjectBody, readString } from "./http.js";
const ADMIN_TENANT_ID = "internal";
const ADMIN_CLIENT_ID = "internal-admin";
const ADMIN_ROLE = "internal-admin";
const ADMIN_CLAIM = "internal_admin";
const SECRET_MASK = "********";
/**
 * Registers the authenticated admin web UI and its JSON mutation APIs.
 */
export function registerAdminRoutes(app, context) {
    /**
     * Serves the admin UI after validating the internal tenant session.
     */
    app.get("/internal/admin", (req, res) => {
        const config = context.getConfig();
        const setup = getAdminSetup(config);
        if (!setup.ok) {
            res.status(503).type("html").send(renderAdminSetupPage(setup.description, createInternalTenantExample(config)));
            return;
        }
        const sessionUser = getSessionUser(req, config, setup.tenant, context.sessionSecret);
        if (!sessionUser) {
            res.redirect(createAdminAuthorizeUrl(config).toString());
            return;
        }
        if (!isAdminUser(sessionUser.user)) {
            res.status(403).type("html").send(renderAdminSetupPage(adminAccessDescription(), createInternalTenantExample(config)));
            return;
        }
        res.type("html").send(renderAdminPage(sessionUser.user));
    });
    /**
     * Completes the internal OIDC login and creates the admin UI session cookie.
     */
    app.get("/internal/admin/callback", (req, res) => {
        const config = context.getConfig();
        const setup = getAdminSetup(config);
        if (!setup.ok) {
            res.status(503).type("html").send(renderAdminSetupPage(setup.description, createInternalTenantExample(config)));
            return;
        }
        const code = readString(req.query.code);
        const entry = code ? context.state.consumeCode(code) : undefined;
        if (!entry ||
            entry.tenantId !== ADMIN_TENANT_ID ||
            entry.clientId !== ADMIN_CLIENT_ID ||
            entry.redirectUri !== adminRedirectUri(config)) {
            res.status(401).type("html").send(renderAdminSetupPage("Admin login code is invalid or expired.", createInternalTenantExample(config)));
            return;
        }
        const resolvedUser = resolveEffectiveUser(config, setup.tenant, entry.userSub);
        if (!resolvedUser) {
            res.status(401).type("html").send(renderAdminSetupPage("Admin login user no longer exists.", createInternalTenantExample(config)));
            return;
        }
        if (!isAdminUser(resolvedUser.user)) {
            res.status(403).type("html").send(renderAdminSetupPage(adminAccessDescription(), createInternalTenantExample(config)));
            return;
        }
        setSessionUser(req, res, config, setup.tenant, resolvedUser.user.sub, entry.authOriginalLevel, context.sessionSecret);
        res.redirect("/internal/admin");
    });
    /**
     * Returns the editable config with secrets redacted and a CSRF token for writes.
     */
    app.get("/internal/admin/api/config", (req, res) => {
        const auth = getAdminRequestUser(context.getConfig(), req, context.sessionSecret);
        if (!auth.ok) {
            res.status(auth.status).json({ error: auth.error, error_description: auth.description });
            return;
        }
        res.json({
            config: redactConfigSecrets(context.getConfig()),
            authStatus: createAuthStatus(context.getConfig(), context),
            user: { sub: auth.user.sub, name: auth.user.name, email: auth.user.email },
            csrfToken: createAdminCsrfToken(auth.user, context.sessionSecret)
        });
    });
    /**
     * Saves an updated config file from the admin UI.
     */
    app.put("/internal/admin/api/config", (req, res) => {
        const auth = getAdminRequestUser(context.getConfig(), req, context.sessionSecret);
        if (!auth.ok) {
            res.status(auth.status).json({ error: auth.error, error_description: auth.description });
            return;
        }
        if (!verifyAdminCsrfToken(req, auth.user, context.sessionSecret)) {
            res.status(403).json({ error: "csrf_failed", error_description: "Admin CSRF token is missing or invalid" });
            return;
        }
        if (!context.configPath) {
            res.status(503).json({ error: "admin_config_readonly", error_description: "Config path is not available for writes" });
            return;
        }
        const body = readObjectBody(req);
        const nextConfig = body.config;
        try {
            // Preserve stored secrets when the UI submits redacted secret placeholders.
            const saved = saveConfig(context.configPath, mergeMaskedClientSecrets(context.getConfig(), nextConfig));
            context.onConfigSaved?.(saved);
            context.logger.info("admin config saved", { userSub: auth.user.sub, tenantCount: saved.tenants.length });
            res.json({ config: redactConfigSecrets(saved), authStatus: createAuthStatus(saved, context) });
        }
        catch (error) {
            res.status(400).json({
                error: "invalid_config",
                error_description: error instanceof Error ? error.message : String(error)
            });
        }
    });
    /**
     * Sets a user's secure-login password from the admin UI.
     */
    app.post("/internal/admin/api/passwords", (req, res) => {
        const config = context.getConfig();
        const auth = getAdminRequestUser(config, req, context.sessionSecret);
        if (!auth.ok) {
            res.status(auth.status).json({ error: auth.error, error_description: auth.description });
            return;
        }
        if (!verifyAdminCsrfToken(req, auth.user, context.sessionSecret)) {
            res.status(403).json({ error: "csrf_failed", error_description: "Admin CSRF token is missing or invalid" });
            return;
        }
        const body = readObjectBody(req);
        const tenantId = readString(body.tenant_id) ?? readString(body.tenantId);
        const userSub = readString(body.user_sub) ?? readString(body.userSub);
        const password = readString(body.password);
        const tenant = tenantId ? findTenant(config, tenantId) : undefined;
        const user = tenant && userSub ? findUser(tenant, userSub) : undefined;
        if (!tenant || !user || !password) {
            res.status(400).json({
                error: "invalid_request",
                error_description: "tenant_id, user_sub, and password are required"
            });
            return;
        }
        try {
            context.passwordStore.setPassword(tenant.tenantId, user.sub, password);
            context.logger.info("admin user password updated", {
                adminUserSub: auth.user.sub,
                tenantId: tenant.tenantId,
                userSub: user.sub
            });
            res.json({ updated: true, tenant_id: tenant.tenantId, user_sub: user.sub });
        }
        catch (error) {
            res.status(503).json({
                error: "password_store_unavailable",
                error_description: error instanceof Error ? error.message : String(error)
            });
        }
    });
    /**
     * Resets a user's TOTP enrollment from the admin UI.
     */
    app.delete("/internal/admin/api/mfa", (req, res) => {
        const config = context.getConfig();
        const auth = getAdminRequestUser(config, req, context.sessionSecret);
        if (!auth.ok) {
            res.status(auth.status).json({ error: auth.error, error_description: auth.description });
            return;
        }
        if (!verifyAdminCsrfToken(req, auth.user, context.sessionSecret)) {
            res.status(403).json({ error: "csrf_failed", error_description: "Admin CSRF token is missing or invalid" });
            return;
        }
        const body = readObjectBody(req);
        const tenantId = readString(body.tenant_id) ?? readString(body.tenantId);
        const userSub = readString(body.user_sub) ?? readString(body.userSub);
        const tenant = tenantId ? findTenant(config, tenantId) : undefined;
        const user = tenant && userSub ? findUser(tenant, userSub) : undefined;
        if (!tenant || !user) {
            res.status(400).json({
                error: "invalid_request",
                error_description: "tenant_id and user_sub are required"
            });
            return;
        }
        const deleted = context.mfaStore.remove(tenant.tenantId, user.sub);
        context.logger.info("admin user 2fa reset", {
            adminUserSub: auth.user.sub,
            tenantId: tenant.tenantId,
            userSub: user.sub,
            deleted
        });
        res.json({ deleted, tenant_id: tenant.tenantId, user_sub: user.sub });
    });
    /**
     * Resets all stored passkeys for a user from the admin UI.
     */
    app.delete("/internal/admin/api/passkeys", (req, res) => {
        const config = context.getConfig();
        const auth = getAdminRequestUser(config, req, context.sessionSecret);
        if (!auth.ok) {
            res.status(auth.status).json({ error: auth.error, error_description: auth.description });
            return;
        }
        if (!verifyAdminCsrfToken(req, auth.user, context.sessionSecret)) {
            res.status(403).json({ error: "csrf_failed", error_description: "Admin CSRF token is missing or invalid" });
            return;
        }
        const body = readObjectBody(req);
        const tenantId = readString(body.tenant_id) ?? readString(body.tenantId);
        const userSub = readString(body.user_sub) ?? readString(body.userSub);
        const tenant = tenantId ? findTenant(config, tenantId) : undefined;
        const user = tenant && userSub ? findUser(tenant, userSub) : undefined;
        if (!tenant || !user) {
            res.status(400).json({
                error: "invalid_request",
                error_description: "tenant_id and user_sub are required"
            });
            return;
        }
        const deleted = context.passkeyStore.remove(tenant.tenantId, user.sub);
        context.logger.info("admin user passkeys reset", {
            adminUserSub: auth.user.sub,
            tenantId: tenant.tenantId,
            userSub: user.sub,
            deleted
        });
        res.json({ deleted, tenant_id: tenant.tenantId, user_sub: user.sub });
    });
}
/**
 * Builds runtime security enrollment status for the admin UI without persisting it in config.
 */
function createAuthStatus(config, context) {
    return Object.fromEntries(config.tenants.map((tenant) => [
        tenant.tenantId,
        Object.fromEntries(tenant.users.map((user) => [
            user.sub,
            {
                mfa: context.mfaStore.isEnrolledForTenants([tenant.tenantId], user.sub),
                passkey: context.passkeyStore.isEnrolled(tenant.tenantId, user.sub)
            }
        ]))
    ]));
}
/**
 * Replaces client secrets with a mask before config is sent to the browser.
 */
function redactConfigSecrets(config) {
    return {
        ...config,
        tenants: config.tenants.map((tenant) => ({
            ...tenant,
            clients: tenant.clients.map((client) => ({
                ...client,
                ...(client.clientSecret ? { clientSecret: SECRET_MASK } : {}),
                ...(client.clientSecrets ? {
                    clientSecrets: client.clientSecrets.map((credential) => ({ ...credential, secret: SECRET_MASK }))
                } : {})
            }))
        }))
    };
}
/**
 * Rehydrates masked client secrets from the current config before saving UI edits.
 */
function mergeMaskedClientSecrets(currentConfig, nextConfig) {
    return {
        ...nextConfig,
        tenants: nextConfig.tenants.map((tenant) => {
            const currentTenant = findTenant(currentConfig, tenant.tenantId);
            return {
                ...tenant,
                clients: tenant.clients.map((client) => {
                    const currentClient = currentTenant ? findClient(currentTenant, client.clientId) : undefined;
                    // A missing or masked secret means "keep the existing secret" when one exists.
                    if ((client.clientSecret === undefined || client.clientSecret === SECRET_MASK) && currentClient?.clientSecret) {
                        client.clientSecret = currentClient.clientSecret;
                    }
                    else if (client.clientSecret === SECRET_MASK) {
                        client.clientSecret = undefined;
                    }
                    const currentSecrets = currentClient?.clientSecrets ?? [];
                    const clientSecrets = (client.clientSecrets ?? []).flatMap((credential) => {
                        const current = currentSecrets.find((entry) => entry.name.toLowerCase() === credential.name.toLowerCase());
                        const secret = credential.secret === SECRET_MASK ? current?.secret : credential.secret;
                        return secret ? [{ ...credential, secret }] : [];
                    });
                    return { ...client, ...(clientSecrets.length > 0 ? { clientSecrets } : { clientSecrets: undefined }) };
                })
            };
        })
    };
}
/**
 * Validates that the internal admin tenant and client are configured correctly.
 */
function getAdminSetup(config) {
    const tenant = findTenant(config, ADMIN_TENANT_ID);
    if (!tenant) {
        return { ok: false, description: `Tenant "${ADMIN_TENANT_ID}" is required for the admin UI.` };
    }
    const client = findClient(tenant, ADMIN_CLIENT_ID);
    if (!client) {
        return { ok: false, description: `Client "${ADMIN_CLIENT_ID}" is required in tenant "${ADMIN_TENANT_ID}".` };
    }
    if (!client.enabled) {
        return { ok: false, description: `Client "${ADMIN_CLIENT_ID}" is disabled.` };
    }
    if (!validateRedirectUri(client, adminRedirectUri(config))) {
        return { ok: false, description: `Client "${ADMIN_CLIENT_ID}" must allow redirect URI "${adminRedirectUri(config)}".` };
    }
    if (!validateScopes(client, ["openid", "profile", "email"])) {
        return { ok: false, description: `Client "${ADMIN_CLIENT_ID}" must allow openid, profile, and email scopes.` };
    }
    return { ok: true, tenant, client };
}
/**
 * Authenticates an admin API request using the internal tenant session cookie.
 */
function getAdminRequestUser(config, req, sessionSecret) {
    const setup = getAdminSetup(config);
    if (!setup.ok) {
        return { ok: false, status: 503, error: "admin_not_configured", description: setup.description };
    }
    const sessionUser = getSessionUser(req, config, setup.tenant, sessionSecret);
    if (!sessionUser) {
        return { ok: false, status: 401, error: "login_required", description: "Sign in with the internal tenant first" };
    }
    if (!isAdminUser(sessionUser.user)) {
        return { ok: false, status: 403, error: "forbidden", description: adminAccessDescription() };
    }
    return { ok: true, user: sessionUser.user };
}
/**
 * Checks whether a user is allowed to administer the mock.
 */
function isAdminUser(user) {
    return user.roles.includes(ADMIN_ROLE) || user.claims[ADMIN_CLAIM] === true;
}
/**
 * Builds the human-readable admin access requirement.
 */
function adminAccessDescription() {
    return `Admin login requires the "${ADMIN_ROLE}" role or claims.${ADMIN_CLAIM}=true.`;
}
/**
 * Creates the admin UI CSRF token bound to the signed-in admin user.
 */
function createAdminCsrfToken(user, sessionSecret) {
    return crypto
        .createHmac("sha256", sessionSecret)
        .update(`admin:${user.sub}`)
        .digest("base64url");
}
/**
 * Verifies the admin UI CSRF token supplied by mutating requests.
 */
function verifyAdminCsrfToken(req, user, sessionSecret) {
    const supplied = readString(req.header("x-csrf-token"));
    return Boolean(supplied && constantTimeEqual(supplied, createAdminCsrfToken(user, sessionSecret)));
}
/**
 * Builds the internal tenant authorize URL used to start admin login.
 */
function createAdminAuthorizeUrl(config) {
    const url = new URL(`${config.baseUrl.replace(/\/$/, "")}/${ADMIN_TENANT_ID}/oauth2/v2.0/authorize`);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", ADMIN_CLIENT_ID);
    url.searchParams.set("redirect_uri", adminRedirectUri(config));
    url.searchParams.set("scope", "openid profile email");
    url.searchParams.set("state", "admin");
    return url;
}
/**
 * Builds the admin callback URI that the internal admin client must allow.
 */
function adminRedirectUri(config) {
    return `${config.baseUrl.replace(/\/$/, "")}/internal/admin/callback`;
}
/**
 * Generates a copy-pasteable internal tenant example for setup errors.
 */
function createInternalTenantExample(config) {
    return JSON.stringify({
        tenantId: ADMIN_TENANT_ID,
        displayName: "Internal Admin",
        secure: true,
        enableSessions: true,
        sessionLifetimeSeconds: 28800,
        twoFactorEnabled: false,
        twoFactorMandatory: false,
        passkeysEnabled: false,
        passkeysMandatory: false,
        clients: [
            {
                clientId: ADMIN_CLIENT_ID,
                redirectUris: [adminRedirectUri(config)],
                allowedScopes: ["openid", "profile", "email"],
                enabled: true
            }
        ],
        devices: [],
        users: [
            {
                sub: "admin-1",
                name: "Admin User",
                email: "admin@example.test",
                preferred_username: "admin@example.test",
                roles: [],
                claims: { [ADMIN_CLAIM]: true }
            }
        ]
    }, null, 2);
}
