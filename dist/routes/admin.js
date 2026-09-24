import { saveConfig } from "../config.js";
import { getSessionUser, setSessionUser } from "../oidc/session.js";
import { findClient, findTenant, findUser, validateRedirectUri, validateScopes } from "../oidc/validation.js";
import { renderAdminPage, renderAdminSetupPage } from "../views/admin.js";
import { readObjectBody, readString } from "./http.js";
const ADMIN_TENANT_ID = "internal";
const ADMIN_CLIENT_ID = "internal-admin";
const SECRET_MASK = "********";
export function registerAdminRoutes(app, context) {
    app.get("/internal/admin", (req, res) => {
        const config = context.getConfig();
        const setup = getAdminSetup(config);
        if (!setup.ok) {
            res.status(503).type("html").send(renderAdminSetupPage(setup.description, createInternalTenantExample(config)));
            return;
        }
        const sessionUser = getSessionUser(req, setup.tenant, context.sessionSecret);
        if (!sessionUser) {
            res.redirect(createAdminAuthorizeUrl(config).toString());
            return;
        }
        res.type("html").send(renderAdminPage(sessionUser));
    });
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
        const user = findUser(setup.tenant, entry.userSub);
        if (!user) {
            res.status(401).type("html").send(renderAdminSetupPage("Admin login user no longer exists.", createInternalTenantExample(config)));
            return;
        }
        setSessionUser(res, setup.tenant, user.sub, context.sessionSecret);
        res.redirect("/internal/admin");
    });
    app.get("/internal/admin/api/config", (req, res) => {
        const auth = getAdminRequestUser(context.getConfig(), req, context.sessionSecret);
        if (!auth.ok) {
            res.status(auth.status).json({ error: auth.error, error_description: auth.description });
            return;
        }
        res.json({
            config: redactConfigSecrets(context.getConfig()),
            user: { sub: auth.user.sub, name: auth.user.name, email: auth.user.email }
        });
    });
    app.put("/internal/admin/api/config", (req, res) => {
        const auth = getAdminRequestUser(context.getConfig(), req, context.sessionSecret);
        if (!auth.ok) {
            res.status(auth.status).json({ error: auth.error, error_description: auth.description });
            return;
        }
        if (!context.configPath) {
            res.status(503).json({ error: "admin_config_readonly", error_description: "Config path is not available for writes" });
            return;
        }
        const body = readObjectBody(req);
        const nextConfig = body.config;
        try {
            const saved = saveConfig(context.configPath, mergeMaskedClientSecrets(context.getConfig(), nextConfig));
            context.onConfigSaved?.(saved);
            context.logger.info("admin config saved", { userSub: auth.user.sub, tenantCount: saved.tenants.length });
            res.json({ config: redactConfigSecrets(saved) });
        }
        catch (error) {
            res.status(400).json({
                error: "invalid_config",
                error_description: error instanceof Error ? error.message : String(error)
            });
        }
    });
    app.post("/internal/admin/api/passwords", (req, res) => {
        const config = context.getConfig();
        const auth = getAdminRequestUser(config, req, context.sessionSecret);
        if (!auth.ok) {
            res.status(auth.status).json({ error: auth.error, error_description: auth.description });
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
}
function redactConfigSecrets(config) {
    return {
        ...config,
        tenants: config.tenants.map((tenant) => ({
            ...tenant,
            clients: tenant.clients.map((client) => ({
                ...client,
                ...(client.clientSecret ? { clientSecret: SECRET_MASK } : {})
            }))
        }))
    };
}
function mergeMaskedClientSecrets(currentConfig, nextConfig) {
    return {
        ...nextConfig,
        tenants: nextConfig.tenants.map((tenant) => {
            const currentTenant = findTenant(currentConfig, tenant.tenantId);
            return {
                ...tenant,
                clients: tenant.clients.map((client) => {
                    const currentClient = currentTenant ? findClient(currentTenant, client.clientId) : undefined;
                    if ((client.clientSecret === undefined || client.clientSecret === SECRET_MASK) && currentClient?.clientSecret) {
                        return { ...client, clientSecret: currentClient.clientSecret };
                    }
                    return client.clientSecret === SECRET_MASK ? { ...client, clientSecret: undefined } : client;
                })
            };
        })
    };
}
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
function getAdminRequestUser(config, req, sessionSecret) {
    const setup = getAdminSetup(config);
    if (!setup.ok) {
        return { ok: false, status: 503, error: "admin_not_configured", description: setup.description };
    }
    const user = getSessionUser(req, setup.tenant, sessionSecret);
    if (!user) {
        return { ok: false, status: 401, error: "login_required", description: "Sign in with the internal tenant first" };
    }
    return { ok: true, user };
}
function createAdminAuthorizeUrl(config) {
    const url = new URL(`${config.baseUrl.replace(/\/$/, "")}/${ADMIN_TENANT_ID}/oauth2/v2.0/authorize`);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", ADMIN_CLIENT_ID);
    url.searchParams.set("redirect_uri", adminRedirectUri(config));
    url.searchParams.set("scope", "openid profile email");
    url.searchParams.set("state", "admin");
    return url;
}
function adminRedirectUri(config) {
    return `${config.baseUrl.replace(/\/$/, "")}/internal/admin/callback`;
}
function createInternalTenantExample(config) {
    return JSON.stringify({
        tenantId: ADMIN_TENANT_ID,
        displayName: "Internal Admin",
        secure: true,
        enableSessions: true,
        sessionLifetimeSeconds: 28800,
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
                roles: ["Admin"],
                claims: {}
            }
        ]
    }, null, 2);
}
