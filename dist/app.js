import express from "express";
import { tenantIssuer } from "./config.js";
import { OidcState } from "./oidc/state.js";
import { createAccessToken, createIdToken } from "./oidc/tokens.js";
import { findClient, findTenant, findUser, parseScopes, validateRedirectUri, validateScopes } from "./oidc/validation.js";
import { renderLoginPage } from "./views/login.js";
export function createApp({ config, keys, state = new OidcState() }) {
    const app = express();
    const getConfig = typeof config === "function" ? config : () => config;
    app.disable("x-powered-by");
    app.use(express.urlencoded({ extended: false }));
    app.use(express.json());
    app.get("/health", (_req, res) => {
        res.json({ status: "ok" });
    });
    app.get("/:tenantId/.well-known/openid-configuration", (req, res) => {
        const config = getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        const base = config.baseUrl.replace(/\/$/, "");
        const tenantBase = `${base}/${encodeURIComponent(tenant.tenantId)}/oauth2/v2.0`;
        res.json({
            issuer: tenantIssuer(config, tenant.tenantId),
            authorization_endpoint: `${tenantBase}/authorize`,
            token_endpoint: `${tenantBase}/token`,
            jwks_uri: `${base}/${encodeURIComponent(tenant.tenantId)}/discovery/v2.0/keys`,
            end_session_endpoint: `${tenantBase}/logout`,
            response_types_supported: ["code"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: ["RS256"],
            scopes_supported: tenantScopes(tenant),
            token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
            claims_supported: [
                "aud",
                "email",
                "exp",
                "iat",
                "iss",
                "name",
                "nonce",
                "oid",
                "preferred_username",
                "roles",
                "sub",
                "tid"
            ]
        });
    });
    app.get("/:tenantId/discovery/v2.0/keys", (req, res) => {
        const config = getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        res.json(keys.jwks);
    });
    app.get("/:tenantId/oauth2/v2.0/authorize", (req, res) => {
        const config = getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        const validation = validateAuthorizeRequest(tenant, req.query);
        if (!validation.ok) {
            sendAuthorizeError(res, req.query.redirect_uri, req.query.state, validation.error, validation.description);
            return;
        }
        const sessionUser = getSessionUser(req, tenant.tenantId);
        if (sessionUser) {
            redirectWithCode(res, state, tenant.tenantId, validation.client, validation.request, sessionUser);
            return;
        }
        if (req.query.prompt === "none") {
            sendAuthorizeError(res, validation.request.redirectUri, validation.request.state, "login_required");
            return;
        }
        res.type("html").send(renderLoginPage(tenant, {
            client_id: validation.client.clientId,
            redirect_uri: validation.request.redirectUri,
            response_type: "code",
            scope: validation.request.scope.join(" "),
            state: validation.request.state ?? "",
            nonce: validation.request.nonce ?? ""
        }));
    });
    app.post("/:tenantId/login", (req, res) => {
        const config = getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        const validation = validateAuthorizeRequest(tenant, req.body);
        if (!validation.ok) {
            sendAuthorizeError(res, req.body.redirect_uri, req.body.state, validation.error, validation.description);
            return;
        }
        const userSub = readString(req.body.user_sub);
        if (!userSub || !findUser(tenant, userSub)) {
            sendAuthorizeError(res, validation.request.redirectUri, validation.request.state, "access_denied", "Unknown user");
            return;
        }
        setSessionUser(res, tenant.tenantId, userSub);
        redirectWithCode(res, state, tenant.tenantId, validation.client, validation.request, userSub);
    });
    app.post("/:tenantId/oauth2/v2.0/token", async (req, res) => {
        const config = getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        const client = authenticateClient(tenant, req);
        if (!client) {
            sendTokenError(res, "invalid_client", "Client authentication failed", 401);
            return;
        }
        const grantType = readString(req.body.grant_type);
        if (grantType === "authorization_code") {
            await handleAuthorizationCodeGrant({ config, keys, state, tenant, client, req, res });
            return;
        }
        if (grantType === "refresh_token") {
            await handleRefreshTokenGrant({ config, keys, state, tenant, client, req, res });
            return;
        }
        sendTokenError(res, "unsupported_grant_type", "Only authorization_code and refresh_token are supported");
    });
    app.get("/:tenantId/oauth2/v2.0/logout", (req, res) => {
        const config = getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        clearSessionUser(res, tenant.tenantId);
        const redirect = readString(req.query.post_logout_redirect_uri);
        if (redirect) {
            res.redirect(redirect);
            return;
        }
        res.status(204).send();
    });
    return app;
}
function getTenantOr404(config, req, res) {
    const tenant = findTenant(config, req.params.tenantId);
    if (!tenant) {
        res.status(404).json({ error: "tenant_not_found" });
    }
    return tenant;
}
function validateAuthorizeRequest(tenant, query) {
    if (query.response_type !== "code") {
        return { ok: false, error: "unsupported_response_type", description: "Only response_type=code is supported" };
    }
    const clientId = query.client_id;
    const redirectUri = query.redirect_uri;
    if (!clientId || !redirectUri) {
        return { ok: false, error: "invalid_request", description: "client_id and redirect_uri are required" };
    }
    const client = findClient(tenant, clientId);
    if (!client) {
        return { ok: false, error: "unauthorized_client", description: "Unknown client for tenant" };
    }
    if (!validateRedirectUri(client, redirectUri)) {
        return { ok: false, error: "invalid_request", description: "redirect_uri is not registered for client" };
    }
    const scope = parseScopes(query.scope);
    if (!scope.includes("openid")) {
        return { ok: false, error: "invalid_scope", description: "openid scope is required" };
    }
    if (!validateScopes(client, scope)) {
        return { ok: false, error: "invalid_scope", description: "Requested scope is not allowed for client" };
    }
    return {
        ok: true,
        client,
        request: {
            clientId,
            redirectUri,
            scope,
            state: emptyToUndefined(query.state),
            nonce: emptyToUndefined(query.nonce)
        }
    };
}
function redirectWithCode(res, oidcState, tenantId, client, request, userSub) {
    const code = oidcState.createCode({
        tenantId,
        clientId: client.clientId,
        redirectUri: request.redirectUri,
        scope: request.scope,
        state: request.state,
        nonce: request.nonce
    }, userSub);
    const redirectUrl = new URL(request.redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (request.state) {
        redirectUrl.searchParams.set("state", request.state);
    }
    res.redirect(redirectUrl.toString());
}
async function handleAuthorizationCodeGrant(args) {
    const code = readString(args.req.body.code);
    const redirectUri = readString(args.req.body.redirect_uri);
    if (!code || !redirectUri) {
        sendTokenError(args.res, "invalid_request", "code and redirect_uri are required");
        return;
    }
    const entry = args.state.consumeCode(code);
    if (!entry ||
        entry.tenantId !== args.tenant.tenantId ||
        entry.clientId !== args.client.clientId ||
        entry.redirectUri !== redirectUri) {
        sendTokenError(args.res, "invalid_grant", "Authorization code is invalid or expired");
        return;
    }
    const user = findUser(args.tenant, entry.userSub);
    if (!user) {
        sendTokenError(args.res, "invalid_grant", "User no longer exists");
        return;
    }
    const refreshToken = entry.scope.includes("offline_access")
        ? args.state.createRefreshToken({
            tenantId: args.tenant.tenantId,
            clientId: args.client.clientId,
            userSub: user.sub,
            scope: entry.scope,
            nonce: entry.nonce,
            expiresAt: Date.now() + args.config.refreshTokenLifetimeSeconds * 1000
        })
        : undefined;
    await sendTokenSet(args.res, {
        config: args.config,
        keys: args.keys,
        state: args.state,
        tenant: args.tenant,
        client: args.client,
        user,
        scope: entry.scope,
        nonce: entry.nonce,
        refreshToken
    });
}
async function handleRefreshTokenGrant(args) {
    const token = readString(args.req.body.refresh_token);
    if (!token) {
        sendTokenError(args.res, "invalid_request", "refresh_token is required");
        return;
    }
    const entry = args.state.getRefreshToken(token);
    if (!entry || entry.tenantId !== args.tenant.tenantId || entry.clientId !== args.client.clientId) {
        sendTokenError(args.res, "invalid_grant", "Refresh token is invalid or expired");
        return;
    }
    const user = findUser(args.tenant, entry.userSub);
    if (!user) {
        sendTokenError(args.res, "invalid_grant", "User no longer exists");
        return;
    }
    let refreshToken = token;
    if (args.config.rotateRefreshTokens) {
        args.state.revokeRefreshToken(token);
        refreshToken = args.state.createRefreshToken({
            tenantId: entry.tenantId,
            clientId: entry.clientId,
            userSub: entry.userSub,
            scope: entry.scope,
            nonce: entry.nonce,
            expiresAt: Date.now() + args.config.refreshTokenLifetimeSeconds * 1000
        });
    }
    await sendTokenSet(args.res, {
        config: args.config,
        keys: args.keys,
        state: args.state,
        tenant: args.tenant,
        client: args.client,
        user,
        scope: entry.scope,
        nonce: entry.nonce,
        refreshToken
    });
}
async function sendTokenSet(res, args) {
    const input = {
        config: args.config,
        keys: args.keys,
        tenant: args.tenant,
        client: args.client,
        user: args.user,
        scope: args.scope,
        nonce: args.nonce
    };
    res.json({
        token_type: "Bearer",
        expires_in: args.config.tokenLifetimeSeconds,
        scope: args.scope.join(" "),
        access_token: await createAccessToken(input),
        id_token: await createIdToken(input),
        ...(args.refreshToken ? { refresh_token: args.refreshToken } : {})
    });
}
function authenticateClient(tenant, req) {
    const basic = parseBasicAuth(req);
    const clientId = basic?.clientId ?? readString(req.body.client_id);
    const clientSecret = basic?.clientSecret ?? readString(req.body.client_secret);
    if (!clientId) {
        return undefined;
    }
    const client = findClient(tenant, clientId);
    if (!client) {
        return undefined;
    }
    if (client.clientSecret && client.clientSecret !== clientSecret) {
        return undefined;
    }
    return client;
}
function parseBasicAuth(req) {
    const header = req.header("authorization");
    if (!header?.startsWith("Basic ")) {
        return undefined;
    }
    const decoded = Buffer.from(header.slice("Basic ".length), "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator < 0) {
        return undefined;
    }
    return {
        clientId: decodeURIComponent(decoded.slice(0, separator)),
        clientSecret: decodeURIComponent(decoded.slice(separator + 1))
    };
}
function getSessionUser(req, tenantId) {
    return parseCookies(req.header("cookie"))[`az_oidc_mock_${tenantId}`];
}
function setSessionUser(res, tenantId, userSub) {
    res.cookie(`az_oidc_mock_${tenantId}`, userSub, {
        httpOnly: true,
        sameSite: "lax",
        path: `/${tenantId}`,
        maxAge: 8 * 60 * 60 * 1000
    });
}
function clearSessionUser(res, tenantId) {
    res.clearCookie(`az_oidc_mock_${tenantId}`, {
        httpOnly: true,
        sameSite: "lax",
        path: `/${tenantId}`
    });
}
function parseCookies(header) {
    if (!header)
        return {};
    return Object.fromEntries(header
        .split(";")
        .map((part) => part.trim().split("="))
        .filter(([key, value]) => key && value)
        .map(([key, value]) => [key, decodeURIComponent(value)]));
}
function sendAuthorizeError(res, redirectUri, state, error, description) {
    if (typeof redirectUri === "string" && isUrl(redirectUri)) {
        const url = new URL(redirectUri);
        url.searchParams.set("error", error);
        if (description) {
            url.searchParams.set("error_description", description);
        }
        if (typeof state === "string" && state) {
            url.searchParams.set("state", state);
        }
        res.redirect(url.toString());
        return;
    }
    res.status(400).json({ error, ...(description ? { error_description: description } : {}) });
}
function sendTokenError(res, error, description, status = 400) {
    res.status(status).json({ error, error_description: description });
}
function readString(value) {
    return typeof value === "string" && value.length > 0 ? value : undefined;
}
function emptyToUndefined(value) {
    return value && value.length > 0 ? value : undefined;
}
function isUrl(value) {
    try {
        new URL(value);
        return true;
    }
    catch {
        return false;
    }
}
function tenantScopes(tenant) {
    return [...new Set(tenant.clients.flatMap((client) => client.allowedScopes))].sort();
}
