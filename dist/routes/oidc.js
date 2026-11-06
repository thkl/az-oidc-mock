import crypto from "node:crypto";
import { tenantIssuer } from "../config.js";
import { authContext, isAuthLevel } from "../oidc/auth-level.js";
import { isS256CodeChallenge, verifyCodeVerifier } from "../oidc/pkce.js";
import { createTotpSecret, createTotpUri, verifyTotpSecret } from "../oidc/mfa.js";
import { createPasskeyChallenge, verifyPasskeyRegistration } from "../oidc/passkeys.js";
import { clearSessionUser, getSessionUser, setSessionUser } from "../oidc/session.js";
import { isInactiveRefreshTokenDevice, resolveActiveTokenSubject } from "../oidc/token-subject.js";
import { createAccessToken, createIdToken } from "../oidc/tokens.js";
import { listEffectiveUsers, resolveEffectiveUser, resolveEffectiveUserByUsername } from "../oidc/users.js";
import { findClient, findDevice, parseScopes, validateRedirectUri, validateScopes } from "../oidc/validation.js";
import { renderLoginPage, renderMfaPage, renderPasskeyPage } from "../views/login.js";
import { emptyToUndefined, getTenantOr404, readBearerToken, readObjectBody, readString, sendAuthorizeError, sendTokenError } from "./http.js";
const MFA_ACR = "urn:az-oidc-mock:acr:mfa";
const MFA_ACR_ALIASES = new Set(["mfa", MFA_ACR]);
/**
 * Registers tenant-aware OIDC, userinfo, logout, MFA, and passkey routes.
 */
export function registerOidcRoutes(app, context) {
    /**
     * Serves Azure-compatible OIDC discovery metadata.
     */
    app.get(["/:tenantId/.well-known/openid-configuration", "/:tenantId/v2.0/.well-known/openid-configuration"], (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        context.logger.verbose(config, "serving discovery document", { tenantId: tenant.tenantId });
        res.json(createDiscoveryDocument(config, tenant));
    });
    /**
     * Serves the public JWKS used by clients to verify mock tokens.
     */
    app.get("/:tenantId/discovery/v2.0/keys", (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        context.logger.verbose(config, "serving jwks", { tenantId: tenant.tenantId, keyCount: context.keys.jwks.keys.length });
        res.json(context.keys.jwks);
    });
    /**
     * Handles authorization requests and either reuses a session or renders login.
     */
    app.get("/:tenantId/oauth2/v2.0/authorize", (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        const enableSessions = tenant.enableSessions;
        context.logger.verbose(config, "authorize request received", {
            tenantId: tenant.tenantId,
            clientId: req.query.client_id,
            prompt: req.query.prompt,
            enableSessions
        });
        const validation = validateAuthorizeRequest(tenant, req.query, context.clientSecretRotationStore);
        if (!validation.ok) {
            context.logger.warn("authorize request rejected", {
                tenantId: tenant.tenantId,
                error: validation.error,
                description: validation.description
            });
            sendAuthorizeError(res, req.query.redirect_uri, req.query.state, validation.error, validation.description);
            return;
        }
        // A mandatory passkey policy also applies to existing sessions, including sessions created before policy changes.
        if (enableSessions === true) {
            const sessionUser = getSessionUser(req, config, tenant, context.sessionSecret, context.passkeyStore);
            if (sessionUser) {
                const sessionAuth = authContext("cookie", sessionUser.authLevel);
                if (!satisfiesRequestedAcr(validation.request, sessionAuth)) {
                    if (req.query.prompt === "none") {
                        sendAuthorizeError(res, validation.request.redirectUri, validation.request.state, "interaction_required", "MFA is required for this request");
                        return;
                    }
                    const resolvedSessionUser = resolveEffectiveUser(config, tenant, sessionUser.user.sub);
                    if (!resolvedSessionUser) {
                        sendAuthorizeError(res, validation.request.redirectUri, validation.request.state, "access_denied", "User no longer exists");
                        return;
                    }
                    const mfa = handleMfaLoginStep({
                        tenant,
                        user: resolvedSessionUser,
                        validation,
                        req,
                        res,
                        sessionSecret: context.sessionSecret,
                        mfaStore: context.mfaStore,
                        config,
                        auth: sessionAuth
                    });
                    if (!mfa.complete) {
                        return;
                    }
                }
                context.logger.verbose(config, "authorize request satisfied from existing session", {
                    tenantId: tenant.tenantId,
                    clientId: validation.client.clientId,
                    userSub: sessionUser.user.sub,
                    authLevel: sessionUser.authLevel
                });
                redirectWithCode(res, context.state, tenant.tenantId, validation.client, validation.request, sessionUser.user.sub, sessionAuth);
                return;
            }
        }
        if (req.query.prompt === "none") {
            context.logger.verbose(config, "silent authorize requires login", {
                tenantId: tenant.tenantId,
                clientId: validation.client.clientId
            });
            sendAuthorizeError(res, validation.request.redirectUri, validation.request.state, "login_required");
            return;
        }
        // No reusable session exists, so render a tenant-specific login experience.
        res.type("html").send(renderLoginPage(tenant, authorizeParamsFromRequest(validation.client, validation.request), readString(req.query.login_error), listEffectiveUsers(config, tenant).map((entry) => entry.user)));
    });
    /**
     * Handles password/user-picker login, MFA steps, optional passkey setup, and code issuance.
     */
    app.post("/:tenantId/login", (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        context.logger.verbose(config, "login form submitted", { tenantId: tenant.tenantId, clientId: req.body.client_id });
        const validation = validateAuthorizeRequest(tenant, req.body, context.clientSecretRotationStore);
        if (!validation.ok) {
            context.logger.warn("login request rejected", {
                tenantId: tenant.tenantId,
                error: validation.error,
                description: validation.description
            });
            sendAuthorizeError(res, req.body.redirect_uri, req.body.state, validation.error, validation.description);
            return;
        }
        // Optional passkey setup can be skipped only when tenant policy allows it.
        const passkeyChallenge = readString(req.body.passkey_challenge)
            ? verifyPasskeyChallenge(readString(req.body.passkey_challenge), tenant.tenantId, context.sessionSecret)
            : undefined;
        if (passkeyChallenge && readString(req.body.passkey_action) === "continue") {
            if (!sameAuthorizeRequest(passkeyChallenge.request, validation.request)) {
                sendAuthorizeError(res, validation.request.redirectUri, validation.request.state, "invalid_request", "Login continuation does not match the original authorization request");
                return;
            }
            const user = resolveEffectiveUser(config, tenant, passkeyChallenge.userSub);
            if (user) {
                if (tenant.passkeysMandatory && !context.passkeyStore.isEnrolled(user.homeTenant.tenantId, user.user.sub)) {
                    res.status(403).json({ error: "passkey_required", error_description: "A passkey must be enrolled before login can continue" });
                    return;
                }
                completeLogin({
                    tenant,
                    user: user.user,
                    validation: { client: validation.client, request: passkeyChallenge.request },
                    req,
                    res,
                    state: context.state,
                    sessionSecret: context.sessionSecret,
                    logger: context.logger,
                    config,
                    auth: passkeyChallenge.auth
                });
                return;
            }
        }
        // A signed MFA challenge means this POST is continuing the second-factor flow.
        const challenge = readString(req.body.mfa_challenge)
            ? verifyMfaChallenge(readString(req.body.mfa_challenge), tenant.tenantId, context.sessionSecret)
            : undefined;
        if (challenge && !sameAuthorizeRequest(challenge.request, validation.request)) {
            sendAuthorizeError(res, validation.request.redirectUri, validation.request.state, "invalid_request", "Login continuation does not match the original authorization request");
            return;
        }
        const login = challenge
            ? authenticateMfaChallengeUser(config, tenant, challenge)
            : authenticateLogin(config, tenant, req, context.passwordStore);
        if (!login.ok) {
            context.logger.warn("login rejected", { tenantId: tenant.tenantId, reason: login.description });
            if (tenant.secure) {
                res.type("html").status(401).send(renderLoginPage(tenant, authorizeParamsFromRequest(validation.client, validation.request), login.description, listEffectiveUsers(config, tenant).map((entry) => entry.user)));
                return;
            }
            sendAuthorizeError(res, validation.request.redirectUri, validation.request.state, "access_denied", login.description);
            return;
        }
        // MFA is evaluated before passkey setup, so mandatory MFA cannot be bypassed by enrollment.
        const mfa = handleMfaLoginStep({
            tenant,
            user: login.user,
            validation,
            req,
            res,
            sessionSecret: context.sessionSecret,
            mfaStore: context.mfaStore,
            challenge,
            config,
            auth: login.auth
        });
        if (!mfa.complete) {
            return;
        }
        // First successful password login can branch into passkey enrollment before code issuance.
        if (shouldShowPasskeySetup(tenant, context.passkeyStore.isEnrolled(login.user.homeTenant.tenantId, login.user.user.sub))) {
            const passkeyChallengeValue = createPasskeyLoginChallenge({
                tenantId: tenant.tenantId,
                userSub: login.user.user.sub,
                request: validation.request,
                auth: mfa.auth
            }, context.sessionSecret);
            res.type("html").send(renderPasskeyPage(tenant, {
                challenge: passkeyChallengeValue,
                params: authorizeParamsFromRequest(validation.client, validation.request),
                mandatory: tenant.passkeysMandatory
            }));
            return;
        }
        completeLogin({
            tenant,
            user: login.user.user,
            validation,
            req,
            res,
            state: context.state,
            sessionSecret: context.sessionSecret,
            logger: context.logger,
            config,
            auth: mfa.auth
        });
    });
    /**
     * Creates WebAuthn registration options for the passkey setup page.
     */
    app.post("/:tenantId/passkeys/register/options", (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        const body = readObjectBody(req);
        const passkeyChallenge = verifyPasskeyChallenge(readString(body.passkey_challenge), tenant.tenantId, context.sessionSecret);
        const user = passkeyChallenge ? resolveEffectiveUser(config, tenant, passkeyChallenge.userSub) : undefined;
        if (!(tenant.passkeysEnabled || tenant.passkeysMandatory) || !passkeyChallenge || !user) {
            res.status(400).json({ error: "invalid_request", error_description: "Passkey setup challenge is invalid" });
            return;
        }
        const webauthnChallenge = createPasskeyChallenge();
        // The registration token binds the browser WebAuthn challenge to the original authorize request.
        const registrationToken = createPasskeyLoginChallenge({ ...passkeyChallenge, webauthnChallenge }, context.sessionSecret);
        res.json({
            registrationToken,
            publicKey: {
                challenge: webauthnChallenge,
                rp: { name: tenant.displayName, id: passkeyRpId(config) },
                user: {
                    id: Buffer.from(`${user.homeTenant.tenantId}:${user.user.sub}`, "utf8").toString("base64url"),
                    name: user.user.preferred_username,
                    displayName: user.user.name
                },
                pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
                authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
                timeout: 60000,
                attestation: "none",
                excludeCredentials: context.passkeyStore.list(user.homeTenant.tenantId, user.user.sub).map((record) => ({
                    type: "public-key",
                    id: record.credentialId
                }))
            }
        });
    });
    /**
     * Verifies and stores a newly created WebAuthn credential.
     */
    app.post("/:tenantId/passkeys/register", (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        const body = readObjectBody(req);
        const token = verifyPasskeyChallenge(readString(body.registration_token), tenant.tenantId, context.sessionSecret);
        const user = token ? resolveEffectiveUser(config, tenant, token.userSub) : undefined;
        const response = body.response && typeof body.response === "object" && !Array.isArray(body.response)
            ? body.response
            : {};
        if (!(tenant.passkeysEnabled || tenant.passkeysMandatory) || !token?.webauthnChallenge || !user) {
            res.status(400).json({ error: "invalid_request", error_description: "Passkey registration token is invalid" });
            return;
        }
        // Verify browser client data, authenticator data, and the credential public key.
        const registration = verifyPasskeyRegistration({
            clientDataJSON: readString(response.clientDataJSON) ?? "",
            attestationObject: readString(response.attestationObject) ?? "",
            expectedChallenge: token.webauthnChallenge,
            expectedOrigin: passkeyOrigin(config),
            rpId: passkeyRpId(config)
        });
        if (!registration.ok) {
            res.status(400).json({ error: "invalid_passkey", error_description: registration.description });
            return;
        }
        // Store credentials against the home tenant so shared users keep one passkey identity.
        context.passkeyStore.add({
            tenantId: user.homeTenant.tenantId,
            userSub: user.user.sub,
            credentialId: registration.credentialId,
            publicKeyCose: registration.publicKeyCose,
            counter: registration.counter
        });
        const client = findClient(tenant, token.request.clientId);
        if (!client) {
            res.status(400).json({ error: "invalid_request", error_description: "Passkey client is no longer available" });
            return;
        }
        // Completing passkey enrollment is also a successful login, so establish the reusable tenant session.
        if (tenant.enableSessions) {
            setSessionUser(req, res, config, tenant, user.user.sub, token.auth.originalLevel, context.sessionSecret);
        }
        const redirect = createCodeRedirectUrl(context.state, tenant.tenantId, client, token.request, user.user.sub, token.auth);
        res.json({ redirect });
    });
    /**
     * Creates WebAuthn authentication options for passwordless passkey login.
     */
    app.post("/:tenantId/passkeys/authenticate/options", (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        const body = readObjectBody(req);
        const validation = validateAuthorizeRequest(tenant, body, context.clientSecretRotationStore);
        const username = readString(body.username)?.toLowerCase();
        const user = username ? resolveEffectiveUserByUsername(config, tenant, username) : undefined;
        const credentials = user ? context.passkeyStore.list(user.homeTenant.tenantId, user.user.sub) : [];
        if (!(tenant.passkeysEnabled || tenant.passkeysMandatory) || !validation.ok || !user || credentials.length === 0) {
            res.status(400).json({ error: "invalid_request", error_description: "No passkey is available for this login" });
            return;
        }
        // Restrict the browser to credentials already registered for the resolved user.
        const webauthnChallenge = createPasskeyChallenge();
        const authenticationToken = createPasskeyLoginChallenge({
            tenantId: tenant.tenantId,
            userSub: user.user.sub,
            request: validation.request,
            auth: authContext("passkey"),
            webauthnChallenge
        }, context.sessionSecret);
        res.json({
            authenticationToken,
            publicKey: {
                challenge: webauthnChallenge,
                rpId: passkeyRpId(config),
                allowCredentials: credentials.map((record) => ({ type: "public-key", id: record.credentialId })),
                userVerification: "preferred",
                timeout: 60000
            }
        });
    });
    /**
     * Verifies a WebAuthn assertion and returns the normal authorization-code redirect.
     */
    app.post("/:tenantId/passkeys/authenticate", (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        const body = readObjectBody(req);
        const response = body.response && typeof body.response === "object" && !Array.isArray(body.response)
            ? body.response
            : {};
        const token = verifyPasskeyChallenge(readString(body.authentication_token), tenant.tenantId, context.sessionSecret);
        const user = token ? resolveEffectiveUser(config, tenant, token.userSub) : undefined;
        if (!(tenant.passkeysEnabled || tenant.passkeysMandatory) || !token?.webauthnChallenge || !user) {
            res.status(400).json({ error: "invalid_request", error_description: "Passkey authentication token is invalid" });
            return;
        }
        // The assertion proves possession of the private key for one stored credential.
        const ok = context.passkeyStore.verify({
            tenantId: user.homeTenant.tenantId,
            userSub: user.user.sub,
            credentialId: readString(body.rawId) ?? readString(body.id) ?? "",
            clientDataJSON: readString(response.clientDataJSON) ?? "",
            authenticatorData: readString(response.authenticatorData) ?? "",
            signature: readString(response.signature) ?? "",
            expectedChallenge: token.webauthnChallenge,
            expectedOrigin: passkeyOrigin(config),
            rpId: passkeyRpId(config)
        });
        if (!ok) {
            res.status(401).json({ error: "invalid_passkey", error_description: "Passkey assertion is invalid" });
            return;
        }
        const client = findClient(tenant, token.request.clientId);
        if (!client) {
            res.status(400).json({ error: "invalid_request", error_description: "Passkey client is no longer available" });
            return;
        }
        // Successful passkey assertions must create the same reusable session as password logins.
        if (tenant.enableSessions) {
            setSessionUser(req, res, config, tenant, user.user.sub, token.auth.originalLevel, context.sessionSecret);
        }
        const redirect = createCodeRedirectUrl(context.state, tenant.tenantId, client, token.request, user.user.sub, authContext("passkey"));
        res.json({ redirect });
    });
    /**
     * Handles token grants for authorization codes and refresh tokens.
     */
    app.post("/:tenantId/oauth2/v2.0/token", async (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        context.logger.verbose(config, "token request received", {
            tenantId: tenant.tenantId,
            grantType: req.body.grant_type,
            clientId: req.body.client_id
        });
        let client;
        try {
            context.clientSecretRotationStore?.synchronizeConfig(config);
            client = authenticateClient(tenant, req, context.clientSecretRotationStore);
        }
        catch (error) {
            context.logger.error("client secret verification storage failed", {
                tenantId: tenant.tenantId,
                error: error instanceof Error ? error.message : "unknown error"
            });
            sendTokenError(res, "temporarily_unavailable", "Client authentication is temporarily unavailable", 503);
            return;
        }
        if (!client) {
            context.logger.warn("token request rejected due to client authentication failure", {
                tenantId: tenant.tenantId,
                clientId: req.body.client_id
            });
            sendTokenError(res, "invalid_client", "Client authentication failed", 401);
            return;
        }
        const grantType = readString(req.body.grant_type);
        if (grantType === "authorization_code") {
            await handleAuthorizationCodeGrant({ ...context, config, tenant, client, req, res });
            return;
        }
        if (grantType === "refresh_token") {
            await handleRefreshTokenGrant({ ...context, config, tenant, client, req, res });
            return;
        }
        context.logger.warn("token request used unsupported grant type", {
            tenantId: tenant.tenantId,
            clientId: client.clientId,
            grantType
        });
        sendTokenError(res, "unsupported_grant_type", "Only authorization_code and refresh_token are supported");
    });
    /**
     * Serves OIDC userinfo for a valid active access token.
     */
    app.all("/:tenantId/oidc/userinfo", async (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        const token = readBearerToken(req);
        if (!token) {
            res.status(401).json({
                error: "invalid_token",
                error_description: "Bearer access token is required"
            });
            return;
        }
        const subject = await resolveActiveTokenSubject({ config, keys: context.keys, tenant, token });
        if (!subject.ok) {
            context.logger.warn("userinfo request rejected", {
                tenantId: tenant.tenantId,
                error: subject.error
            });
            res.status(401).json({
                error: subject.error,
                error_description: subject.description
            });
            return;
        }
        const { user } = subject;
        res.json({
            sub: user.sub,
            oid: user.sub,
            name: user.name,
            email: user.email,
            preferred_username: user.preferred_username,
            roles: user.roles,
            tid: tenant.tenantId,
            ...user.claims
        });
    });
    /**
     * Clears the tenant login session cookie and optionally redirects afterwards.
     */
    app.get("/:tenantId/oauth2/v2.0/logout", (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        clearSessionUser(req, res, config, tenant.tenantId);
        context.logger.info("mock session cleared", { tenantId: tenant.tenantId });
        const redirect = readString(req.query.post_logout_redirect_uri);
        if (redirect) {
            res.redirect(redirect);
            return;
        }
        res.status(204).send();
    });
}
/**
 * Builds the Azure v2.0-style discovery document for a tenant.
 */
function createDiscoveryDocument(config, tenant) {
    const base = config.baseUrl.replace(/\/$/, "");
    const encodedTenantId = encodeURIComponent(tenant.tenantId);
    const tenantBase = `${base}/${encodedTenantId}/oauth2/v2.0`;
    return {
        token_endpoint: `${tenantBase}/token`,
        token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
        userinfo_endpoint: `${base}/${encodedTenantId}/oidc/userinfo`,
        jwks_uri: `${base}/${encodedTenantId}/discovery/v2.0/keys`,
        response_modes_supported: ["query", "form_post"],
        subject_types_supported: ["pairwise"],
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: ["S256"],
        response_types_supported: ["code", "id_token", "code id_token"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        scopes_supported: tenantScopes(tenant),
        issuer: tenantIssuer(config, tenant.tenantId),
        authorization_endpoint: `${tenantBase}/authorize`,
        device_authorization_endpoint: `${tenantBase}/devicecode`,
        http_logout_supported: true,
        frontchannel_logout_supported: true,
        end_session_endpoint: `${tenantBase}/logout`,
        claims_supported: [
            "aud",
            "email",
            "exp",
            "iat",
            "iss",
            "name",
            "nbf",
            "nonce",
            "oid",
            "preferred_username",
            "roles",
            "sub",
            "tid",
            "ver",
            "auth_level",
            "auth_original_level",
            "acr"
        ],
        acr_values_supported: ["mfa", MFA_ACR],
        kerberos_endpoint: `${base}/${encodedTenantId}/kerberos`,
        tenant_region_scope: "NA",
        cloud_instance_name: "mock",
        cloud_graph_host_name: "graph.windows.net",
        msgraph_host: "graph.microsoft.com",
        rbac_url: "https://pas.windows.net"
    };
}
/**
 * Validates an authorize request and normalizes it into internal state.
 */
function validateAuthorizeRequest(tenant, query, rotationStore) {
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
    if (!client.enabled) {
        return { ok: false, error: "unauthorized_client", description: "Client is disabled" };
    }
    if (!validateRedirectUri(client, redirectUri)) {
        return { ok: false, error: "invalid_request", description: "redirect_uri is not registered for client" };
    }
    if ((query.code_challenge !== undefined && typeof query.code_challenge !== "string") ||
        (query.code_challenge_method !== undefined && typeof query.code_challenge_method !== "string")) {
        return { ok: false, error: "invalid_request", description: "PKCE parameters must be single string values" };
    }
    const codeChallenge = emptyToUndefined(query.code_challenge);
    const codeChallengeMethod = emptyToUndefined(query.code_challenge_method);
    if (codeChallenge && (codeChallengeMethod !== "S256" || !isS256CodeChallenge(codeChallenge))) {
        return { ok: false, error: "invalid_request", description: "Only a valid S256 code_challenge is supported" };
    }
    if (!codeChallenge && codeChallengeMethod) {
        return { ok: false, error: "invalid_request", description: "code_challenge_method requires code_challenge" };
    }
    const clientRequiresSecret = Boolean(client.clientSecret || client.clientSecrets?.length) ||
        Boolean(rotationStore?.requiresClientSecret(tenant.tenantId, client.clientId));
    if (!clientRequiresSecret && !codeChallenge) {
        return { ok: false, error: "invalid_request", description: "Public clients must use PKCE with S256" };
    }
    const scope = parseScopes(query.scope);
    if (!scope.includes("openid")) {
        return { ok: false, error: "invalid_scope", description: "openid scope is required" };
    }
    if (!validateScopes(client, scope)) {
        return { ok: false, error: "invalid_scope", description: "Requested scope is not allowed for client" };
    }
    // Device binding is optional, but configured tenants require active devices for issued tokens.
    const device = resolveRequestedDevice(tenant, query.device_id);
    if (!device.ok) {
        return { ok: false, error: "access_denied", description: device.description };
    }
    const acr = requestedAcr(query.acr_values);
    return {
        ok: true,
        client,
        request: {
            clientId,
            redirectUri,
            scope,
            state: emptyToUndefined(query.state),
            nonce: emptyToUndefined(query.nonce),
            deviceId: device.deviceId,
            acr,
            codeChallenge
        }
    };
}
/**
 * Resolves requested or implicit device binding for the authorize request.
 */
function resolveRequestedDevice(tenant, requestedDeviceId) {
    if (requestedDeviceId) {
        const device = findDevice(tenant, requestedDeviceId);
        if (!device) {
            return { ok: false, description: "Unknown device for tenant" };
        }
        if (!device.enabled) {
            return { ok: false, description: "Device is disabled" };
        }
        return { ok: true, deviceId: device.deviceId };
    }
    const activeDevice = tenant.devices.find((device) => device.enabled);
    return { ok: true, deviceId: activeDevice?.deviceId };
}
/**
 * Extracts the supported step-up ACR from the authorize request.
 */
function requestedAcr(acrValues) {
    const requested = acrValues ? parseScopes(acrValues) : [];
    return requested.some((value) => MFA_ACR_ALIASES.has(value)) ? MFA_ACR : undefined;
}
/**
 * Converts internal ACR state back into the authorize form field.
 */
function acrValuesFromRequest(request) {
    return request.acr ?? "";
}
/**
 * Checks whether the current authentication context satisfies the requested ACR.
 */
function satisfiesRequestedAcr(request, auth) {
    if (request.acr !== MFA_ACR) {
        return true;
    }
    return auth.level === "mfa" || auth.originalLevel === "mfa";
}
/**
 * Redirects to the client callback with a newly created authorization code.
 */
function redirectWithCode(res, oidcState, tenantId, client, request, userSub, auth) {
    res.redirect(createCodeRedirectUrl(oidcState, tenantId, client, request, userSub, auth));
}
/**
 * Creates the authorization-code callback URL without writing to the response.
 */
function createCodeRedirectUrl(oidcState, tenantId, client, request, userSub, auth) {
    const code = oidcState.createCode({
        tenantId,
        clientId: client.clientId,
        redirectUri: request.redirectUri,
        scope: request.scope,
        state: request.state,
        nonce: request.nonce,
        deviceId: request.deviceId,
        acr: request.acr,
        codeChallenge: request.codeChallenge
    }, userSub, auth);
    const redirectUrl = new URL(request.redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (request.state) {
        redirectUrl.searchParams.set("state", request.state);
    }
    return redirectUrl.toString();
}
/**
 * Handles optional and mandatory TOTP steps after primary login succeeds.
 */
function handleMfaLoginStep(args) {
    const mfaRequiredByRequest = args.validation.request.acr === MFA_ACR && !satisfiesRequestedAcr(args.validation.request, args.auth);
    const mfaEnabled = mfaRequiredByRequest || args.tenant.twoFactorEnabled || args.tenant.twoFactorMandatory;
    if (!mfaEnabled) {
        return { complete: true, auth: args.auth };
    }
    const params = authorizeParamsFromRequest(args.validation.client, args.validation.request);
    const body = args.req.body && typeof args.req.body === "object" ? args.req.body : {};
    const action = readString(body.mfa_action);
    const code = readString(body.mfa_code);
    const mfaTenantId = args.user.homeTenant.tenantId;
    const mfaTenantIds = [...new Set([mfaTenantId, args.tenant.tenantId])];
    const user = args.user.user;
    const enrolled = args.mfaStore.isEnrolledForTenants(mfaTenantIds, user.sub);
    if (args.challenge) {
        // Existing challenge means the user is choosing, setting up, or verifying MFA.
        const challengeRequiresMfa = args.validation.request.acr === MFA_ACR && !satisfiesRequestedAcr(args.validation.request, args.challenge.auth);
        if (action === "continue" && !challengeRequiresMfa && !args.tenant.twoFactorMandatory && !enrolled) {
            return { complete: true, auth: args.challenge.auth };
        }
        if (action === "setup") {
            const secret = args.challenge.setupSecret ?? createTotpSecret();
            if (!code) {
                // First setup click shows the secret and asks for a code from the authenticator app.
                const setupChallenge = createMfaChallenge({
                    tenantId: args.tenant.tenantId,
                    userSub: user.sub,
                    request: args.validation.request,
                    auth: args.challenge.auth,
                    setupSecret: secret
                }, args.sessionSecret);
                args.res.type("html").send(renderMfaPage(args.tenant, {
                    mode: "setup",
                    challenge: setupChallenge,
                    params,
                    secret,
                    otpauthUri: createTotpUri({
                        issuer: args.config.baseUrl.replace(/\/$/, ""),
                        tenantId: mfaTenantId,
                        accountName: user.preferred_username,
                        secret
                    }),
                    mandatory: args.tenant.twoFactorMandatory || challengeRequiresMfa
                }));
                return { complete: false };
            }
            if (!verifyTotpSecret(secret, code)) {
                // Invalid setup codes keep the same secret so the displayed authenticator entry remains usable.
                const retryChallenge = createMfaChallenge({
                    tenantId: args.tenant.tenantId,
                    userSub: user.sub,
                    request: args.validation.request,
                    auth: args.challenge.auth,
                    setupSecret: secret
                }, args.sessionSecret);
                args.res.type("html").status(401).send(renderMfaPage(args.tenant, {
                    mode: "setup",
                    challenge: retryChallenge,
                    params,
                    secret,
                    otpauthUri: createTotpUri({
                        issuer: args.config.baseUrl.replace(/\/$/, ""),
                        tenantId: mfaTenantId,
                        accountName: user.preferred_username,
                        secret
                    }),
                    mandatory: args.tenant.twoFactorMandatory || challengeRequiresMfa,
                    error: "Authenticator code is invalid"
                }));
                return { complete: false };
            }
            args.mfaStore.enrollTotp(mfaTenantId, user.sub, secret);
            return { complete: true, auth: authContext("mfa") };
        }
        // Enrolled users must provide a valid TOTP code before login can continue.
        if (action === "verify" && code && args.mfaStore.verifyTotpForTenants(mfaTenantIds, user.sub, code)) {
            return { complete: true, auth: authContext("mfa") };
        }
        args.res.type("html").status(401).send(renderMfaPage(args.tenant, {
            mode: enrolled ? "verify" : "choose",
            challenge: createMfaChallenge({
                tenantId: args.tenant.tenantId,
                userSub: user.sub,
                request: args.validation.request,
                auth: args.challenge.auth
            }, args.sessionSecret),
            params,
            mandatory: args.tenant.twoFactorMandatory || challengeRequiresMfa,
            error: enrolled ? "Authenticator code is invalid" : "Choose a two-factor option to continue"
        }));
        return { complete: false };
    }
    // No challenge yet: decide whether the user must verify, must set up, or may choose.
    if (enrolled) {
        args.res.type("html").send(renderMfaPage(args.tenant, {
            mode: "verify",
            challenge: createMfaChallenge({
                tenantId: args.tenant.tenantId,
                userSub: user.sub,
                request: args.validation.request,
                auth: args.auth
            }, args.sessionSecret),
            params
        }));
        return { complete: false };
    }
    if (args.tenant.twoFactorMandatory || mfaRequiredByRequest) {
        const secret = createTotpSecret();
        args.res.type("html").send(renderMfaPage(args.tenant, {
            mode: "setup",
            challenge: createMfaChallenge({
                tenantId: args.tenant.tenantId,
                userSub: user.sub,
                request: args.validation.request,
                auth: args.auth,
                setupSecret: secret
            }, args.sessionSecret),
            params,
            secret,
            otpauthUri: createTotpUri({
                issuer: args.config.baseUrl.replace(/\/$/, ""),
                tenantId: mfaTenantId,
                accountName: user.preferred_username,
                secret
            }),
            mandatory: true
        }));
        return { complete: false };
    }
    args.res.type("html").send(renderMfaPage(args.tenant, {
        mode: "choose",
        challenge: createMfaChallenge({
            tenantId: args.tenant.tenantId,
            userSub: user.sub,
            request: args.validation.request,
            auth: args.auth
        }, args.sessionSecret),
        params,
        mandatory: false
    }));
    return { complete: false };
}
/**
 * Finishes an interactive login by setting a session cookie and issuing a code.
 */
function completeLogin(args) {
    if (args.tenant.enableSessions) {
        setSessionUser(args.req, args.res, args.config, args.tenant, args.user.sub, args.auth.originalLevel, args.sessionSecret);
    }
    args.logger.info("mock user selected", {
        tenantId: args.tenant.tenantId,
        clientId: args.validation.client.clientId,
        userSub: args.user.sub,
        authLevel: args.auth.level,
        authOriginalLevel: args.auth.originalLevel
    });
    redirectWithCode(args.res, args.state, args.tenant.tenantId, args.validation.client, args.validation.request, args.user.sub, args.auth);
}
/**
 * Converts a validated authorize request back into hidden login form fields.
 */
function authorizeParamsFromRequest(client, request) {
    return {
        client_id: client.clientId,
        redirect_uri: request.redirectUri,
        response_type: "code",
        scope: request.scope.join(" "),
        state: request.state ?? "",
        nonce: request.nonce ?? "",
        device_id: request.deviceId ?? "",
        acr_values: acrValuesFromRequest(request),
        code_challenge: request.codeChallenge ?? "",
        code_challenge_method: request.codeChallenge ? "S256" : ""
    };
}
/**
 * Resolves the user stored inside a signed MFA challenge.
 */
function authenticateMfaChallengeUser(config, tenant, challenge) {
    if (!challenge) {
        return { ok: false, description: "Two-factor challenge is invalid or expired" };
    }
    const user = resolveEffectiveUser(config, tenant, challenge.userSub);
    return user ? { ok: true, user, auth: challenge.auth } : { ok: false, description: "User no longer exists" };
}
/**
 * Signs the transient MFA state carried through login form posts.
 */
function createMfaChallenge(challenge, sessionSecret) {
    const payload = Buffer.from(JSON.stringify({
        ...challenge,
        expiresAt: Date.now() + 5 * 60 * 1000
    }), "utf8").toString("base64url");
    const signature = crypto.createHmac("sha256", sessionSecret).update(payload).digest("base64url");
    return `v1.${payload}.${signature}`;
}
/**
 * Verifies and decodes a signed MFA challenge.
 */
function verifyMfaChallenge(value, tenantId, sessionSecret) {
    if (!value) {
        return undefined;
    }
    const [version, payload, signature] = value.split(".");
    if (version !== "v1" || !payload || !signature) {
        return undefined;
    }
    const expected = crypto.createHmac("sha256", sessionSecret).update(payload).digest("base64url");
    if (!constantTimeEqual(signature, expected)) {
        return undefined;
    }
    // The payload is trusted only after the signature matches.
    try {
        const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
        if (decoded.tenantId !== tenantId ||
            typeof decoded.userSub !== "string" ||
            typeof decoded.expiresAt !== "number" ||
            decoded.expiresAt <= Date.now() ||
            !isAuthContext(decoded.auth) ||
            !isValidatedAuthorizeRequest(decoded.request)) {
            return undefined;
        }
        return decoded;
    }
    catch {
        return undefined;
    }
}
/**
 * Decides whether a logged-in user should be asked to enroll a passkey.
 */
function shouldShowPasskeySetup(tenant, enrolled) {
    return (tenant.passkeysEnabled || tenant.passkeysMandatory) && !enrolled;
}
/**
 * Signs transient passkey setup/authentication state.
 */
function createPasskeyLoginChallenge(challenge, sessionSecret) {
    const payload = Buffer.from(JSON.stringify({
        ...challenge,
        expiresAt: Date.now() + 5 * 60 * 1000
    }), "utf8").toString("base64url");
    const signature = crypto.createHmac("sha256", sessionSecret).update(payload).digest("base64url");
    return `v1.${payload}.${signature}`;
}
/**
 * Verifies and decodes signed passkey setup/authentication state.
 */
function verifyPasskeyChallenge(value, tenantId, sessionSecret) {
    if (!value)
        return undefined;
    const [version, payload, signature] = value.split(".");
    if (version !== "v1" || !payload || !signature)
        return undefined;
    const expected = crypto.createHmac("sha256", sessionSecret).update(payload).digest("base64url");
    if (!constantTimeEqual(signature, expected))
        return undefined;
    // The payload may contain the WebAuthn challenge and original authorize request.
    try {
        const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
        if (decoded.tenantId !== tenantId ||
            typeof decoded.userSub !== "string" ||
            typeof decoded.expiresAt !== "number" ||
            decoded.expiresAt <= Date.now() ||
            !isAuthContext(decoded.auth) ||
            (decoded.webauthnChallenge !== undefined && typeof decoded.webauthnChallenge !== "string") ||
            !isValidatedAuthorizeRequest(decoded.request)) {
            return undefined;
        }
        return decoded;
    }
    catch {
        return undefined;
    }
}
/**
 * Returns the browser origin that WebAuthn client data must report.
 */
function passkeyOrigin(config) {
    const url = new URL(config.baseUrl);
    return url.origin;
}
/**
 * Returns the relying-party ID used for passkey registration and authentication.
 */
function passkeyRpId(config) {
    return new URL(config.baseUrl).hostname;
}
/**
 * Validates decoded authentication context stored in signed login challenges.
 */
function isAuthContext(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const auth = value;
    return isAuthLevel(auth.level) && isAuthLevel(auth.originalLevel);
}
/**
 * Validates decoded challenge state before trusting it as an authorize request.
 */
function isValidatedAuthorizeRequest(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const request = value;
    return typeof request.clientId === "string" &&
        typeof request.redirectUri === "string" &&
        Array.isArray(request.scope) &&
        request.scope.every((scope) => typeof scope === "string") &&
        (request.state === undefined || typeof request.state === "string") &&
        (request.nonce === undefined || typeof request.nonce === "string") &&
        (request.deviceId === undefined || typeof request.deviceId === "string") &&
        (request.codeChallenge === undefined || (typeof request.codeChallenge === "string" && isS256CodeChallenge(request.codeChallenge))) &&
        (request.acr === undefined || request.acr === MFA_ACR);
}
/**
 * Ensures an MFA or passkey continuation is still bound to its original authorize request.
 */
function sameAuthorizeRequest(left, right) {
    return left.clientId === right.clientId &&
        left.redirectUri === right.redirectUri &&
        left.scope.length === right.scope.length &&
        left.scope.every((scope, index) => scope === right.scope[index]) &&
        left.state === right.state &&
        left.nonce === right.nonce &&
        left.deviceId === right.deviceId &&
        left.acr === right.acr &&
        left.codeChallenge === right.codeChallenge;
}
/**
 * Compares two strings without leaking timing differences for equal-length values.
 */
function constantTimeEqual(actualValue, expectedValue) {
    const actual = Buffer.from(actualValue);
    const expected = Buffer.from(expectedValue);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
/**
 * Exchanges an authorization code for access, ID, and optional refresh tokens.
 */
async function handleAuthorizationCodeGrant(args) {
    const code = readString(args.req.body.code);
    const redirectUri = readString(args.req.body.redirect_uri);
    if (!code || !redirectUri) {
        args.logger.warn("authorization code grant rejected because required fields are missing", {
            tenantId: args.tenant.tenantId,
            clientId: args.client.clientId
        });
        sendTokenError(args.res, "invalid_request", "code and redirect_uri are required");
        return;
    }
    // Authorization codes are single-use and must match tenant, client, and redirect URI.
    const entry = args.state.consumeCode(code);
    if (!entry ||
        entry.tenantId !== args.tenant.tenantId ||
        entry.clientId !== args.client.clientId ||
        entry.redirectUri !== redirectUri) {
        args.logger.warn("authorization code grant rejected", {
            tenantId: args.tenant.tenantId,
            clientId: args.client.clientId
        });
        sendTokenError(args.res, "invalid_grant", "Authorization code is invalid or expired");
        return;
    }
    const rawCodeVerifier = args.req.body.code_verifier;
    if (rawCodeVerifier !== undefined && typeof rawCodeVerifier !== "string") {
        sendTokenError(args.res, "invalid_request", "code_verifier must be a single string value");
        return;
    }
    const codeVerifier = typeof rawCodeVerifier === "string" ? rawCodeVerifier : undefined;
    if (entry.codeChallenge ? !verifyCodeVerifier(codeVerifier, entry.codeChallenge) : codeVerifier !== undefined) {
        sendTokenError(args.res, "invalid_grant", "PKCE code_verifier is invalid");
        return;
    }
    const resolvedUser = resolveEffectiveUser(args.config, args.tenant, entry.userSub);
    if (!resolvedUser) {
        args.logger.warn("authorization code grant rejected because user is missing", {
            tenantId: args.tenant.tenantId,
            clientId: args.client.clientId,
            userSub: entry.userSub
        });
        sendTokenError(args.res, "invalid_grant", "User no longer exists");
        return;
    }
    // Refresh tokens are issued only when offline_access was part of the original request.
    const refreshTokenExpiresAt = Date.now() + args.config.refreshTokenLifetimeSeconds * 1000;
    const refreshToken = entry.scope.includes("offline_access")
        ? args.state.createRefreshToken({
            tenantId: args.tenant.tenantId,
            clientId: args.client.clientId,
            userSub: resolvedUser.user.sub,
            scope: entry.scope,
            authLevel: entry.authLevel,
            authOriginalLevel: entry.authOriginalLevel,
            nonce: entry.nonce,
            deviceId: entry.deviceId,
            acr: entry.acr,
            expiresAt: refreshTokenExpiresAt
        })
        : undefined;
    await sendTokenSet(args.res, {
        config: args.config,
        keys: args.keys,
        state: args.state,
        tenant: args.tenant,
        client: args.client,
        user: resolvedUser.user,
        scope: entry.scope,
        auth: authContext(entry.authLevel, entry.authOriginalLevel),
        nonce: entry.nonce,
        deviceId: entry.deviceId,
        acr: entry.acr,
        refreshToken,
        refreshTokenExpiresAt: refreshToken ? refreshTokenExpiresAt : undefined
    });
    args.logger.info("authorization code grant completed", {
        tenantId: args.tenant.tenantId,
        clientId: args.client.clientId,
        userSub: resolvedUser.user.sub,
        refreshTokenIssued: Boolean(refreshToken)
    });
}
/**
 * Exchanges a refresh token for a new token set, rotating it when configured.
 */
async function handleRefreshTokenGrant(args) {
    const token = readString(args.req.body.refresh_token);
    if (!token) {
        args.logger.warn("refresh token grant rejected because refresh_token is missing", {
            tenantId: args.tenant.tenantId,
            clientId: args.client.clientId
        });
        sendTokenError(args.res, "invalid_request", "refresh_token is required");
        return;
    }
    // Refresh tokens are scoped to the tenant and client that received them.
    const entry = args.state.getRefreshToken(token);
    if (!entry || entry.tenantId !== args.tenant.tenantId || entry.clientId !== args.client.clientId) {
        args.logger.warn("refresh token grant rejected", {
            tenantId: args.tenant.tenantId,
            clientId: args.client.clientId
        });
        sendTokenError(args.res, "invalid_grant", "Refresh token is invalid or expired");
        return;
    }
    const resolvedUser = resolveEffectiveUser(args.config, args.tenant, entry.userSub);
    if (!resolvedUser) {
        args.logger.warn("refresh token grant rejected because user is missing", {
            tenantId: args.tenant.tenantId,
            clientId: args.client.clientId,
            userSub: entry.userSub
        });
        sendTokenError(args.res, "invalid_grant", "User no longer exists");
        return;
    }
    // Device binding invalidates refresh tokens when the original login device is removed or disabled.
    const device = entry.deviceId ? findDevice(args.tenant, entry.deviceId) : undefined;
    if (isInactiveRefreshTokenDevice(args.tenant, entry.deviceId, device)) {
        args.logger.warn("refresh token grant rejected because device is inactive", {
            tenantId: args.tenant.tenantId,
            clientId: args.client.clientId,
            userSub: entry.userSub,
            deviceId: entry.deviceId
        });
        sendTokenError(args.res, "invalid_grant", "Device used for original sign-in is inactive");
        return;
    }
    let refreshToken = token;
    let refreshTokenExpiresAt = entry.expiresAt;
    if (args.config.rotateRefreshTokens) {
        // Rotation mirrors real-world refresh-token replay mitigation.
        args.state.revokeRefreshToken(token);
        refreshTokenExpiresAt = Date.now() + args.config.refreshTokenLifetimeSeconds * 1000;
        refreshToken = args.state.createRefreshToken({
            tenantId: entry.tenantId,
            clientId: entry.clientId,
            userSub: entry.userSub,
            scope: entry.scope,
            authLevel: entry.authLevel,
            authOriginalLevel: entry.authOriginalLevel,
            nonce: entry.nonce,
            deviceId: entry.deviceId,
            acr: entry.acr,
            expiresAt: refreshTokenExpiresAt
        });
    }
    await sendTokenSet(args.res, {
        config: args.config,
        keys: args.keys,
        state: args.state,
        tenant: args.tenant,
        client: args.client,
        user: resolvedUser.user,
        scope: entry.scope,
        auth: authContext(entry.authLevel, entry.authOriginalLevel),
        nonce: entry.nonce,
        deviceId: entry.deviceId,
        acr: entry.acr,
        refreshToken,
        refreshTokenExpiresAt
    });
    args.logger.info("refresh token grant completed", {
        tenantId: args.tenant.tenantId,
        clientId: args.client.clientId,
        userSub: resolvedUser.user.sub,
        refreshTokenRotated: args.config.rotateRefreshTokens
    });
}
/**
 * Sends the OAuth token response payload.
 */
async function sendTokenSet(res, args) {
    const input = {
        config: args.config,
        keys: args.keys,
        tenant: args.tenant,
        client: args.client,
        user: args.user,
        scope: args.scope,
        auth: args.auth,
        acr: args.acr,
        nonce: args.nonce,
        deviceId: args.deviceId
    };
    const raw = JSON.stringify({ uid: args.user.sub, utid: args.tenant.tenantId });
    // Azure clients expect client_info to be base64url JSON with uid and utid.
    const enc = Buffer.from(raw)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
    res.json({
        client_info: enc,
        token_type: "Bearer",
        expires_in: args.config.tokenLifetimeSeconds,
        scope: args.scope.join(" "),
        access_token: await createAccessToken(input),
        id_token: await createIdToken(input),
        ...(args.refreshToken && args.refreshTokenExpiresAt ? {
            refresh_token: args.refreshToken,
            refresh_token_expires_in: Math.max(0, Math.floor((args.refreshTokenExpiresAt - Date.now()) / 1000)),
            refresh_token_expires_at: Math.floor(args.refreshTokenExpiresAt / 1000)
        } : {})
    });
}
/**
 * Authenticates a token endpoint client through Basic auth or form fields.
 */
function authenticateClient(tenant, req, rotationStore) {
    const basic = parseBasicAuth(req);
    const clientId = basic?.clientId ?? readString(req.body.client_id);
    const clientSecret = basic?.clientSecret ?? readString(req.body.client_secret);
    if (!clientId) {
        return undefined;
    }
    const client = findClient(tenant, clientId);
    if (!client || !client.enabled) {
        return undefined;
    }
    const configuredSecrets = [
        ...(client.clientSecret ? [client.clientSecret] : []),
        ...(!rotationStore ? (client.clientSecrets ?? []).map((credential) => credential.secret) : [])
    ];
    let matchesConfiguredSecret = rotationStore
        ? rotationStore.verifyNamedSecret(tenant.tenantId, client, clientSecret ?? "")
        : false;
    for (const configuredSecret of configuredSecrets) {
        // Check every configured value so a match's position does not reveal the named slot.
        const matches = constantTimeEqual(clientSecret ?? "", configuredSecret);
        matchesConfiguredSecret = matches || matchesConfiguredSecret;
    }
    const namedSecretConfigured = rotationStore
        ? rotationStore.requiresClientSecret(tenant.tenantId, client.clientId)
        : Boolean(client.clientSecrets?.length);
    if ((configuredSecrets.length > 0 || namedSecretConfigured) && !matchesConfiguredSecret) {
        return undefined;
    }
    return client;
}
/**
 * Parses OAuth client credentials from an Authorization: Basic header.
 */
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
/**
 * Authenticates either the mock user picker or secure email/password login.
 */
function authenticateLogin(config, tenant, req, passwordStore) {
    if (!tenant.secure) {
        // Non-secure tenants intentionally trust the selected mock user.
        const userSub = readString(req.body.user_sub);
        const user = userSub ? resolveEffectiveUser(config, tenant, userSub) : undefined;
        return user ? { ok: true, user, auth: authContext("mock") } : { ok: false, description: "Unknown user" };
    }
    // Secure tenants verify the password against the source tenant for shared users.
    const username = readString(req.body.username)?.toLowerCase();
    const password = readString(req.body.password);
    if (!username || !password) {
        return { ok: false, description: "Email and password are required" };
    }
    const user = resolveEffectiveUserByUsername(config, tenant, username);
    if (!user || !passwordStore.verify(user.homeTenant.tenantId, user.user.sub, password)) {
        return { ok: false, description: "Invalid email or password" };
    }
    return { ok: true, user, auth: authContext("password") };
}
/**
 * Collects the tenant's advertised scopes from every configured client.
 */
function tenantScopes(tenant) {
    return [...new Set(tenant.clients.flatMap((client) => client.allowedScopes))].sort();
}
