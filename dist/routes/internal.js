import { resolveVerifiedTokenSubject } from "../oidc/token-subject.js";
import { verifyAccessToken } from "../oidc/tokens.js";
import { findUser } from "../oidc/validation.js";
import { constantTimeEqual } from "../oidc/session.js";
import { getTenantOr404, readBearerToken, readObjectBody, readString } from "./http.js";
/**
 * Registers internal service endpoints for token introspection and password management.
 */
export function registerInternalRoutes(app, context) {
    /**
     * Verifies an access token for mocked downstream services.
     */
    app.post("/:tenantId/internal/token/verify", async (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        const body = readObjectBody(req);
        const token = readBearerToken(req) ?? readString(body.token) ?? readString(body.access_token);
        const audience = readString(body.audience) ?? readString(body.client_id);
        if (!token) {
            res.status(400).json({
                active: false,
                error: "invalid_request",
                error_description: "Bearer token or token body field is required"
            });
            return;
        }
        // First verify the JWT cryptographically, then ensure the backing config objects are active.
        const verification = await verifyAccessToken({ config, keys: context.keys, tenant, token, audience });
        if (!verification.ok) {
            context.logger.warn("internal token verification failed", {
                tenantId: tenant.tenantId,
                error: verification.error
            });
            res.status(401).json({
                active: false,
                error: verification.error,
                error_description: verification.description
            });
            return;
        }
        const subject = resolveVerifiedTokenSubject(config, tenant, verification.claims);
        if (!subject.ok) {
            context.logger.warn("internal token verification rejected unknown claims", {
                tenantId: tenant.tenantId,
                audience: verification.claims.aud,
                subject: verification.claims.sub,
                deviceId: verification.claims.deviceid
            });
            res.status(401).json({
                active: false,
                error: "invalid_token",
                error_description: subject.description
            });
            return;
        }
        context.logger.verbose(config, "internal token verification succeeded", {
            tenantId: tenant.tenantId,
            clientId: subject.client.clientId,
            userSub: subject.user.sub
        });
        res.json({
            active: true,
            tenant_id: tenant.tenantId,
            client_id: subject.client.clientId,
            user_sub: subject.user.sub,
            ...(subject.device ? { device_id: subject.device.deviceId } : {}),
            claims: verification.claims
        });
    });
    /**
     * Sets or rotates a secure-tenant password using the out-of-band admin token.
     */
    app.post("/:tenantId/internal/passwords", (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        if (!authorizeAdminRequest(req, context.adminToken)) {
            res.status(401).json({ error: "unauthorized", error_description: "Admin token is required" });
            return;
        }
        const body = readObjectBody(req);
        const user = resolvePasswordUser(tenant, body);
        const password = readString(body.password);
        if (!user || !password) {
            res.status(400).json({
                error: "invalid_request",
                error_description: "user_sub or username and password are required"
            });
            return;
        }
        context.passwordStore.setPassword(tenant.tenantId, user.sub, password);
        context.logger.info("secure tenant password updated", { tenantId: tenant.tenantId, userSub: user.sub });
        res.json({ updated: true, tenant_id: tenant.tenantId, user_sub: user.sub });
    });
    /**
     * Removes a secure-tenant password using the out-of-band admin token.
     */
    app.delete("/:tenantId/internal/passwords", (req, res) => {
        const config = context.getConfig();
        const tenant = getTenantOr404(config, req, res);
        if (!tenant)
            return;
        if (!authorizeAdminRequest(req, context.adminToken)) {
            res.status(401).json({ error: "unauthorized", error_description: "Admin token is required" });
            return;
        }
        const body = readObjectBody(req);
        const user = resolvePasswordUser(tenant, body);
        if (!user) {
            res.status(400).json({
                error: "invalid_request",
                error_description: "user_sub or username is required"
            });
            return;
        }
        const deleted = context.passwordStore.deletePassword(tenant.tenantId, user.sub);
        context.logger.info("secure tenant password removed", { tenantId: tenant.tenantId, userSub: user.sub, deleted });
        res.json({ deleted, tenant_id: tenant.tenantId, user_sub: user.sub });
    });
}
/**
 * Resolves a password-management target by subject or username.
 */
function resolvePasswordUser(tenant, body) {
    const userSub = readString(body.user_sub) ?? readString(body.userSub);
    if (userSub) {
        return findUser(tenant, userSub);
    }
    const username = readString(body.username)?.toLowerCase();
    if (!username) {
        return undefined;
    }
    return tenant.users.find((candidate) => candidate.email.toLowerCase() === username ||
        candidate.preferred_username.toLowerCase() === username);
}
/**
 * Verifies the configured internal admin token in a bearer or x-admin-token header.
 */
function authorizeAdminRequest(req, adminToken) {
    if (!adminToken) {
        return false;
    }
    const suppliedToken = readBearerToken(req) ?? readString(req.header("x-admin-token"));
    if (!suppliedToken) {
        return false;
    }
    return constantTimeEqual(suppliedToken, adminToken);
}
