import crypto from "node:crypto";
import { isAuthLevel } from "./auth-level.js";
import { resolveEffectiveUser } from "./users.js";
/**
 * Reads and verifies the tenant-scoped login session cookie.
 */
export function getSessionUser(req, config, tenant, sessionSecret) {
    const cookie = parseCookies(req.header("cookie"))[`az_oidc_mock_${tenant.tenantId}`];
    const session = cookie ? verifySessionCookie(cookie, tenant.tenantId, sessionSecret) : undefined;
    if (!session) {
        return undefined;
    }
    const user = resolveEffectiveUser(config, tenant, session.userSub)?.user;
    return user ? { user, authLevel: session.authLevel } : undefined;
}
/**
 * Issues a signed HTTP-only login session cookie for the tenant.
 */
export function setSessionUser(req, res, config, tenant, userSub, authLevel, sessionSecret) {
    const maxAge = tenant.sessionLifetimeSeconds * 1000;
    res.cookie(`az_oidc_mock_${tenant.tenantId}`, createSessionCookie(tenant.tenantId, userSub, authLevel, Date.now() + maxAge, sessionSecret), {
        httpOnly: true,
        sameSite: "lax",
        secure: isSecureRequest(req, config),
        path: `/${tenant.tenantId}`,
        maxAge
    });
}
/**
 * Clears the tenant-scoped login session cookie.
 */
export function clearSessionUser(req, res, config, tenantId) {
    res.clearCookie(`az_oidc_mock_${tenantId}`, {
        httpOnly: true,
        sameSite: "lax",
        secure: isSecureRequest(req, config),
        path: `/${tenantId}`
    });
}
/**
 * Creates the fallback per-process session signing secret.
 */
export function createDefaultSessionSecret() {
    return crypto.randomBytes(32).toString("base64url");
}
/**
 * Compares two strings without leaking timing differences for equal-length values.
 */
export function constantTimeEqual(actualValue, expectedValue) {
    const actual = Buffer.from(actualValue);
    const expected = Buffer.from(expectedValue);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
/**
 * Parses a Cookie header into decoded cookie name/value pairs.
 */
function parseCookies(header) {
    if (!header)
        return {};
    return Object.fromEntries(header
        .split(";")
        .map((part) => part.trim().split("="))
        .filter(([key, value]) => key && value)
        .map(([key, value]) => [key, decodeURIComponent(value)]));
}
/**
 * Creates the signed cookie payload that stores tenant, subject, and expiry.
 */
function createSessionCookie(tenantId, userSub, authLevel, expiresAt, sessionSecret) {
    const payload = base64UrlJson({ tenantId, userSub, authLevel, expiresAt });
    const signature = signSessionPayload(payload, sessionSecret);
    return `v1.${payload}.${signature}`;
}
/**
 * Verifies the signed session cookie and returns its user and original auth level when valid.
 */
function verifySessionCookie(cookie, tenantId, sessionSecret) {
    const [version, payload, signature] = cookie.split(".");
    if (version !== "v1" || !payload || !signature) {
        return undefined;
    }
    const expected = signSessionPayload(payload, sessionSecret);
    if (!constantTimeEqual(signature, expected)) {
        return undefined;
    }
    // The payload is trusted only after the HMAC has been checked.
    const decoded = parseBase64UrlJson(payload);
    if (decoded?.tenantId !== tenantId ||
        typeof decoded.userSub !== "string" ||
        typeof decoded.expiresAt !== "number" ||
        decoded.expiresAt <= Date.now()) {
        return undefined;
    }
    return {
        userSub: decoded.userSub,
        authLevel: isAuthLevel(decoded.authLevel) ? decoded.authLevel : "cookie"
    };
}
/**
 * Signs a session payload with the shared session secret.
 */
function signSessionPayload(payload, sessionSecret) {
    return crypto.createHmac("sha256", sessionSecret).update(payload).digest("base64url");
}
/**
 * Decides whether cookies should be marked Secure for direct or proxied HTTPS.
 */
function isSecureRequest(req, config) {
    const forwardedProto = req.header("x-forwarded-proto")?.split(",")[0]?.trim().toLowerCase();
    return req.secure || forwardedProto === "https" || new URL(config.baseUrl).protocol === "https:";
}
/**
 * Encodes JSON as URL-safe base64 for cookie payloads.
 */
function base64UrlJson(value) {
    return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}
/**
 * Decodes a URL-safe base64 JSON object, returning undefined on malformed input.
 */
function parseBase64UrlJson(value) {
    try {
        const decoded = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
        return decoded && typeof decoded === "object" && !Array.isArray(decoded)
            ? decoded
            : undefined;
    }
    catch {
        return undefined;
    }
}
