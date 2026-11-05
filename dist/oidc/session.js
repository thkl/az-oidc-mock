import crypto from "node:crypto";
import fs from "node:fs";
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
 * Loads the session signing secret from disk, creating it once for this config directory.
 */
export function loadOrCreateSessionSecret(secretPath) {
    try {
        return readPersistedSessionSecret(secretPath);
    }
    catch (error) {
        if (!isMissingFile(error)) {
            throw error;
        }
    }
    const secret = createDefaultSessionSecret();
    const temporaryPath = `${secretPath}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
    try {
        // Link a fully written temporary file so concurrent processes never read a partial secret.
        fs.writeFileSync(temporaryPath, `${secret}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
        try {
            fs.linkSync(temporaryPath, secretPath);
            return secret;
        }
        catch (error) {
            if (!isAlreadyExists(error)) {
                throw error;
            }
            return readPersistedSessionSecret(secretPath);
        }
    }
    finally {
        fs.rmSync(temporaryPath, { force: true });
    }
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
/**
 * Reads a persisted secret and rejects empty or truncated files instead of invalidating sessions silently.
 */
function readPersistedSessionSecret(secretPath) {
    const secret = fs.readFileSync(secretPath, "utf8").trim();
    if (secret.length < 32) {
        throw new Error(`Persisted session secret must contain at least 32 characters: ${secretPath}`);
    }
    return secret;
}
/**
 * Checks whether a filesystem operation failed because the secret file is not present yet.
 */
function isMissingFile(error) {
    return isNodeError(error) && error.code === "ENOENT";
}
/**
 * Checks whether another process created the secret first.
 */
function isAlreadyExists(error) {
    return isNodeError(error) && error.code === "EEXIST";
}
/**
 * Narrows filesystem errors to Node errors with a code field.
 */
function isNodeError(error) {
    return error instanceof Error && "code" in error;
}
