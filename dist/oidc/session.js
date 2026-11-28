import crypto from "node:crypto";
import fs from "node:fs";
import { ensurePrivateFilePermissions } from "../private-file.js";
import { isAuthLevel } from "./auth-level.js";
import { resolveEffectiveUser } from "./users.js";
const LOGIN_CSRF_TOKEN_LIFETIME_MS = 30 * 60 * 1000;
/**
 * Reads and verifies the tenant-scoped login session cookie.
 */
export function getSessionUser(req, config, tenant, sessionSecret, passkeyStore) {
    const cookie = parseCookies(req.header("cookie"))[`az_oidc_mock_${tenant.tenantId}`];
    const session = cookie ? verifySessionCookie(cookie, tenant.tenantId, sessionSecret) : undefined;
    if (!session) {
        return undefined;
    }
    const resolvedUser = resolveEffectiveUser(config, tenant, session.userSub);
    if (resolvedUser && tenant.passkeysMandatory && !passkeyStore?.isEnrolled(resolvedUser.homeTenant.tenantId, resolvedUser.user.sub)) {
        return undefined;
    }
    return resolvedUser ? { user: resolvedUser.user, authLevel: session.authLevel, authTime: session.authTime } : undefined;
}
/**
 * Issues a signed HTTP-only login session cookie for the tenant.
 */
export function setSessionUser(req, res, config, tenant, userSub, authLevel, sessionSecret, authTime) {
    const maxAge = tenant.sessionLifetimeSeconds * 1000;
    res.cookie(`az_oidc_mock_${tenant.tenantId}`, createSessionCookie(tenant.tenantId, userSub, authLevel, authTime, Date.now() + maxAge, sessionSecret), {
        httpOnly: true,
        sameSite: "lax",
        secure: isSecureRequest(req, config),
        path: `/${tenant.tenantId}`,
        maxAge
    });
}
/**
 * Issues or reuses a signed tenant-scoped CSRF token for interactive login forms.
 */
export function getOrCreateLoginCsrfToken(req, res, config, tenant, sessionSecret) {
    const cookieName = loginCsrfCookieName(tenant);
    const existing = readCookie(req.header("cookie"), cookieName);
    if (existing && isValidLoginCsrfToken(existing, tenant, sessionSecret)) {
        return existing;
    }
    const token = createLoginCsrfToken(tenant, sessionSecret);
    res.cookie(cookieName, token, {
        httpOnly: true,
        sameSite: "lax",
        secure: isSecureRequest(req, config),
        path: `/${encodeURIComponent(tenant.tenantId)}`,
        maxAge: LOGIN_CSRF_TOKEN_LIFETIME_MS
    });
    return token;
}
/**
 * Verifies the hidden login form token against its signed, tenant-scoped cookie.
 */
export function verifyLoginCsrfToken(req, tenant, sessionSecret) {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const submitted = typeof body.csrf_token === "string" ? body.csrf_token : "";
    const cookie = readCookie(req.header("cookie"), loginCsrfCookieName(tenant));
    return submitted.length <= 512 && !!cookie && constantTimeEqual(submitted, cookie) &&
        isValidLoginCsrfToken(cookie, tenant, sessionSecret);
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
 * Reads one cookie without accepting duplicate names or malformed encoding.
 */
function readCookie(header, name) {
    if (!header)
        return undefined;
    let found;
    for (const part of header.split(";")) {
        const separator = part.indexOf("=");
        if (separator < 0 || part.slice(0, separator).trim() !== name)
            continue;
        if (found !== undefined)
            return undefined;
        try {
            found = decodeURIComponent(part.slice(separator + 1).trim());
        }
        catch {
            return undefined;
        }
    }
    return found;
}
/**
 * Names the tenant-scoped pre-authentication CSRF cookie.
 */
function loginCsrfCookieName(tenant) {
    return `az_oidc_mock_csrf_${tenant.tenantId}`;
}
/**
 * Creates a short-lived HMAC-signed pre-authentication CSRF token.
 */
function createLoginCsrfToken(tenant, sessionSecret) {
    const expiresAt = Date.now() + LOGIN_CSRF_TOKEN_LIFETIME_MS;
    const nonce = crypto.randomBytes(32).toString("base64url");
    const payload = `${tenant.tenantId}\n${expiresAt}\n${nonce}`;
    const signature = crypto.createHmac("sha256", sessionSecret).update(`login-csrf\n${payload}`).digest("base64url");
    return `v1.${expiresAt}.${nonce}.${signature}`;
}
/**
 * Verifies the token's format, lifetime, tenant binding, and HMAC signature.
 */
function isValidLoginCsrfToken(token, tenant, sessionSecret) {
    if (token.length > 512)
        return false;
    const [version, expiryText, nonce, signature, extra] = token.split(".");
    const expiresAt = Number(expiryText);
    if (version !== "v1" || extra !== undefined || !/^\d+$/.test(expiryText ?? "") ||
        !Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() ||
        expiresAt > Date.now() + LOGIN_CSRF_TOKEN_LIFETIME_MS + 1000 ||
        !/^[A-Za-z0-9_-]{43}$/.test(nonce ?? "") || !/^[A-Za-z0-9_-]{43}$/.test(signature ?? "")) {
        return false;
    }
    const payload = `${tenant.tenantId}\n${expiresAt}\n${nonce}`;
    const expected = crypto.createHmac("sha256", sessionSecret).update(`login-csrf\n${payload}`).digest("base64url");
    return constantTimeEqual(signature, expected);
}
/**
 * Creates the signed cookie payload that stores tenant, subject, and expiry.
 */
function createSessionCookie(tenantId, userSub, authLevel, authTime, expiresAt, sessionSecret) {
    const payload = base64UrlJson({ tenantId, userSub, authLevel, authTime, expiresAt });
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
        authLevel: isAuthLevel(decoded.authLevel) ? decoded.authLevel : "cookie",
        authTime: Number.isSafeInteger(decoded.authTime) ? decoded.authTime : undefined
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
    ensurePrivateFilePermissions(secretPath);
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
