import crypto from "node:crypto";
import { resolveEffectiveUser } from "./users.js";
export function getSessionUser(req, config, tenant, sessionSecret) {
    const cookie = parseCookies(req.header("cookie"))[`az_oidc_mock_${tenant.tenantId}`];
    const userSub = cookie ? verifySessionCookie(cookie, tenant.tenantId, sessionSecret) : undefined;
    return userSub ? resolveEffectiveUser(config, tenant, userSub)?.user : undefined;
}
export function setSessionUser(req, res, config, tenant, userSub, sessionSecret) {
    const maxAge = tenant.sessionLifetimeSeconds * 1000;
    res.cookie(`az_oidc_mock_${tenant.tenantId}`, createSessionCookie(tenant.tenantId, userSub, Date.now() + maxAge, sessionSecret), {
        httpOnly: true,
        sameSite: "lax",
        secure: isSecureRequest(req, config),
        path: `/${tenant.tenantId}`,
        maxAge
    });
}
export function clearSessionUser(req, res, config, tenantId) {
    res.clearCookie(`az_oidc_mock_${tenantId}`, {
        httpOnly: true,
        sameSite: "lax",
        secure: isSecureRequest(req, config),
        path: `/${tenantId}`
    });
}
export function createDefaultSessionSecret() {
    return crypto.randomBytes(32).toString("base64url");
}
export function constantTimeEqual(actualValue, expectedValue) {
    const actual = Buffer.from(actualValue);
    const expected = Buffer.from(expectedValue);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
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
function createSessionCookie(tenantId, userSub, expiresAt, sessionSecret) {
    const payload = base64UrlJson({ tenantId, userSub, expiresAt });
    const signature = signSessionPayload(payload, sessionSecret);
    return `v1.${payload}.${signature}`;
}
function verifySessionCookie(cookie, tenantId, sessionSecret) {
    const [version, payload, signature] = cookie.split(".");
    if (version !== "v1" || !payload || !signature) {
        return undefined;
    }
    const expected = signSessionPayload(payload, sessionSecret);
    if (!constantTimeEqual(signature, expected)) {
        return undefined;
    }
    const decoded = parseBase64UrlJson(payload);
    if (decoded?.tenantId !== tenantId ||
        typeof decoded.userSub !== "string" ||
        typeof decoded.expiresAt !== "number" ||
        decoded.expiresAt <= Date.now()) {
        return undefined;
    }
    return decoded.userSub;
}
function signSessionPayload(payload, sessionSecret) {
    return crypto.createHmac("sha256", sessionSecret).update(payload).digest("base64url");
}
function isSecureRequest(req, config) {
    const forwardedProto = req.header("x-forwarded-proto")?.split(",")[0]?.trim().toLowerCase();
    return req.secure || forwardedProto === "https" || new URL(config.baseUrl).protocol === "https:";
}
function base64UrlJson(value) {
    return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}
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
