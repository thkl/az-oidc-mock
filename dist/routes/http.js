import { findTenant } from "../oidc/validation.js";
/**
 * Resolves the route tenant parameter and sends a shared 404 response on failure.
 */
export function getTenantOr404(config, req, res) {
    const tenantId = readParamString(req.params.tenantId);
    if (!tenantId) {
        res.status(404).json({ error: "tenant_not_found" });
        return undefined;
    }
    const tenant = findTenant(config, tenantId);
    if (!tenant) {
        res.status(404).json({ error: "tenant_not_found" });
    }
    return tenant;
}
/**
 * Sends an OAuth authorize error either through the redirect URI or as JSON.
 */
export function sendAuthorizeError(res, redirectUri, state, error, description) {
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
/**
 * Sends an OAuth token-endpoint JSON error with the requested HTTP status.
 */
export function sendTokenError(res, error, description, status = 400) {
    res.status(status).json({ error, error_description: description });
}
/**
 * Reads a bearer token from the Authorization header.
 */
export function readBearerToken(req) {
    const header = req.header("authorization");
    if (!header?.startsWith("Bearer ")) {
        return undefined;
    }
    return readString(header.slice("Bearer ".length).trim());
}
/**
 * Narrows Express's untyped body value to an object record.
 */
export function readObjectBody(req) {
    return req.body && typeof req.body === "object" ? req.body : {};
}
/**
 * Returns non-empty strings while treating all other values as absent.
 */
export function readString(value) {
    return typeof value === "string" && value.length > 0 ? value : undefined;
}
/**
 * Reads an Express route parameter that may have been parsed as an array.
 */
export function readParamString(value) {
    if (Array.isArray(value)) {
        return value[0];
    }
    return readString(value);
}
/**
 * Preserves non-empty form fields and drops empty strings.
 */
export function emptyToUndefined(value) {
    return value && value.length > 0 ? value : undefined;
}
/**
 * Checks whether a string can be parsed as an absolute URL.
 */
function isUrl(value) {
    try {
        new URL(value);
        return true;
    }
    catch {
        return false;
    }
}
