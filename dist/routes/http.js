import { findTenant } from "../oidc/validation.js";
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
export function sendTokenError(res, error, description, status = 400) {
    res.status(status).json({ error, error_description: description });
}
export function readBearerToken(req) {
    const header = req.header("authorization");
    if (!header?.startsWith("Bearer ")) {
        return undefined;
    }
    return readString(header.slice("Bearer ".length).trim());
}
export function readObjectBody(req) {
    return req.body && typeof req.body === "object" ? req.body : {};
}
export function readString(value) {
    return typeof value === "string" && value.length > 0 ? value : undefined;
}
export function readParamString(value) {
    if (Array.isArray(value)) {
        return value[0];
    }
    return readString(value);
}
export function emptyToUndefined(value) {
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
