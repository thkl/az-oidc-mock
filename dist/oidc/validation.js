/**
 * Finds a tenant by its configured tenant ID.
 */
export function findTenant(config, tenantId) {
    return config.tenants.find((tenant) => tenant.tenantId === tenantId);
}
/**
 * Finds a client registration inside a tenant.
 */
export function findClient(tenant, clientId) {
    return tenant.clients.find((client) => client.clientId === clientId);
}
/**
 * Finds a registered device inside a tenant.
 */
export function findDevice(tenant, deviceId) {
    return tenant.devices.find((device) => device.deviceId === deviceId);
}
/**
 * Finds a user inside a tenant by subject identifier.
 */
export function findUser(tenant, sub) {
    return tenant.users.find((user) => user.sub === sub);
}
/**
 * Checks whether the redirect URI is registered for the client.
 */
export function validateRedirectUri(client, redirectUri) {
    return client.redirectUris.includes(redirectUri);
}
/**
 * Parses a space-delimited OAuth scope string into unique scope names.
 */
export function parseScopes(scope) {
    return [...new Set((scope ?? "openid").split(/\s+/).filter(Boolean))];
}
/**
 * Checks whether every requested scope is allowed for the client.
 */
export function validateScopes(client, scopes) {
    return scopes.every((scope) => client.allowedScopes.includes(scope));
}
