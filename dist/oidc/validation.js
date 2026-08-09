export function findTenant(config, tenantId) {
    return config.tenants.find((tenant) => tenant.tenantId === tenantId);
}
export function findClient(tenant, clientId) {
    return tenant.clients.find((client) => client.clientId === clientId);
}
export function findUser(tenant, sub) {
    return tenant.users.find((user) => user.sub === sub);
}
export function validateRedirectUri(client, redirectUri) {
    return client.redirectUris.includes(redirectUri);
}
export function parseScopes(scope) {
    return [...new Set((scope ?? "openid").split(/\s+/).filter(Boolean))];
}
export function validateScopes(client, scopes) {
    return scopes.every((scope) => client.allowedScopes.includes(scope));
}
