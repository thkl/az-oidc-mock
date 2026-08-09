import type { AppConfig, MockClient, MockTenant, MockUser } from "../config.js";

/**
 * Finds a tenant by its configured tenant ID.
 */
export function findTenant(config: AppConfig, tenantId: string): MockTenant | undefined {
  return config.tenants.find((tenant) => tenant.tenantId === tenantId);
}

/**
 * Finds a client registration inside a tenant.
 */
export function findClient(tenant: MockTenant, clientId: string): MockClient | undefined {
  return tenant.clients.find((client) => client.clientId === clientId);
}

/**
 * Finds a user inside a tenant by subject identifier.
 */
export function findUser(tenant: MockTenant, sub: string): MockUser | undefined {
  return tenant.users.find((user) => user.sub === sub);
}

/**
 * Checks whether the redirect URI is registered for the client.
 */
export function validateRedirectUri(client: MockClient, redirectUri: string): boolean {
  return client.redirectUris.includes(redirectUri);
}

/**
 * Parses a space-delimited OAuth scope string into unique scope names.
 */
export function parseScopes(scope?: string): string[] {
  return [...new Set((scope ?? "openid").split(/\s+/).filter(Boolean))];
}

/**
 * Checks whether every requested scope is allowed for the client.
 */
export function validateScopes(client: MockClient, scopes: string[]): boolean {
  return scopes.every((scope) => client.allowedScopes.includes(scope));
}
