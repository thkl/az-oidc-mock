import type { AppConfig, MockClient, MockTenant, MockUser } from "../config.js";

export function findTenant(config: AppConfig, tenantId: string): MockTenant | undefined {
  return config.tenants.find((tenant) => tenant.tenantId === tenantId);
}

export function findClient(tenant: MockTenant, clientId: string): MockClient | undefined {
  return tenant.clients.find((client) => client.clientId === clientId);
}

export function findUser(tenant: MockTenant, sub: string): MockUser | undefined {
  return tenant.users.find((user) => user.sub === sub);
}

export function validateRedirectUri(client: MockClient, redirectUri: string): boolean {
  return client.redirectUris.includes(redirectUri);
}

export function parseScopes(scope?: string): string[] {
  return [...new Set((scope ?? "openid").split(/\s+/).filter(Boolean))];
}

export function validateScopes(client: MockClient, scopes: string[]): boolean {
  return scopes.every((scope) => client.allowedScopes.includes(scope));
}

