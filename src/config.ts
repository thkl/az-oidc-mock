import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

const userSchema = z.object({
  sub: z.string().min(1),
  name: z.string().min(1),
  email: z.string().email(),
  preferred_username: z.string().min(1),
  roles: z.array(z.string()).default([]),
  claims: z.record(z.unknown()).default({})
});

const clientSchema = z.object({
  clientId: z.string().min(1),
  clientSecret: z.string().optional(),
  redirectUris: z.array(z.string().url()).min(1),
  allowedScopes: z.array(z.string()).default(["openid", "profile", "email"])
});

const tenantSchema = z.object({
  tenantId: z.string().min(1),
  displayName: z.string().min(1),
  clients: z.array(clientSchema).min(1),
  users: z.array(userSchema).min(1)
});

const appConfigSchema = z.object({
  port: z.number().int().positive().default(3000),
  baseUrl: z.string().url(),
  tokenLifetimeSeconds: z.number().int().positive().default(3600),
  refreshTokenLifetimeSeconds: z.number().int().positive().default(86400),
  rotateRefreshTokens: z.boolean().default(true),
  tenants: z.array(tenantSchema).min(1)
});

export type MockUser = z.infer<typeof userSchema>;
export type MockClient = z.infer<typeof clientSchema>;
export type MockTenant = z.infer<typeof tenantSchema>;
export type AppConfig = z.infer<typeof appConfigSchema>;

export function loadConfig(configPath = process.env.CONFIG_PATH ?? "config.json"): AppConfig {
  const resolved = path.resolve(configPath);
  const raw = fs.readFileSync(resolved, "utf8");
  const parsed = appConfigSchema.parse(JSON.parse(raw));

  const tenantIds = new Set<string>();
  for (const tenant of parsed.tenants) {
    if (tenantIds.has(tenant.tenantId)) {
      throw new Error(`Duplicate tenantId in config: ${tenant.tenantId}`);
    }
    tenantIds.add(tenant.tenantId);

    const clientIds = new Set<string>();
    for (const client of tenant.clients) {
      if (clientIds.has(client.clientId)) {
        throw new Error(`Duplicate clientId "${client.clientId}" in tenant "${tenant.tenantId}"`);
      }
      clientIds.add(client.clientId);
    }
  }

  return {
    ...parsed,
    port: process.env.PORT ? Number(process.env.PORT) : parsed.port,
    baseUrl: process.env.BASE_URL ?? parsed.baseUrl
  };
}

export function tenantIssuer(config: AppConfig, tenantId: string): string {
  return `${config.baseUrl.replace(/\/$/, "")}/${tenantId}/v2.0`;
}
