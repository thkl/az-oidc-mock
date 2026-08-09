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
export function loadConfig(configPath = process.env.CONFIG_PATH ?? "config.json") {
    const resolved = path.resolve(configPath);
    const raw = fs.readFileSync(resolved, "utf8");
    const parsed = appConfigSchema.parse(JSON.parse(raw));
    const tenantIds = new Set();
    for (const tenant of parsed.tenants) {
        if (tenantIds.has(tenant.tenantId)) {
            throw new Error(`Duplicate tenantId in config: ${tenant.tenantId}`);
        }
        tenantIds.add(tenant.tenantId);
        const clientIds = new Set();
        for (const client of tenant.clients) {
            if (clientIds.has(client.clientId)) {
                throw new Error(`Duplicate clientId "${client.clientId}" in tenant "${tenant.tenantId}"`);
            }
            clientIds.add(client.clientId);
        }
    }
    return {
        ...parsed,
        port: readPortOverride(parsed.port),
        baseUrl: readBaseUrlOverride(parsed.baseUrl)
    };
}
export function watchConfig(configPath, onReload) {
    const resolved = path.resolve(configPath);
    let lastMtimeMs = fs.statSync(resolved).mtimeMs;
    fs.watchFile(resolved, { interval: 500 }, (current, previous) => {
        if (previous.mtimeMs === 0) {
            lastMtimeMs = current.mtimeMs;
            return;
        }
        if (current.mtimeMs === previous.mtimeMs || current.mtimeMs <= lastMtimeMs) {
            return;
        }
        lastMtimeMs = current.mtimeMs;
        try {
            onReload(loadConfig(resolved));
            console.log(`Reloaded config from ${resolved}`);
        }
        catch (error) {
            console.error(`Failed to reload config from ${resolved}`);
            console.error(error);
        }
    });
    return {
        close: () => {
            fs.unwatchFile(resolved);
        }
    };
}
export function tenantIssuer(config, tenantId) {
    return `${config.baseUrl.replace(/\/$/, "")}/${tenantId}/v2.0`;
}
function readPortOverride(fallback) {
    if (!process.env.PORT) {
        return fallback;
    }
    const port = Number(process.env.PORT);
    if (!Number.isInteger(port) || port <= 0) {
        throw new Error(`Invalid PORT override: ${process.env.PORT}`);
    }
    return port;
}
function readBaseUrlOverride(fallback) {
    const override = process.env.OIDC_MOCK_BASE_URL ?? process.env.BASE_URL;
    if (!override) {
        return fallback;
    }
    try {
        new URL(override);
        return override;
    }
    catch {
        if (process.env.OIDC_MOCK_BASE_URL) {
            throw new Error(`Invalid OIDC_MOCK_BASE_URL override: ${process.env.OIDC_MOCK_BASE_URL}`);
        }
        return fallback;
    }
}
