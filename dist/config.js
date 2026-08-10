import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
const userSchema = z.object({
    sub: z.string().min(1),
    name: z.string().min(1),
    email: z.string().email(),
    preferred_username: z.string().min(1),
    roles: z.array(z.string()).default([]),
    claims: z.record(z.string(), z.unknown()).default({})
});
const deviceSchema = z.object({
    deviceId: z.string().min(1),
    displayName: z.string().min(1),
    enabled: z.boolean().default(true)
});
const clientSchema = z.object({
    clientId: z.string().min(1),
    clientSecret: z.string().optional(),
    redirectUris: z.array(z.string().url()).min(1),
    allowedScopes: z.array(z.string()).default(["openid", "profile", "email"]),
    enabled: z.boolean().default(true)
});
const tenantSchema = z.object({
    tenantId: z.string().min(1),
    displayName: z.string().min(1),
    clients: z.array(clientSchema).min(1),
    users: z.array(userSchema).min(1),
    devices: z.array(deviceSchema).default([]),
    enableSessions: z.boolean().default(true),
});
const tlsSchema = z.object({
    keyPath: z.string().min(1).optional(),
    certPath: z.string().min(1).optional(),
    autoGenerate: z.boolean().default(false),
    hosts: z.array(z.string().min(1)).default(["localhost", "127.0.0.1"]),
    days: z.number().int().positive().default(365)
}).superRefine((tls, ctx) => {
    if (!tls.autoGenerate && (!tls.keyPath || !tls.certPath)) {
        ctx.addIssue({
            code: "custom",
            message: "tls.keyPath and tls.certPath are required unless tls.autoGenerate is true"
        });
    }
    if ((tls.keyPath && !tls.certPath) || (!tls.keyPath && tls.certPath)) {
        ctx.addIssue({
            code: "custom",
            message: "tls.keyPath and tls.certPath must be set together"
        });
    }
});
const appConfigSchema = z.object({
    port: z.number().int().positive().default(3000),
    baseUrl: z.string().url(),
    tls: tlsSchema.optional(),
    verbose: z.boolean().default(false),
    tokenLifetimeSeconds: z.number().int().positive().default(3600),
    refreshTokenLifetimeSeconds: z.number().int().positive().default(86400),
    rotateRefreshTokens: z.boolean().default(true),
    tenants: z.array(tenantSchema).min(1)
});
/**
 * Loads, validates, and normalizes the JSON configuration file.
 */
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
        const deviceIds = new Set();
        for (const device of tenant.devices) {
            if (deviceIds.has(device.deviceId)) {
                throw new Error(`Duplicate deviceId "${device.deviceId}" in tenant "${tenant.tenantId}"`);
            }
            deviceIds.add(device.deviceId);
        }
    }
    return {
        ...parsed,
        port: readPortOverride(parsed.port),
        baseUrl: readBaseUrlOverride(parsed.baseUrl),
        tls: readTlsOverride(parsed.tls),
        verbose: readBooleanOverride("OIDC_MOCK_VERBOSE", parsed.verbose)
    };
}
/**
 * Watches the configuration file and emits only successfully parsed configs.
 */
export function watchConfig(configPath, onReload, onError = console.error) {
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
        }
        catch (error) {
            onError(error);
        }
    });
    return {
        close: () => {
            fs.unwatchFile(resolved);
        }
    };
}
/**
 * Builds the Azure v2.0-style issuer value for a tenant.
 */
export function tenantIssuer(config, tenantId) {
    return `${config.baseUrl.replace(/\/$/, "")}/${tenantId}/v2.0`;
}
/**
 * Reads and validates the optional numeric port override.
 */
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
/**
 * Reads and validates the optional base URL override.
 */
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
/**
 * Reads optional TLS certificate paths used by the startup listener.
 */
function readTlsOverride(fallback) {
    const keyPath = process.env.OIDC_MOCK_TLS_KEY_PATH;
    const certPath = process.env.OIDC_MOCK_TLS_CERT_PATH;
    const autoGenerate = readOptionalBooleanOverride("OIDC_MOCK_TLS_AUTO_GENERATE");
    const hosts = process.env.OIDC_MOCK_TLS_HOSTS;
    if (!keyPath && !certPath && autoGenerate === undefined && !hosts) {
        return fallback;
    }
    if (!fallback && !keyPath && !certPath && autoGenerate === false && !hosts) {
        return undefined;
    }
    const override = {
        ...(fallback ?? {}),
        ...(keyPath ? { keyPath } : {}),
        ...(certPath ? { certPath } : {}),
        ...(autoGenerate !== undefined ? { autoGenerate } : {}),
        ...(hosts ? { hosts: hosts.split(",").map((host) => host.trim()).filter(Boolean) } : {})
    };
    if (!keyPath || !certPath) {
        if (keyPath || certPath) {
            throw new Error("OIDC_MOCK_TLS_KEY_PATH and OIDC_MOCK_TLS_CERT_PATH must be set together");
        }
    }
    return tlsSchema.parse(override);
}
/**
 * Reads a boolean environment override using common truthy and falsy values.
 */
function readBooleanOverride(name, fallback) {
    const value = process.env[name];
    if (!value) {
        return fallback;
    }
    if (["1", "true", "yes", "on"].includes(value.toLowerCase())) {
        return true;
    }
    if (["0", "false", "no", "off"].includes(value.toLowerCase())) {
        return false;
    }
    throw new Error(`Invalid ${name} override: ${value}`);
}
function readOptionalBooleanOverride(name) {
    const value = process.env[name];
    if (!value) {
        return undefined;
    }
    return readBooleanOverride(name, false);
}
