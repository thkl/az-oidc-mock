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
const sharedUserSchema = z.object({
    tenantId: z.string().min(1),
    userSub: z.string().min(1)
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
    users: z.array(userSchema).default([]),
    sharedUsers: z.array(sharedUserSchema).default([]),
    devices: z.array(deviceSchema).default([]),
    secure: z.boolean().default(false),
    enableSessions: z.boolean().default(true),
    sessionLifetimeSeconds: z.number().int().positive().default(8 * 60 * 60),
    twoFactorEnabled: z.boolean().default(false),
    twoFactorMandatory: z.boolean().default(false),
    passkeysEnabled: z.boolean().default(false),
    passkeysMandatory: z.boolean().default(false),
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
 * Validates raw config data and checks cross-record uniqueness constraints.
 */
export function parseConfig(raw) {
    const parsed = appConfigSchema.parse(raw);
    validateConfigUniqueness(parsed);
    return parsed;
}
/**
 * Loads, validates, and normalizes the JSON configuration file.
 */
export function loadConfig(configPath = process.env.CONFIG_PATH ?? "config.json") {
    const resolved = path.resolve(configPath);
    const raw = fs.readFileSync(resolved, "utf8");
    const parsed = parseConfig(JSON.parse(raw));
    return {
        ...parsed,
        port: readPortOverride(parsed.port),
        baseUrl: readBaseUrlOverride(parsed.baseUrl),
        tls: readTlsOverride(parsed.tls),
        verbose: readBooleanOverride("OIDC_MOCK_VERBOSE", parsed.verbose)
    };
}
/**
 * Writes a validated configuration file atomically.
 */
export function saveConfig(configPath, nextConfig) {
    const parsed = parseConfig(normalizeConfigForSave(nextConfig));
    const resolved = path.resolve(configPath);
    const tmpPath = `${resolved}.${process.pid}.tmp`;
    fs.writeFileSync(tmpPath, `${JSON.stringify(parsed, null, 2)}\n`, "utf8");
    fs.renameSync(tmpPath, resolved);
    return parsed;
}
/**
 * Normalizes UI-edited config values before validation and persistence.
 */
function normalizeConfigForSave(config) {
    return {
        ...config,
        tenants: config.tenants.map((tenant) => ({
            ...tenant,
            // Mandatory modes imply the corresponding optional setup capability.
            twoFactorEnabled: tenant.twoFactorEnabled || tenant.twoFactorMandatory,
            passkeysEnabled: tenant.passkeysEnabled || tenant.passkeysMandatory,
            sharedUsers: tenant.sharedUsers ?? [],
            clients: tenant.clients.map((client) => ({
                ...client,
                // The admin UI accepts comma, whitespace, or newline separated scope text.
                allowedScopes: client.allowedScopes.flatMap((scope) => scope.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean))
            }))
        }))
    };
}
/**
 * Watches the configuration file and emits only successfully parsed configs.
 */
export function watchConfig(configPath, onReload, onError = console.error) {
    const resolved = path.resolve(configPath);
    let lastMtimeMs = fs.statSync(resolved).mtimeMs;
    fs.watchFile(resolved, { interval: 500 }, (current, previous) => {
        // Ignore initialization and duplicate watch events from the same file timestamp.
        if (previous.mtimeMs === 0) {
            lastMtimeMs = current.mtimeMs;
            return;
        }
        if (current.mtimeMs === previous.mtimeMs || current.mtimeMs <= lastMtimeMs) {
            return;
        }
        lastMtimeMs = current.mtimeMs;
        try {
            // Only publish a reload after the new file parses and validates successfully.
            onReload(loadConfig(resolved));
        }
        catch (error) {
            onError(error);
        }
    });
    return {
        /**
         * Stops the polling watcher for this config file.
         */
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
    // Environment values layer on top of config-file TLS settings.
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
/**
 * Reads an optional boolean override and leaves it undefined when absent.
 */
function readOptionalBooleanOverride(name) {
    const value = process.env[name];
    if (!value) {
        return undefined;
    }
    return readBooleanOverride(name, false);
}
/**
 * Validates uniqueness and cross-tenant references that schemas cannot express.
 */
function validateConfigUniqueness(config) {
    const tenantIds = new Set();
    for (const tenant of config.tenants) {
        // Tenant, client, and device identifiers are addressable by protocol routes.
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
    // Shared accounts must point at an existing source tenant and user.
    for (const tenant of config.tenants) {
        for (const sharedUser of tenant.sharedUsers ?? []) {
            const homeTenant = config.tenants.find((candidate) => candidate.tenantId === sharedUser.tenantId);
            if (!homeTenant) {
                throw new Error(`Shared user tenant "${sharedUser.tenantId}" referenced by tenant "${tenant.tenantId}" does not exist`);
            }
            if (!homeTenant.users.some((user) => user.sub === sharedUser.userSub)) {
                throw new Error(`Shared user "${sharedUser.userSub}" from tenant "${sharedUser.tenantId}" referenced by tenant "${tenant.tenantId}" does not exist`);
            }
        }
    }
}
