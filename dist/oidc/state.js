import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { isAuthLevel } from "./auth-level.js";
/**
 * Stores short-lived mock authorization codes and refresh tokens.
 */
export class OidcState {
    refreshTokenStorePath;
    authorizationCodes = new Map();
    refreshTokens = new Map();
    /**
     * Creates state storage and hydrates persisted refresh tokens when configured.
     */
    constructor(refreshTokenStorePath) {
        this.refreshTokenStorePath = refreshTokenStorePath;
        this.loadRefreshTokens();
    }
    /**
     * Creates a one-time authorization code for a validated authorization request.
     */
    createCode(request, userSub, auth) {
        const code = randomToken();
        this.authorizationCodes.set(code, {
            ...request,
            code,
            userSub,
            authLevel: auth.level,
            authOriginalLevel: auth.originalLevel,
            expiresAt: Date.now() + 5 * 60 * 1000
        });
        return code;
    }
    /**
     * Consumes and removes an authorization code if it exists and is not expired.
     */
    consumeCode(code) {
        const entry = this.authorizationCodes.get(code);
        this.authorizationCodes.delete(code);
        if (!entry || entry.expiresAt < Date.now()) {
            return undefined;
        }
        return entry;
    }
    /**
     * Creates a refresh token bound to a tenant, client, user, and scope set.
     */
    createRefreshToken(entry) {
        const token = randomToken();
        this.refreshTokens.set(token, { ...entry, token });
        this.saveRefreshTokens();
        return token;
    }
    /**
     * Looks up a refresh token and removes it if it has expired.
     */
    getRefreshToken(token) {
        const entry = this.refreshTokens.get(token);
        if (!entry || entry.expiresAt < Date.now()) {
            this.refreshTokens.delete(token);
            this.saveRefreshTokens();
            return undefined;
        }
        return entry;
    }
    /**
     * Removes a refresh token from the in-memory store.
     */
    revokeRefreshToken(token) {
        this.refreshTokens.delete(token);
        this.saveRefreshTokens();
    }
    /**
     * Loads persisted refresh tokens and drops expired or malformed entries.
     */
    loadRefreshTokens() {
        if (!this.refreshTokenStorePath || !fs.existsSync(this.refreshTokenStorePath)) {
            return;
        }
        const raw = fs.readFileSync(this.refreshTokenStorePath, "utf8");
        const parsed = JSON.parse(raw);
        if (parsed.version !== 1 || !Array.isArray(parsed.refreshTokens)) {
            throw new Error(`Unsupported refresh token store format: ${this.refreshTokenStorePath}`);
        }
        // Only valid, non-expired tokens are hydrated into memory.
        const now = Date.now();
        for (const token of parsed.refreshTokens) {
            const normalized = normalizeRefreshToken(token);
            if (normalized && normalized.expiresAt >= now) {
                this.refreshTokens.set(normalized.token, normalized);
            }
        }
        this.saveRefreshTokens();
    }
    /**
     * Persists refresh tokens after pruning expired records.
     */
    saveRefreshTokens() {
        if (!this.refreshTokenStorePath) {
            return;
        }
        // Keep the on-disk file compact and prevent expired tokens from coming back after restart.
        const now = Date.now();
        for (const [token, entry] of this.refreshTokens) {
            if (entry.expiresAt < now) {
                this.refreshTokens.delete(token);
            }
        }
        const dir = path.dirname(this.refreshTokenStorePath);
        fs.mkdirSync(dir, { recursive: true });
        const tmpPath = `${this.refreshTokenStorePath}.${process.pid}.tmp`;
        const payload = {
            version: 1,
            refreshTokens: [...this.refreshTokens.values()]
        };
        fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2), "utf8");
        fs.renameSync(tmpPath, this.refreshTokenStorePath);
    }
}
/**
 * Validates and normalizes a parsed refresh-token record before loading it from disk.
 */
function normalizeRefreshToken(value) {
    if (!value || typeof value !== "object") {
        return undefined;
    }
    const token = value;
    if (!(typeof token.token === "string" &&
        typeof token.tenantId === "string" &&
        typeof token.clientId === "string" &&
        typeof token.userSub === "string" &&
        Array.isArray(token.scope) &&
        token.scope.every((scope) => typeof scope === "string") &&
        (token.nonce === undefined || typeof token.nonce === "string") &&
        (token.deviceId === undefined || typeof token.deviceId === "string") &&
        (token.authLevel === undefined || isAuthLevel(token.authLevel)) &&
        (token.authOriginalLevel === undefined || isAuthLevel(token.authOriginalLevel)) &&
        typeof token.expiresAt === "number")) {
        return undefined;
    }
    return {
        token: token.token,
        tenantId: token.tenantId,
        clientId: token.clientId,
        userSub: token.userSub,
        authLevel: token.authLevel ?? "cookie",
        authOriginalLevel: token.authOriginalLevel ?? token.authLevel ?? "cookie",
        scope: token.scope,
        nonce: token.nonce,
        deviceId: token.deviceId,
        expiresAt: token.expiresAt
    };
}
/**
 * Creates an opaque URL-safe token value.
 */
export function randomToken() {
    return crypto.randomBytes(32).toString("base64url");
}
