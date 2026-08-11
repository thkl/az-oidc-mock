import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
/**
 * Stores short-lived mock authorization codes and refresh tokens.
 */
export class OidcState {
    refreshTokenStorePath;
    authorizationCodes = new Map();
    refreshTokens = new Map();
    constructor(refreshTokenStorePath) {
        this.refreshTokenStorePath = refreshTokenStorePath;
        this.loadRefreshTokens();
    }
    /**
     * Creates a one-time authorization code for a validated authorization request.
     */
    createCode(request, userSub) {
        const code = randomToken();
        this.authorizationCodes.set(code, {
            ...request,
            code,
            userSub,
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
    loadRefreshTokens() {
        if (!this.refreshTokenStorePath || !fs.existsSync(this.refreshTokenStorePath)) {
            return;
        }
        const raw = fs.readFileSync(this.refreshTokenStorePath, "utf8");
        const parsed = JSON.parse(raw);
        if (parsed.version !== 1 || !Array.isArray(parsed.refreshTokens)) {
            throw new Error(`Unsupported refresh token store format: ${this.refreshTokenStorePath}`);
        }
        const now = Date.now();
        for (const token of parsed.refreshTokens) {
            if (isRefreshToken(token) && token.expiresAt >= now) {
                this.refreshTokens.set(token.token, token);
            }
        }
        this.saveRefreshTokens();
    }
    saveRefreshTokens() {
        if (!this.refreshTokenStorePath) {
            return;
        }
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
function isRefreshToken(value) {
    if (!value || typeof value !== "object") {
        return false;
    }
    const token = value;
    return typeof token.token === "string" &&
        typeof token.tenantId === "string" &&
        typeof token.clientId === "string" &&
        typeof token.userSub === "string" &&
        Array.isArray(token.scope) &&
        token.scope.every((scope) => typeof scope === "string") &&
        (token.nonce === undefined || typeof token.nonce === "string") &&
        (token.deviceId === undefined || typeof token.deviceId === "string") &&
        typeof token.expiresAt === "number";
}
/**
 * Creates an opaque URL-safe token value.
 */
export function randomToken() {
    return crypto.randomBytes(32).toString("base64url");
}
