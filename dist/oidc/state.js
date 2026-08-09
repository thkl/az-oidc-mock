import crypto from "node:crypto";
/**
 * Stores short-lived mock authorization codes and refresh tokens in memory.
 */
export class OidcState {
    authorizationCodes = new Map();
    refreshTokens = new Map();
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
        return token;
    }
    /**
     * Looks up a refresh token and removes it if it has expired.
     */
    getRefreshToken(token) {
        const entry = this.refreshTokens.get(token);
        if (!entry || entry.expiresAt < Date.now()) {
            this.refreshTokens.delete(token);
            return undefined;
        }
        return entry;
    }
    /**
     * Removes a refresh token from the in-memory store.
     */
    revokeRefreshToken(token) {
        this.refreshTokens.delete(token);
    }
}
/**
 * Creates an opaque URL-safe token value.
 */
export function randomToken() {
    return crypto.randomBytes(32).toString("base64url");
}
