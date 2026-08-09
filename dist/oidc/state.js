import crypto from "node:crypto";
export class OidcState {
    authorizationCodes = new Map();
    refreshTokens = new Map();
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
    consumeCode(code) {
        const entry = this.authorizationCodes.get(code);
        this.authorizationCodes.delete(code);
        if (!entry || entry.expiresAt < Date.now()) {
            return undefined;
        }
        return entry;
    }
    createRefreshToken(entry) {
        const token = randomToken();
        this.refreshTokens.set(token, { ...entry, token });
        return token;
    }
    getRefreshToken(token) {
        const entry = this.refreshTokens.get(token);
        if (!entry || entry.expiresAt < Date.now()) {
            this.refreshTokens.delete(token);
            return undefined;
        }
        return entry;
    }
    revokeRefreshToken(token) {
        this.refreshTokens.delete(token);
    }
}
export function randomToken() {
    return crypto.randomBytes(32).toString("base64url");
}
