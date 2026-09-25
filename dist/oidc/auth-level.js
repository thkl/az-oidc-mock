export const AUTH_LEVELS = ["mock", "password", "mfa", "passkey", "cookie"];
/**
 * Creates the authentication context stored with authorization codes and refresh tokens.
 */
export function authContext(level, originalLevel = level) {
    return { level, originalLevel };
}
/**
 * Validates untyped data before accepting it as an authentication level.
 */
export function isAuthLevel(value) {
    return typeof value === "string" && AUTH_LEVELS.includes(value);
}
