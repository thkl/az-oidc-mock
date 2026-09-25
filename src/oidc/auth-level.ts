export const AUTH_LEVELS = ["mock", "password", "mfa", "passkey", "cookie"] as const;

export type AuthLevel = typeof AUTH_LEVELS[number];

export type AuthContext = {
  level: AuthLevel;
  originalLevel: AuthLevel;
};

/**
 * Creates the authentication context stored with authorization codes and refresh tokens.
 */
export function authContext(level: AuthLevel, originalLevel: AuthLevel = level): AuthContext {
  return { level, originalLevel };
}

/**
 * Validates untyped data before accepting it as an authentication level.
 */
export function isAuthLevel(value: unknown): value is AuthLevel {
  return typeof value === "string" && AUTH_LEVELS.includes(value as AuthLevel);
}
