import crypto from "node:crypto";

export type AuthorizationRequest = {
  tenantId: string;
  clientId: string;
  redirectUri: string;
  scope: string[];
  state?: string;
  nonce?: string;
  deviceId?: string;
};

export type AuthorizationCode = AuthorizationRequest & {
  code: string;
  userSub: string;
  expiresAt: number;
};

export type RefreshToken = {
  token: string;
  tenantId: string;
  clientId: string;
  userSub: string;
  scope: string[];
  nonce?: string;
  deviceId?: string;
  expiresAt: number;
};

/**
 * Stores short-lived mock authorization codes and refresh tokens in memory.
 */
export class OidcState {
  private authorizationCodes = new Map<string, AuthorizationCode>();
  private refreshTokens = new Map<string, RefreshToken>();

  /**
   * Creates a one-time authorization code for a validated authorization request.
   */
  createCode(request: AuthorizationRequest, userSub: string): string {
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
  consumeCode(code: string): AuthorizationCode | undefined {
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
  createRefreshToken(entry: Omit<RefreshToken, "token">): string {
    const token = randomToken();
    this.refreshTokens.set(token, { ...entry, token });
    return token;
  }

  /**
   * Looks up a refresh token and removes it if it has expired.
   */
  getRefreshToken(token: string): RefreshToken | undefined {
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
  revokeRefreshToken(token: string): void {
    this.refreshTokens.delete(token);
  }
}

/**
 * Creates an opaque URL-safe token value.
 */
export function randomToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}
