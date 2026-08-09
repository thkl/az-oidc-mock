import crypto from "node:crypto";

export type AuthorizationRequest = {
  tenantId: string;
  clientId: string;
  redirectUri: string;
  scope: string[];
  state?: string;
  nonce?: string;
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
  expiresAt: number;
};

export class OidcState {
  private authorizationCodes = new Map<string, AuthorizationCode>();
  private refreshTokens = new Map<string, RefreshToken>();

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

  consumeCode(code: string): AuthorizationCode | undefined {
    const entry = this.authorizationCodes.get(code);
    this.authorizationCodes.delete(code);
    if (!entry || entry.expiresAt < Date.now()) {
      return undefined;
    }
    return entry;
  }

  createRefreshToken(entry: Omit<RefreshToken, "token">): string {
    const token = randomToken();
    this.refreshTokens.set(token, { ...entry, token });
    return token;
  }

  getRefreshToken(token: string): RefreshToken | undefined {
    const entry = this.refreshTokens.get(token);
    if (!entry || entry.expiresAt < Date.now()) {
      this.refreshTokens.delete(token);
      return undefined;
    }
    return entry;
  }

  revokeRefreshToken(token: string): void {
    this.refreshTokens.delete(token);
  }
}

export function randomToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}

