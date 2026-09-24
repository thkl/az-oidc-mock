import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

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

type PersistedRefreshTokenStore = {
  version: 1;
  refreshTokens: RefreshToken[];
};

/**
 * Stores short-lived mock authorization codes and refresh tokens.
 */
export class OidcState {
  private authorizationCodes = new Map<string, AuthorizationCode>();
  private refreshTokens = new Map<string, RefreshToken>();

  /**
   * Creates state storage and hydrates persisted refresh tokens when configured.
   */
  constructor(private readonly refreshTokenStorePath?: string) {
    this.loadRefreshTokens();
  }

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
    this.saveRefreshTokens();
    return token;
  }

  /**
   * Looks up a refresh token and removes it if it has expired.
   */
  getRefreshToken(token: string): RefreshToken | undefined {
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
  revokeRefreshToken(token: string): void {
    this.refreshTokens.delete(token);
    this.saveRefreshTokens();
  }

  /**
   * Loads persisted refresh tokens and drops expired or malformed entries.
   */
  private loadRefreshTokens(): void {
    if (!this.refreshTokenStorePath || !fs.existsSync(this.refreshTokenStorePath)) {
      return;
    }

    const raw = fs.readFileSync(this.refreshTokenStorePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<PersistedRefreshTokenStore>;
    if (parsed.version !== 1 || !Array.isArray(parsed.refreshTokens)) {
      throw new Error(`Unsupported refresh token store format: ${this.refreshTokenStorePath}`);
    }

    // Only valid, non-expired tokens are hydrated into memory.
    const now = Date.now();
    for (const token of parsed.refreshTokens) {
      if (isRefreshToken(token) && token.expiresAt >= now) {
        this.refreshTokens.set(token.token, token);
      }
    }
    this.saveRefreshTokens();
  }

  /**
   * Persists refresh tokens after pruning expired records.
   */
  private saveRefreshTokens(): void {
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
    const payload: PersistedRefreshTokenStore = {
      version: 1,
      refreshTokens: [...this.refreshTokens.values()]
    };
    fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2), "utf8");
    fs.renameSync(tmpPath, this.refreshTokenStorePath);
  }
}

/**
 * Validates a parsed refresh-token record before loading it from disk.
 */
function isRefreshToken(value: unknown): value is RefreshToken {
  if (!value || typeof value !== "object") {
    return false;
  }
  const token = value as Partial<RefreshToken>;
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
export function randomToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}
