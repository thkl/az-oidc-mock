import crypto from "node:crypto";
import fs from "node:fs";
import type { AuthContext, AuthLevel } from "./auth-level.js";
import { isAuthLevel } from "./auth-level.js";
import { createCodeVerifier } from "./pkce.js";
import { ensurePrivateFilePermissions, writePrivateFileAtomically } from "../private-file.js";

export type AuthorizationRequest = {
  tenantId: string;
  clientId: string;
  redirectUri: string;
  scope: string[];
  state?: string;
  nonce?: string;
  deviceId?: string;
  acr?: string;
  codeChallenge?: string;
};

export type AuthorizationCode = AuthorizationRequest & {
  code: string;
  userSub: string;
  authLevel: AuthLevel;
  authOriginalLevel: AuthLevel;
  expiresAt: number;
};

export type RefreshToken = {
  token: string;
  tenantId: string;
  clientId: string;
  userSub: string;
  authLevel: AuthLevel;
  authOriginalLevel: AuthLevel;
  scope: string[];
  nonce?: string;
  deviceId?: string;
  acr?: string;
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
  private pkceTransactions = new Map<string, { verifier: string; expiresAt: number }>();

  /**
   * Creates state storage and hydrates persisted refresh tokens when configured.
   */
  constructor(private readonly refreshTokenStorePath?: string) {
    this.loadRefreshTokens();
  }

  /**
   * Creates a one-time authorization code for a validated authorization request.
   */
  createCode(request: AuthorizationRequest, userSub: string, auth: AuthContext): string {
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
   * Starts a short-lived PKCE transaction for first-party authorization flows.
   */
  createPkceTransaction(): { state: string; verifier: string } | undefined {
    this.prunePkceTransactions();
    if (this.pkceTransactions.size >= 10_000) {
      return undefined;
    }
    const state = randomToken();
    const verifier = createCodeVerifier();
    this.pkceTransactions.set(state, { verifier, expiresAt: Date.now() + 5 * 60 * 1000 });
    return { state, verifier };
  }

  /**
   * Consumes a first-party PKCE verifier once when its state is returned.
   */
  consumePkceVerifier(state: string): string | undefined {
    const transaction = this.pkceTransactions.get(state);
    this.pkceTransactions.delete(state);
    if (!transaction || transaction.expiresAt < Date.now()) {
      return undefined;
    }
    return transaction.verifier;
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

    ensurePrivateFilePermissions(this.refreshTokenStorePath);
    const raw = fs.readFileSync(this.refreshTokenStorePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<PersistedRefreshTokenStore>;
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

    const payload: PersistedRefreshTokenStore = {
      version: 1,
      refreshTokens: [...this.refreshTokens.values()]
    };
    writePrivateFileAtomically(this.refreshTokenStorePath, JSON.stringify(payload, null, 2));
  }

  private prunePkceTransactions(): void {
    const now = Date.now();
    for (const [state, transaction] of this.pkceTransactions) {
      if (transaction.expiresAt < now) {
        this.pkceTransactions.delete(state);
      }
    }
  }
}

/**
 * Validates and normalizes a parsed refresh-token record before loading it from disk.
 */
function normalizeRefreshToken(value: unknown): RefreshToken | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const token = value as Partial<RefreshToken>;
  if (!(typeof token.token === "string" &&
    typeof token.tenantId === "string" &&
    typeof token.clientId === "string" &&
    typeof token.userSub === "string" &&
    Array.isArray(token.scope) &&
    token.scope.every((scope) => typeof scope === "string") &&
    (token.nonce === undefined || typeof token.nonce === "string") &&
    (token.deviceId === undefined || typeof token.deviceId === "string") &&
    (token.acr === undefined || typeof token.acr === "string") &&
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
    acr: token.acr,
    expiresAt: token.expiresAt
  };
}

/**
 * Creates an opaque URL-safe token value.
 */
export function randomToken(): string {
  return crypto.randomBytes(32).toString("base64url");
}
