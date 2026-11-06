import crypto from "node:crypto";
import type { NextFunction, Request, RequestHandler, Response } from "express";

const WINDOW_MS = 5 * 60 * 1000;
const MAX_BUCKETS = 50_000;

type RateLimitPolicy = {
  group: "admin" | "login" | "passkey" | "token" | "rotation";
  tenantId: string;
  principal?: string;
  sourceLimit: number;
  principalLimit: number;
};

type Bucket = {
  startedAt: number;
  count: number;
};

/**
 * Applies bounded per-process limits to authentication and credential-management POSTs.
 */
export function createAuthenticationRateLimitMiddleware(): RequestHandler {
  const limiter = new FixedWindowLimiter();

  return (req: Request, res: Response, next: NextFunction) => {
    const policy = identifyPolicy(req);
    if (!policy) {
      next();
      return;
    }

    const source = req.ip || req.socket.remoteAddress || "unknown";
    const sourceDecision = limiter.consume(`source:${policy.group}:${policy.tenantId}:${source}`, policy.sourceLimit);
    if (!sourceDecision.allowed) {
      respondRateLimited(res, sourceDecision.retryAfterSeconds);
      return;
    }

    if (policy.principal) {
      const principalHash = crypto.createHash("sha256").update(policy.principal).digest("hex");
      const key = `principal:${policy.group}:${policy.tenantId}:${source}:${principalHash}`;
      const principalDecision = limiter.consume(key, policy.principalLimit);
      if (!principalDecision.allowed) {
        respondRateLimited(res, principalDecision.retryAfterSeconds);
        return;
      }
    }

    next();
  };
}

function identifyPolicy(req: Request): RateLimitPolicy | undefined {
  const normalizedPath = (req.path.replace(/\/+$/, "") || "/").toLowerCase();
  if (req.method === "GET" && (normalizedPath === "/internal/admin" || normalizedPath === "/internal/admin/callback")) {
    return {
      group: "admin",
      tenantId: "internal",
      sourceLimit: 300,
      principalLimit: 300
    };
  }

  if (req.method !== "POST" && req.method !== "GET" && req.method !== "DELETE") {
    return undefined;
  }

  if (normalizedPath.startsWith("/internal/admin/api/")) {
    return {
      group: "admin",
      tenantId: "internal",
      sourceLimit: 300,
      principalLimit: 300
    };
  }

  const segments = req.path.split("/").filter(Boolean);
  const routeSegments = segments.map((segment) => segment.toLowerCase());
  const body = asRecord(req.body);
  if (req.method === "POST" && segments.length === 2 && routeSegments[1] === "login") {
    return {
      group: "login",
      tenantId: segments[0],
      principal: readLoginPrincipal(body),
      sourceLimit: 300,
      principalLimit: 10
    };
  }

  if (req.method === "POST" && segments.length >= 3 && routeSegments[1] === "passkeys" && (routeSegments[2] === "authenticate" || routeSegments[2] === "register")) {
    return {
      group: "passkey",
      tenantId: segments[0],
      principal: readPasskeyPrincipal(body),
      sourceLimit: 300,
      principalLimit: 30
    };
  }

  if (req.method === "POST" && segments.length === 4 && routeSegments[1] === "oauth2" && routeSegments[2] === "v2.0" && routeSegments[3] === "token") {
    return {
      group: "token",
      tenantId: segments[0],
      principal: readClientPrincipal(req, body),
      sourceLimit: 600,
      principalLimit: 300
    };
  }

  if (
    (req.method === "GET" || req.method === "POST" || req.method === "DELETE") && segments.length >= 7 &&
    routeSegments[0] === "internal" && routeSegments[1] === "v1" && routeSegments[2] === "tenants" &&
    routeSegments[4] === "clients" && ["rotation-tokens", "check-token", "secrets"].includes(routeSegments[6])
  ) {
    return {
      group: "rotation",
      tenantId: segments[3],
      principal: `client:${segments[5]}`,
      sourceLimit: 300,
      principalLimit: 60
    };
  }

  return undefined;
}

function readLoginPrincipal(body: Record<string, unknown>): string | undefined {
  const challengePrincipal = readChallengePrincipal(body.mfa_challenge) ?? readChallengePrincipal(body.passkey_challenge);
  if (challengePrincipal) return challengePrincipal;

  const username = readString(body.username)?.trim().toLowerCase();
  if (username) return `username:${username}`;

  const subject = readString(body.user_sub);
  return subject ? `subject:${subject}` : undefined;
}

function readPasskeyPrincipal(body: Record<string, unknown>): string | undefined {
  const challengePrincipal = readChallengePrincipal(body.authentication_token) ??
    readChallengePrincipal(body.registration_token) ??
    readChallengePrincipal(body.passkey_challenge);
  if (challengePrincipal) return challengePrincipal;

  const username = readString(body.username)?.trim().toLowerCase();
  return username ? `username:${username}` : undefined;
}

function readClientPrincipal(req: Request, body: Record<string, unknown>): string | undefined {
  const clientId = basicAuthClientId(req) ?? readString(body.client_id);
  return clientId ? `client:${clientId}` : undefined;
}

function readChallengePrincipal(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 8192) {
    return undefined;
  }

  const [, payload] = value.split(".");
  if (!payload) return undefined;
  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, unknown>;
    return typeof parsed.userSub === "string" && parsed.userSub.length > 0 ? `subject:${parsed.userSub}` : undefined;
  } catch {
    return undefined;
  }
}

function basicAuthClientId(req: Request): string | undefined {
  const header = req.header("authorization");
  if (!header?.startsWith("Basic ")) return undefined;
  try {
    const decoded = Buffer.from(header.slice("Basic ".length), "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    return separator > 0 ? decodeURIComponent(decoded.slice(0, separator)) : undefined;
  } catch {
    return undefined;
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function respondRateLimited(res: Response, retryAfterSeconds: number): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Retry-After", String(retryAfterSeconds));
  res.status(429).json({
    error: "too_many_requests",
    error_description: "Too many authentication attempts. Try again later."
  });
}

class FixedWindowLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private checks = 0;

  consume(key: string, maximum: number): { allowed: boolean; retryAfterSeconds: number } {
    const now = Date.now();
    if ((this.checks++ & 0xff) === 0) {
      this.pruneExpired(now);
    }

    let bucket = this.buckets.get(key);
    if (!bucket || now - bucket.startedAt >= WINDOW_MS) {
      if (!bucket && this.buckets.size >= MAX_BUCKETS) {
        this.pruneExpired(now);
        if (this.buckets.size >= MAX_BUCKETS) {
          return { allowed: false, retryAfterSeconds: Math.ceil(WINDOW_MS / 1000) };
        }
      }
      bucket = { startedAt: now, count: 0 };
    }

    bucket.count += 1;
    this.buckets.delete(key);
    this.buckets.set(key, bucket);
    return {
      allowed: bucket.count <= maximum,
      retryAfterSeconds: Math.max(1, Math.ceil((bucket.startedAt + WINDOW_MS - now) / 1000))
    };
  }

  private pruneExpired(now: number): void {
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.startedAt >= WINDOW_MS) {
        this.buckets.delete(key);
      }
    }
  }
}
