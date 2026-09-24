import type { Request, Response } from "express";
import crypto from "node:crypto";
import type { AppConfig, MockTenant, MockUser } from "../config.js";
import { resolveEffectiveUser } from "./users.js";

export function getSessionUser(req: Request, config: AppConfig, tenant: MockTenant, sessionSecret: string): MockUser | undefined {
  const cookie = parseCookies(req.header("cookie"))[`az_oidc_mock_${tenant.tenantId}`];
  const userSub = cookie ? verifySessionCookie(cookie, tenant.tenantId, sessionSecret) : undefined;
  return userSub ? resolveEffectiveUser(config, tenant, userSub)?.user : undefined;
}

export function setSessionUser(req: Request, res: Response, config: AppConfig, tenant: MockTenant, userSub: string, sessionSecret: string): void {
  const maxAge = tenant.sessionLifetimeSeconds * 1000;
  res.cookie(`az_oidc_mock_${tenant.tenantId}`, createSessionCookie(tenant.tenantId, userSub, Date.now() + maxAge, sessionSecret), {
    httpOnly: true,
    sameSite: "lax",
    secure: isSecureRequest(req, config),
    path: `/${tenant.tenantId}`,
    maxAge
  });
}

export function clearSessionUser(req: Request, res: Response, config: AppConfig, tenantId: string): void {
  res.clearCookie(`az_oidc_mock_${tenantId}`, {
    httpOnly: true,
    sameSite: "lax",
    secure: isSecureRequest(req, config),
    path: `/${tenantId}`
  });
}

export function createDefaultSessionSecret(): string {
  return crypto.randomBytes(32).toString("base64url");
}

export function constantTimeEqual(actualValue: string, expectedValue: string): boolean {
  const actual = Buffer.from(actualValue);
  const expected = Buffer.from(expectedValue);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function parseCookies(header?: string): Record<string, string> {
  if (!header) return {};
  return Object.fromEntries(
    header
      .split(";")
      .map((part) => part.trim().split("="))
      .filter(([key, value]) => key && value)
      .map(([key, value]) => [key, decodeURIComponent(value)])
  );
}

function createSessionCookie(tenantId: string, userSub: string, expiresAt: number, sessionSecret: string): string {
  const payload = base64UrlJson({ tenantId, userSub, expiresAt });
  const signature = signSessionPayload(payload, sessionSecret);
  return `v1.${payload}.${signature}`;
}

function verifySessionCookie(cookie: string, tenantId: string, sessionSecret: string): string | undefined {
  const [version, payload, signature] = cookie.split(".");
  if (version !== "v1" || !payload || !signature) {
    return undefined;
  }

  const expected = signSessionPayload(payload, sessionSecret);
  if (!constantTimeEqual(signature, expected)) {
    return undefined;
  }

  const decoded = parseBase64UrlJson(payload);
  if (
    decoded?.tenantId !== tenantId ||
    typeof decoded.userSub !== "string" ||
    typeof decoded.expiresAt !== "number" ||
    decoded.expiresAt <= Date.now()
  ) {
    return undefined;
  }
  return decoded.userSub;
}

function signSessionPayload(payload: string, sessionSecret: string): string {
  return crypto.createHmac("sha256", sessionSecret).update(payload).digest("base64url");
}

function isSecureRequest(req: Request, config: AppConfig): boolean {
  const forwardedProto = req.header("x-forwarded-proto")?.split(",")[0]?.trim().toLowerCase();
  return req.secure || forwardedProto === "https" || new URL(config.baseUrl).protocol === "https:";
}

function base64UrlJson(value: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function parseBase64UrlJson(value: string): Record<string, unknown> | undefined {
  try {
    const decoded = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    return decoded && typeof decoded === "object" && !Array.isArray(decoded)
      ? decoded as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
}
