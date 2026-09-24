import type { Request, Response } from "express";
import type { AppConfig, MockTenant } from "../config.js";
import { findTenant } from "../oidc/validation.js";

export function getTenantOr404(config: AppConfig, req: Request, res: Response): MockTenant | undefined {
  const tenantId = readParamString(req.params.tenantId);
  if (!tenantId) {
    res.status(404).json({ error: "tenant_not_found" });
    return undefined;
  }

  const tenant = findTenant(config, tenantId);
  if (!tenant) {
    res.status(404).json({ error: "tenant_not_found" });
  }
  return tenant;
}

export function sendAuthorizeError(
  res: Response,
  redirectUri: unknown,
  state: unknown,
  error: string,
  description?: string
): void {
  if (typeof redirectUri === "string" && isUrl(redirectUri)) {
    const url = new URL(redirectUri);
    url.searchParams.set("error", error);
    if (description) {
      url.searchParams.set("error_description", description);
    }
    if (typeof state === "string" && state) {
      url.searchParams.set("state", state);
    }
    res.redirect(url.toString());
    return;
  }

  res.status(400).json({ error, ...(description ? { error_description: description } : {}) });
}

export function sendTokenError(res: Response, error: string, description: string, status = 400): void {
  res.status(status).json({ error, error_description: description });
}

export function readBearerToken(req: Request): string | undefined {
  const header = req.header("authorization");
  if (!header?.startsWith("Bearer ")) {
    return undefined;
  }
  return readString(header.slice("Bearer ".length).trim());
}

export function readObjectBody(req: Request): Record<string, unknown> {
  return req.body && typeof req.body === "object" ? req.body as Record<string, unknown> : {};
}

export function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function readParamString(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }
  return readString(value);
}

export function emptyToUndefined(value?: string): string | undefined {
  return value && value.length > 0 ? value : undefined;
}

function isUrl(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}
