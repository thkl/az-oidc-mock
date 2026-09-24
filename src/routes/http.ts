import type { Request, Response } from "express";
import type { AppConfig, MockTenant } from "../config.js";
import { findTenant } from "../oidc/validation.js";

/**
 * Resolves the route tenant parameter and sends a shared 404 response on failure.
 */
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

/**
 * Sends an OAuth authorize error either through the redirect URI or as JSON.
 */
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

/**
 * Sends an OAuth token-endpoint JSON error with the requested HTTP status.
 */
export function sendTokenError(res: Response, error: string, description: string, status = 400): void {
  res.status(status).json({ error, error_description: description });
}

/**
 * Reads a bearer token from the Authorization header.
 */
export function readBearerToken(req: Request): string | undefined {
  const header = req.header("authorization");
  if (!header?.startsWith("Bearer ")) {
    return undefined;
  }
  return readString(header.slice("Bearer ".length).trim());
}

/**
 * Narrows Express's untyped body value to an object record.
 */
export function readObjectBody(req: Request): Record<string, unknown> {
  return req.body && typeof req.body === "object" ? req.body as Record<string, unknown> : {};
}

/**
 * Returns non-empty strings while treating all other values as absent.
 */
export function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * Reads an Express route parameter that may have been parsed as an array.
 */
export function readParamString(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }
  return readString(value);
}

/**
 * Preserves non-empty form fields and drops empty strings.
 */
export function emptyToUndefined(value?: string): string | undefined {
  return value && value.length > 0 ? value : undefined;
}

/**
 * Checks whether a string can be parsed as an absolute URL.
 */
function isUrl(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}
