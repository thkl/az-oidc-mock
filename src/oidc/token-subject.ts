import type { JWTPayload } from "jose";
import type { AppConfig, MockClient, MockDevice, MockTenant, MockUser } from "../config.js";
import type { SigningKeys } from "./keys.js";
import { verifyAccessToken } from "./tokens.js";
import { resolveEffectiveUser } from "./users.js";
import { findClient, findDevice } from "./validation.js";

export async function resolveActiveTokenSubject(input: {
  config: AppConfig;
  keys: SigningKeys;
  tenant: MockTenant;
  token: string;
}): Promise<
  | { ok: true; client: MockClient; user: MockUser; device?: MockDevice }
  | { ok: false; error: string; description: string }
> {
  const verification = await verifyAccessToken(input);
  if (!verification.ok) {
    return verification;
  }
  const subject = resolveVerifiedTokenSubject(input.config, input.tenant, verification.claims);
  return subject.ok ? subject : { ok: false, error: "invalid_token", description: subject.description };
}

export function resolveVerifiedTokenSubject(
  config: AppConfig,
  tenant: MockTenant,
  claims: JWTPayload
):
  | { ok: true; client: MockClient; user: MockUser; device?: MockDevice }
  | { ok: false; description: string } {
  const client = findClient(tenant, String(claims.aud));
  const user = resolveEffectiveUser(config, tenant, String(claims.sub))?.user;
  const device = typeof claims.deviceid === "string"
    ? findDevice(tenant, claims.deviceid)
    : undefined;
  if (!client || !client.enabled || !user || isInactiveTokenDevice(tenant, claims.deviceid, device)) {
    return {
      ok: false,
      description: describeInactiveTokenSubject(tenant, client, user, claims.deviceid, device)
    };
  }
  return { ok: true, client, user, ...(device ? { device } : {}) };
}

export function isInactiveRefreshTokenDevice(
  tenant: MockTenant,
  deviceId: string | undefined,
  device: MockDevice | undefined
): boolean {
  if (!deviceId) {
    return tenant.devices.length > 0;
  }
  return !device || !device.enabled;
}

function describeInactiveTokenSubject(
  tenant: MockTenant,
  client: MockClient | undefined,
  user: MockUser | undefined,
  deviceId: unknown,
  device: MockDevice | undefined
): string {
  if (!client) {
    return "Token audience is not a configured client";
  }
  if (!client.enabled) {
    return "Token audience client is disabled";
  }
  if (!user) {
    return "Token subject is not a configured user";
  }
  if (isInactiveTokenDevice(tenant, deviceId, device)) {
    return !device ? "Token device is not a configured device" : "Token device is disabled";
  }
  return "Token is no longer active";
}

function isInactiveTokenDevice(
  tenant: MockTenant,
  deviceId: unknown,
  device: MockDevice | undefined
): boolean {
  if (typeof deviceId !== "string") {
    return tenant.devices.length > 0;
  }
  return !device || !device.enabled;
}
