import { SignJWT } from "jose";
import type { AppConfig, MockClient, MockTenant, MockUser } from "../config.js";
import { tenantIssuer } from "../config.js";
import type { SigningKeys } from "./keys.js";

export type TokenSetInput = {
  config: AppConfig;
  keys: SigningKeys;
  tenant: MockTenant;
  client: MockClient;
  user: MockUser;
  scope: string[];
  nonce?: string;
};

export async function createIdToken(input: TokenSetInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const issuer = tenantIssuer(input.config, input.tenant.tenantId);
  const claims: Record<string, unknown> = {
    iss: issuer,
    aud: input.client.clientId,
    iat: now,
    nbf: now,
    exp: now + input.config.tokenLifetimeSeconds,
    tid: input.tenant.tenantId,
    oid: input.user.sub,
    sub: input.user.sub,
    name: input.user.name,
    preferred_username: input.user.preferred_username,
    email: input.user.email,
    roles: input.user.roles,
    ...input.user.claims
  };

  if (input.nonce) {
    claims.nonce = input.nonce;
  }

  return signJwt(claims, input.keys);
}

export async function createAccessToken(input: TokenSetInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const issuer = tenantIssuer(input.config, input.tenant.tenantId);
  return signJwt(
    {
      iss: issuer,
      aud: input.client.clientId,
      iat: now,
      nbf: now,
      exp: now + input.config.tokenLifetimeSeconds,
      tid: input.tenant.tenantId,
      oid: input.user.sub,
      sub: input.user.sub,
      name: input.user.name,
      preferred_username: input.user.preferred_username,
      scp: input.scope.filter((scope) => scope !== "openid").join(" "),
      roles: input.user.roles,
      ...input.user.claims
    },
    input.keys
  );
}

function signJwt(claims: Record<string, unknown>, keys: SigningKeys): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "JWT" })
    .sign(keys.privateKey);
}

