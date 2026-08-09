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

/**
 * Creates an Azure-style OIDC ID token for the selected mock user.
 */
export async function createIdToken(input: TokenSetInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const issuer = tenantIssuer(input.config, input.tenant.tenantId);
  const claims: Record<string, unknown> = {
    iss: issuer,
    aud: input.client.clientId,
    iat: now,
    nbf: now,
    exp: now + input.config.tokenLifetimeSeconds,
    ver: "2.0",
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

/**
 * Creates an Azure-style JWT access token for the selected mock user.
 */
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
      ver: "2.0",
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

/**
 * Signs the provided claims with the process RSA signing key.
 */
function signJwt(claims: Record<string, unknown>, keys: SigningKeys): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "JWT" })
    .sign(keys.privateKey);
}
