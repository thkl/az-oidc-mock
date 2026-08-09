import { exportJWK, generateKeyPair, type JWK, type KeyLike } from "jose";

export type SigningKeys = {
  kid: string;
  privateKey: KeyLike;
  jwks: { keys: JWK[] };
};

/**
 * Generates the RSA signing key pair and public JWKS document for this process.
 */
export async function createSigningKeys(): Promise<SigningKeys> {
  const kid = "mock-key-1";
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = kid;
  publicJwk.use = "sig";
  publicJwk.alg = "RS256";

  return {
    kid,
    privateKey,
    jwks: { keys: [publicJwk] }
  };
}
