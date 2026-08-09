import { exportJWK, generateKeyPair } from "jose";
export async function createSigningKeys() {
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
