import { createLocalJWKSet, errors, jwtVerify, SignJWT } from "jose";
import { tenantIssuer } from "../config.js";
/**
 * Creates an Azure-style OIDC ID token for the selected mock user.
 */
export async function createIdToken(input) {
    const now = Math.floor(Date.now() / 1000);
    const issuer = tenantIssuer(input.config, input.tenant.tenantId);
    const claims = {
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
    if (input.deviceId) {
        claims.deviceid = input.deviceId;
    }
    return signJwt(claims, input.keys);
}
/**
 * Creates an Azure-style JWT access token for the selected mock user.
 */
export async function createAccessToken(input) {
    const now = Math.floor(Date.now() / 1000);
    const issuer = tenantIssuer(input.config, input.tenant.tenantId);
    return signJwt({
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
        ...(input.deviceId ? { deviceid: input.deviceId } : {}),
        ...input.user.claims
    }, input.keys);
}
/**
 * Verifies a mock Azure-style access token against this process signing keys and tenant issuer.
 */
export async function verifyAccessToken(input) {
    try {
        const { payload } = await jwtVerify(input.token, createLocalJWKSet(input.keys.jwks), {
            issuer: tenantIssuer(input.config, input.tenant.tenantId),
            ...(input.audience ? { audience: input.audience } : {})
        });
        if (payload.ver !== "2.0") {
            return {
                ok: false,
                error: "invalid_token",
                description: "Token version is not supported"
            };
        }
        if (payload.tid !== input.tenant.tenantId) {
            return {
                ok: false,
                error: "invalid_token",
                description: "Token tenant does not match request tenant"
            };
        }
        if (typeof payload.sub !== "string" || payload.sub.length === 0) {
            return {
                ok: false,
                error: "invalid_token",
                description: "Token subject is missing"
            };
        }
        if (typeof payload.aud !== "string") {
            return {
                ok: false,
                error: "invalid_token",
                description: "Token audience is missing"
            };
        }
        return { ok: true, claims: payload };
    }
    catch (error) {
        return {
            ok: false,
            error: "invalid_token",
            description: describeJwtVerificationError(error)
        };
    }
}
/**
 * Signs the provided claims with the process RSA signing key.
 */
function signJwt(claims, keys) {
    return new SignJWT(claims)
        .setProtectedHeader({ alg: "RS256", kid: keys.kid, typ: "JWT" })
        .sign(keys.privateKey);
}
function describeJwtVerificationError(error) {
    if (error instanceof errors.JWTExpired) {
        return "Token is expired";
    }
    if (error instanceof errors.JWTClaimValidationFailed) {
        return `Token claim validation failed: ${error.claim}`;
    }
    if (error instanceof errors.JWSSignatureVerificationFailed) {
        return "Token signature is invalid";
    }
    if (error instanceof Error && error.message) {
        return error.message;
    }
    return "Token verification failed";
}
