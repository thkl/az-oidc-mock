import crypto from "node:crypto";
const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
const S256_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
/**
 * Creates a high-entropy PKCE code verifier.
 */
export function createCodeVerifier() {
    return crypto.randomBytes(32).toString("base64url");
}
/**
 * Computes the RFC 7636 S256 challenge for a syntactically valid verifier.
 */
export function createCodeChallenge(verifier) {
    return crypto.createHash("sha256").update(verifier, "ascii").digest("base64url");
}
/**
 * Checks whether a value is a valid S256 challenge.
 */
export function isS256CodeChallenge(value) {
    return S256_CHALLENGE_PATTERN.test(value);
}
/**
 * Verifies a PKCE verifier without leaking a string-comparison timing signal.
 */
export function verifyCodeVerifier(verifier, challenge) {
    if (!verifier || !challenge || !CODE_VERIFIER_PATTERN.test(verifier) || !isS256CodeChallenge(challenge)) {
        return false;
    }
    const actual = Buffer.from(createCodeChallenge(verifier), "ascii");
    const expected = Buffer.from(challenge, "ascii");
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
