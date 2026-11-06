import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ensurePrivateFilePermissions, writePrivateFileAtomically } from "../private-file.js";
/**
 * Stores WebAuthn passkey credentials in memory or in passkeys.json.
 */
export class PasskeyStore {
    storePath;
    memory = new Map();
    /**
     * Creates a passkey store backed by passkeys.json when a path is provided.
     */
    constructor(storePath) {
        this.storePath = storePath;
    }
    /**
     * Lists all stored credentials for a tenant user.
     */
    list(tenantId, userSub) {
        return this.readRecords().filter((record) => record.tenantId === tenantId && record.userSub === userSub);
    }
    /**
     * Checks whether a user has at least one passkey enrolled.
     */
    isEnrolled(tenantId, userSub) {
        return this.list(tenantId, userSub).length > 0;
    }
    /**
     * Adds or replaces a stored passkey credential.
     */
    add(record) {
        const saved = { ...record, createdAt: new Date().toISOString() };
        const records = this.readRecords().filter((candidate) => candidate.credentialId !== record.credentialId);
        records.push(saved);
        this.writeRecords(records);
        return saved;
    }
    /**
     * Removes every stored passkey for a tenant user.
     */
    remove(tenantId, userSub) {
        const records = this.readRecords();
        const filtered = records.filter((record) => record.tenantId !== tenantId || record.userSub !== userSub);
        if (filtered.length === records.length)
            return false;
        this.writeRecords(filtered);
        return true;
    }
    /**
     * Verifies a WebAuthn assertion and updates the credential usage metadata.
     */
    verify(input) {
        const records = this.readRecords();
        // Locate the credential by tenant, user, and browser-provided raw credential ID.
        const index = records.findIndex((record) => record.tenantId === input.tenantId &&
            record.userSub === input.userSub &&
            record.credentialId === input.credentialId);
        const record = index >= 0 ? records[index] : undefined;
        if (!record || !verifyPasskeyAssertion({ ...input, publicKeyCose: record.publicKeyCose })) {
            return false;
        }
        // Counters are preserved for audit/debugging, but authenticators may legitimately report zero.
        const nextCounter = readCounter(fromBase64Url(input.authenticatorData));
        records[index] = { ...record, counter: Math.max(record.counter, nextCounter), lastUsedAt: new Date().toISOString() };
        this.writeRecords(records);
        return true;
    }
    /**
     * Reads and validates stored passkey credentials.
     */
    readRecords() {
        if (!this.storePath) {
            return [...this.memory.values()].flat();
        }
        if (!fs.existsSync(this.storePath)) {
            return [];
        }
        const resolved = path.resolve(this.storePath);
        ensurePrivateFilePermissions(resolved);
        try {
            const parsed = JSON.parse(fs.readFileSync(resolved, "utf8"));
            return Array.isArray(parsed) ? parsed.filter(isPasskeyRecord) : [];
        }
        catch {
            return [];
        }
    }
    /**
     * Writes passkey credentials back to memory or atomically to disk.
     */
    writeRecords(records) {
        if (!this.storePath) {
            this.memory.clear();
            for (const record of records) {
                const key = `${record.tenantId}:${record.userSub}`;
                this.memory.set(key, [...(this.memory.get(key) ?? []), record]);
            }
            return;
        }
        const resolved = path.resolve(this.storePath);
        writePrivateFileAtomically(resolved, `${JSON.stringify(records, null, 2)}\n`);
    }
}
/**
 * Creates a browser challenge for registration or authentication.
 */
export function createPasskeyChallenge() {
    return crypto.randomBytes(32).toString("base64url");
}
/**
 * Validates a WebAuthn registration response and extracts the credential key.
 */
export function verifyPasskeyRegistration(input) {
    // Client data binds the browser response to our signed challenge and origin.
    const client = parseClientData(input.clientDataJSON);
    if (!client || client.type !== "webauthn.create" || client.challenge !== input.expectedChallenge || client.origin !== input.expectedOrigin) {
        return { ok: false, description: "Passkey registration challenge is invalid" };
    }
    // The attestation object contains authenticator data with credential ID and public key.
    const attestation = decodeCbor(fromBase64Url(input.attestationObject));
    const authData = attestation instanceof Map ? attestation.get("authData") : undefined;
    if (!Buffer.isBuffer(authData)) {
        return { ok: false, description: "Passkey registration response is invalid" };
    }
    if (!verifyRpIdHash(authData, input.rpId) || !hasUserPresent(authData)) {
        return { ok: false, description: "Passkey registration authenticator data is invalid" };
    }
    // Store only the stable credential identifier and COSE public key.
    const credential = parseAttestedCredentialData(authData);
    if (!credential) {
        return { ok: false, description: "Passkey credential data is missing" };
    }
    return {
        ok: true,
        credentialId: credential.credentialId.toString("base64url"),
        publicKeyCose: credential.publicKeyCose.toString("base64url"),
        counter: readCounter(authData)
    };
}
/**
 * Verifies a WebAuthn authentication assertion against a stored public key.
 */
function verifyPasskeyAssertion(input) {
    // Authentication client data must match the challenge and origin we issued.
    const client = parseClientData(input.clientDataJSON);
    if (!client || client.type !== "webauthn.get" || client.challenge !== input.expectedChallenge || client.origin !== input.expectedOrigin) {
        return false;
    }
    const authData = fromBase64Url(input.authenticatorData);
    if (!verifyRpIdHash(authData, input.rpId) || !hasUserPresent(authData)) {
        return false;
    }
    // WebAuthn signs authenticatorData || SHA256(clientDataJSON).
    const signed = Buffer.concat([authData, crypto.createHash("sha256").update(fromBase64Url(input.clientDataJSON)).digest()]);
    const publicKey = cosePublicKeyToKeyObject(fromBase64Url(input.publicKeyCose));
    return publicKey ? crypto.verify("sha256", signed, publicKey, fromBase64Url(input.signature)) : false;
}
/**
 * Parses browser clientDataJSON and keeps the fields this mock validates.
 */
function parseClientData(value) {
    try {
        const parsed = JSON.parse(fromBase64Url(value).toString("utf8"));
        return typeof parsed.type === "string" && typeof parsed.challenge === "string" && typeof parsed.origin === "string"
            ? { type: parsed.type, challenge: parsed.challenge, origin: parsed.origin }
            : undefined;
    }
    catch {
        return undefined;
    }
}
/**
 * Checks that authenticator data is scoped to the configured relying-party ID.
 */
function verifyRpIdHash(authData, rpId) {
    if (authData.length < 37)
        return false;
    return crypto.timingSafeEqual(authData.subarray(0, 32), crypto.createHash("sha256").update(rpId).digest());
}
/**
 * Checks the user-present flag in authenticator data.
 */
function hasUserPresent(authData) {
    return authData.length >= 37 && (authData[32] & 0x01) === 0x01;
}
/**
 * Reads the authenticator signature counter from authenticator data.
 */
function readCounter(authData) {
    return authData.length >= 37 ? authData.readUInt32BE(33) : 0;
}
/**
 * Extracts credential ID and COSE public key from attested authenticator data.
 */
function parseAttestedCredentialData(authData) {
    if (authData.length < 55 || (authData[32] & 0x40) !== 0x40)
        return undefined;
    // Layout: rpIdHash(32) + flags(1) + counter(4) + AAGUID(16) + credentialIdLength(2).
    const credentialIdLength = authData.readUInt16BE(53);
    const credentialIdStart = 55;
    const credentialIdEnd = credentialIdStart + credentialIdLength;
    if (authData.length <= credentialIdEnd)
        return undefined;
    return {
        credentialId: authData.subarray(credentialIdStart, credentialIdEnd),
        publicKeyCose: authData.subarray(credentialIdEnd)
    };
}
/**
 * Converts an ES256 or RS256 COSE public key into a Node KeyObject.
 */
function cosePublicKeyToKeyObject(cose) {
    const key = decodeCbor(cose);
    if (!(key instanceof Map))
        return undefined;
    const kty = key.get(1);
    const alg = key.get(3);
    // EC2/P-256 public key used by most platform authenticators.
    if (kty === 2 && alg === -7) {
        const x = key.get(-2);
        const y = key.get(-3);
        if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y))
            return undefined;
        return crypto.createPublicKey({
            key: { kty: "EC", crv: "P-256", x: x.toString("base64url"), y: y.toString("base64url") },
            format: "jwk"
        });
    }
    // RSA public key support for authenticators that produce RS256 credentials.
    if (kty === 3 && alg === -257) {
        const n = key.get(-1);
        const e = key.get(-2);
        if (!Buffer.isBuffer(n) || !Buffer.isBuffer(e))
            return undefined;
        return crypto.createPublicKey({
            key: { kty: "RSA", n: n.toString("base64url"), e: e.toString("base64url") },
            format: "jwk"
        });
    }
    return undefined;
}
/**
 * Decodes the constrained CBOR subset used by WebAuthn structures.
 */
function decodeCbor(buffer) {
    const decoder = new CborDecoder(buffer);
    return decoder.decode();
}
/**
 * Minimal CBOR decoder for maps, arrays, byte strings, text, integers, and booleans.
 */
class CborDecoder {
    buffer;
    offset = 0;
    /**
     * Creates a decoder over one CBOR byte buffer.
     */
    constructor(buffer) {
        this.buffer = buffer;
    }
    /**
     * Decodes the next value from the current byte offset.
     */
    decode() {
        const first = this.readByte();
        const major = first >> 5;
        const length = this.readLength(first & 0x1f);
        if (major === 0)
            return length;
        if (major === 1)
            return -1 - length;
        if (major === 2)
            return this.readBytes(length);
        if (major === 3)
            return this.readBytes(length).toString("utf8");
        if (major === 4)
            return Array.from({ length }, () => this.decode());
        if (major === 5) {
            const map = new Map();
            for (let index = 0; index < length; index += 1) {
                map.set(this.decode(), this.decode());
            }
            return map;
        }
        if (major === 7) {
            if (length === 20)
                return false;
            if (length === 21)
                return true;
            if (length === 22)
                return null;
        }
        throw new Error("Unsupported CBOR value");
    }
    /**
     * Reads a CBOR length value from the additional-information bits.
     */
    readLength(info) {
        if (info < 24)
            return info;
        if (info === 24)
            return this.readByte();
        if (info === 25)
            return this.readBytes(2).readUInt16BE();
        if (info === 26)
            return this.readBytes(4).readUInt32BE();
        throw new Error("Unsupported CBOR length");
    }
    /**
     * Reads one byte and advances the decoder offset.
     */
    readByte() {
        if (this.offset >= this.buffer.length)
            throw new Error("Unexpected CBOR end");
        return this.buffer[this.offset++];
    }
    /**
     * Reads a fixed-size byte slice and advances the decoder offset.
     */
    readBytes(length) {
        const end = this.offset + length;
        if (end > this.buffer.length)
            throw new Error("Unexpected CBOR end");
        const value = this.buffer.subarray(this.offset, end);
        this.offset = end;
        return value;
    }
}
/**
 * Decodes URL-safe base64 input used by browser WebAuthn payloads.
 */
function fromBase64Url(value) {
    return Buffer.from(value, "base64url");
}
/**
 * Validates untyped JSON before accepting it as a passkey record.
 */
function isPasskeyRecord(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        return false;
    const record = value;
    return typeof record.tenantId === "string" &&
        typeof record.userSub === "string" &&
        typeof record.credentialId === "string" &&
        typeof record.publicKeyCose === "string" &&
        typeof record.counter === "number" &&
        typeof record.createdAt === "string";
}
