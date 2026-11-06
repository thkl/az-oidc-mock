import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ensurePrivateFilePermissions, writePrivateFileAtomically } from "../private-file.js";
const TOTP_DIGITS = 6;
const TOTP_PERIOD_SECONDS = 30;
const TOTP_WINDOW = 1;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/**
 * Stores TOTP enrollment records in memory or in the configured mfa.json file.
 */
export class MfaStore {
    storePath;
    memory = new Map();
    /**
     * Creates an MFA store backed by mfa.json when a path is provided.
     */
    constructor(storePath) {
        this.storePath = storePath;
    }
    /**
     * Checks whether a user has a TOTP secret enrolled.
     */
    isEnrolled(tenantId, userSub) {
        return Boolean(this.getTotpSecret(tenantId, userSub));
    }
    /**
     * Checks candidate tenant keys plus a unique legacy subject-only match.
     */
    isEnrolledForTenants(tenantIds, userSub) {
        return Boolean(this.getTotpSecretForTenants(tenantIds, userSub));
    }
    /**
     * Creates or replaces the TOTP enrollment for a user.
     */
    enrollTotp(tenantId, userSub, secret) {
        const record = {
            tenantId,
            userSub,
            type: "totp",
            secret,
            createdAt: new Date().toISOString()
        };
        if (!this.storePath) {
            this.memory.set(recordKey(tenantId, userSub), record);
            return;
        }
        const records = this.readRecords();
        const existingIndex = records.findIndex((candidate) => candidate.tenantId === tenantId && candidate.userSub === userSub);
        if (existingIndex >= 0) {
            records[existingIndex] = record;
        }
        else {
            records.push(record);
        }
        this.writeRecords(records);
    }
    /**
     * Removes a user's TOTP enrollment.
     */
    remove(tenantId, userSub) {
        if (!this.storePath) {
            return this.memory.delete(recordKey(tenantId, userSub));
        }
        const records = this.readRecords();
        const filtered = records.filter((record) => record.tenantId !== tenantId || record.userSub !== userSub);
        if (filtered.length === records.length) {
            return false;
        }
        this.writeRecords(filtered);
        return true;
    }
    /**
     * Verifies a submitted TOTP code against the stored user secret.
     */
    verifyTotp(tenantId, userSub, code, now = Date.now()) {
        const secret = this.getTotpSecret(tenantId, userSub);
        return secret ? verifyTotpCode(secret, code, now) : false;
    }
    /**
     * Verifies a TOTP code against candidate tenant keys plus a unique legacy subject-only match.
     */
    verifyTotpForTenants(tenantIds, userSub, code, now = Date.now()) {
        const secret = this.getTotpSecretForTenants(tenantIds, userSub);
        return secret ? verifyTotpCode(secret, code, now) : false;
    }
    /**
     * Reads a user's stored TOTP secret from memory or disk.
     */
    getTotpSecret(tenantId, userSub) {
        if (!this.storePath) {
            return this.memory.get(recordKey(tenantId, userSub))?.secret;
        }
        return this.readRecords().find((record) => record.tenantId === tenantId && record.userSub === userSub)?.secret;
    }
    /**
     * Finds a user's TOTP secret by preferred tenant keys, then a unique legacy subject match.
     */
    getTotpSecretForTenants(tenantIds, userSub) {
        const records = this.readRecords();
        const candidates = new Set(tenantIds);
        const exact = records.find((record) => candidates.has(record.tenantId) && record.userSub === userSub);
        if (exact) {
            return exact.secret;
        }
        const subjectMatches = records.filter((record) => record.userSub === userSub);
        return subjectMatches.length === 1 ? subjectMatches[0].secret : undefined;
    }
    /**
     * Reads and validates TOTP enrollment records from disk.
     */
    readRecords() {
        if (!this.storePath) {
            return [...this.memory.values()];
        }
        if (!fs.existsSync(this.storePath)) {
            return [];
        }
        const resolved = path.resolve(this.storePath);
        ensurePrivateFilePermissions(resolved);
        try {
            const parsed = JSON.parse(fs.readFileSync(resolved, "utf8"));
            return Array.isArray(parsed)
                ? parsed.filter(isMfaRecord)
                : [];
        }
        catch {
            return [];
        }
    }
    /**
     * Atomically writes TOTP enrollment records to disk.
     */
    writeRecords(records) {
        if (!this.storePath) {
            return;
        }
        const resolved = path.resolve(this.storePath);
        writePrivateFileAtomically(resolved, `${JSON.stringify(records, null, 2)}\n`);
    }
}
/**
 * Creates a random base32 TOTP secret suitable for authenticator apps.
 */
export function createTotpSecret() {
    return base32Encode(crypto.randomBytes(20));
}
/**
 * Builds an otpauth URI for QR-code or link based TOTP setup.
 */
export function createTotpUri(input) {
    const label = `${input.issuer}:${input.accountName}`;
    const params = new URLSearchParams({
        secret: input.secret,
        issuer: input.issuer,
        algorithm: "SHA1",
        digits: String(TOTP_DIGITS),
        period: String(TOTP_PERIOD_SECONDS),
        tenant: input.tenantId
    });
    return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}
/**
 * Creates the expected six-digit code for the current TOTP time step.
 */
export function createTotpCode(secret, now = Date.now()) {
    return createTotpCodeForCounter(secret, Math.floor(now / 1000 / TOTP_PERIOD_SECONDS));
}
/**
 * Verifies a TOTP code for a raw secret without consulting the store.
 */
export function verifyTotpSecret(secret, code, now = Date.now()) {
    return verifyTotpCode(secret, code, now);
}
/**
 * Checks a submitted code against the current time step and adjacent drift window.
 */
function verifyTotpCode(secret, code, now) {
    const normalized = code.replace(/\s+/g, "");
    if (!/^\d{6}$/.test(normalized)) {
        return false;
    }
    const counter = Math.floor(now / 1000 / TOTP_PERIOD_SECONDS);
    for (let offset = -TOTP_WINDOW; offset <= TOTP_WINDOW; offset += 1) {
        if (createTotpCodeForCounter(secret, counter + offset) === normalized) {
            return true;
        }
    }
    return false;
}
/**
 * Computes the HOTP value used by TOTP for a specific counter.
 */
function createTotpCodeForCounter(secret, counter) {
    const key = base32Decode(secret);
    const message = Buffer.alloc(8);
    message.writeBigUInt64BE(BigInt(counter));
    const hmac = crypto.createHmac("sha1", key).update(message).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    // Dynamic truncation follows RFC 4226 to convert the HMAC into a short code.
    const value = (((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff)) % 10 ** TOTP_DIGITS;
    return String(value).padStart(TOTP_DIGITS, "0");
}
/**
 * Encodes binary random secret material into unpadded base32.
 */
function base32Encode(buffer) {
    let bits = 0;
    let value = 0;
    let output = "";
    for (const byte of buffer) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) {
        output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
    }
    return output;
}
/**
 * Decodes a base32 TOTP secret back into bytes.
 */
function base32Decode(value) {
    let bits = 0;
    let decoded = 0;
    const bytes = [];
    for (const char of value.toUpperCase().replace(/=|\s+/g, "")) {
        const index = BASE32_ALPHABET.indexOf(char);
        if (index < 0) {
            throw new Error("Invalid base32 secret");
        }
        decoded = (decoded << 5) | index;
        bits += 5;
        if (bits >= 8) {
            bytes.push((decoded >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }
    return Buffer.from(bytes);
}
/**
 * Creates the storage key for a user's MFA record.
 */
function recordKey(tenantId, userSub) {
    return `${tenantId}:${userSub}`;
}
/**
 * Validates untyped JSON before accepting it as an MFA record.
 */
function isMfaRecord(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const record = value;
    return record.type === "totp" &&
        typeof record.tenantId === "string" &&
        typeof record.userSub === "string" &&
        typeof record.secret === "string" &&
        typeof record.createdAt === "string";
}
