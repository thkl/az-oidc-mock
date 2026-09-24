import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
const HASH_ALGORITHM = "sha256";
const HASH_ITERATIONS = 310_000;
const HASH_KEY_LENGTH = 32;
const HASH_PREFIX = "pbkdf2-sha256";
/**
 * Manages the passwd file that stores secure-tenant password hashes.
 */
export class PasswordStore {
    passwdPath;
    /**
     * Creates a password store backed by passwd when a path is provided.
     */
    constructor(passwdPath) {
        this.passwdPath = passwdPath;
    }
    /**
     * Creates or replaces the password hash for one tenant user.
     */
    setPassword(tenantId, userSub, password) {
        if (!this.passwdPath) {
            throw new Error("Password store path is not configured");
        }
        const records = this.readRecords();
        const record = `${tenantId}:${userSub}:${createPasswordHash(password)}`;
        const existingIndex = records.findIndex((line) => isRecordFor(line, tenantId, userSub));
        if (existingIndex >= 0) {
            records[existingIndex] = record;
        }
        else {
            records.push(record);
        }
        this.writeRecords(records);
    }
    /**
     * Removes the password record for one tenant user.
     */
    deletePassword(tenantId, userSub) {
        if (!this.passwdPath) {
            throw new Error("Password store path is not configured");
        }
        const records = this.readRecords();
        const filtered = records.filter((line) => !isRecordFor(line, tenantId, userSub));
        if (filtered.length === records.length) {
            return false;
        }
        this.writeRecords(filtered);
        return true;
    }
    /**
     * Verifies a plaintext password against the stored hash.
     */
    verify(tenantId, userSub, password) {
        if (!this.passwdPath) {
            return false;
        }
        const hash = this.findHash(tenantId, userSub);
        return hash ? verifyPassword(password, hash) : false;
    }
    /**
     * Finds the encoded hash line for a tenant user.
     */
    findHash(tenantId, userSub) {
        if (!this.passwdPath || !fs.existsSync(this.passwdPath)) {
            return undefined;
        }
        const resolved = path.resolve(this.passwdPath);
        const lines = fs.readFileSync(resolved, "utf8").split(/\r?\n/);
        // Comment and blank lines allow operators to annotate the passwd file.
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith("#")) {
                continue;
            }
            const [recordTenantId, recordUserSub, ...hashParts] = trimmed.split(":");
            if (recordTenantId === tenantId && recordUserSub === userSub) {
                return hashParts.join(":");
            }
        }
        return undefined;
    }
    /**
     * Reads non-empty passwd records from disk.
     */
    readRecords() {
        if (!this.passwdPath || !fs.existsSync(this.passwdPath)) {
            return [];
        }
        return fs.readFileSync(path.resolve(this.passwdPath), "utf8")
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean);
    }
    /**
     * Atomically writes the passwd file so readers never see a partial update.
     */
    writeRecords(records) {
        if (!this.passwdPath) {
            throw new Error("Password store path is not configured");
        }
        const resolved = path.resolve(this.passwdPath);
        fs.mkdirSync(path.dirname(resolved), { recursive: true });
        const tmpPath = `${resolved}.${process.pid}.tmp`;
        fs.writeFileSync(tmpPath, records.length > 0 ? `${records.join("\n")}\n` : "", "utf8");
        fs.renameSync(tmpPath, resolved);
    }
}
/**
 * Creates a salted PBKDF2-SHA256 password hash record.
 */
export function createPasswordHash(password) {
    const salt = crypto.randomBytes(16).toString("base64url");
    const hash = crypto.pbkdf2Sync(password, salt, HASH_ITERATIONS, HASH_KEY_LENGTH, HASH_ALGORITHM).toString("base64url");
    return `${HASH_PREFIX}$${HASH_ITERATIONS}$${salt}$${hash}`;
}
/**
 * Verifies a plaintext password against an encoded PBKDF2 hash.
 */
export function verifyPassword(password, encodedHash) {
    const [prefix, iterationsText, salt, expectedHash] = encodedHash.split("$");
    const iterations = Number(iterationsText);
    if (prefix !== HASH_PREFIX || !Number.isInteger(iterations) || iterations <= 0 || !salt || !expectedHash) {
        return false;
    }
    const actual = crypto.pbkdf2Sync(password, salt, iterations, HASH_KEY_LENGTH, HASH_ALGORITHM);
    const expected = Buffer.from(expectedHash, "base64url");
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
/**
 * Checks whether a passwd line belongs to a tenant user.
 */
function isRecordFor(line, tenantId, userSub) {
    if (!line || line.startsWith("#")) {
        return false;
    }
    const [recordTenantId, recordUserSub] = line.split(":");
    return recordTenantId === tenantId && recordUserSub === userSub;
}
