import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
const HASH_ALGORITHM = "sha256";
const HASH_ITERATIONS = 310_000;
const HASH_KEY_LENGTH = 32;
const HASH_PREFIX = "pbkdf2-sha256";
export class PasswordStore {
    passwdPath;
    constructor(passwdPath) {
        this.passwdPath = passwdPath;
    }
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
    verify(tenantId, userSub, password) {
        if (!this.passwdPath) {
            return false;
        }
        const hash = this.findHash(tenantId, userSub);
        return hash ? verifyPassword(password, hash) : false;
    }
    findHash(tenantId, userSub) {
        if (!this.passwdPath || !fs.existsSync(this.passwdPath)) {
            return undefined;
        }
        const resolved = path.resolve(this.passwdPath);
        const lines = fs.readFileSync(resolved, "utf8").split(/\r?\n/);
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
    readRecords() {
        if (!this.passwdPath || !fs.existsSync(this.passwdPath)) {
            return [];
        }
        return fs.readFileSync(path.resolve(this.passwdPath), "utf8")
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean);
    }
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
export function createPasswordHash(password) {
    const salt = crypto.randomBytes(16).toString("base64url");
    const hash = crypto.pbkdf2Sync(password, salt, HASH_ITERATIONS, HASH_KEY_LENGTH, HASH_ALGORITHM).toString("base64url");
    return `${HASH_PREFIX}$${HASH_ITERATIONS}$${salt}$${hash}`;
}
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
function isRecordFor(line, tenantId, userSub) {
    if (!line || line.startsWith("#")) {
        return false;
    }
    const [recordTenantId, recordUserSub] = line.split(":");
    return recordTenantId === tenantId && recordUserSub === userSub;
}
