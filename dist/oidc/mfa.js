import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
const TOTP_DIGITS = 6;
const TOTP_PERIOD_SECONDS = 30;
const TOTP_WINDOW = 1;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export class MfaStore {
    storePath;
    memory = new Map();
    constructor(storePath) {
        this.storePath = storePath;
    }
    isEnrolled(tenantId, userSub) {
        return Boolean(this.getTotpSecret(tenantId, userSub));
    }
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
    verifyTotp(tenantId, userSub, code, now = Date.now()) {
        const secret = this.getTotpSecret(tenantId, userSub);
        return secret ? verifyTotpCode(secret, code, now) : false;
    }
    getTotpSecret(tenantId, userSub) {
        if (!this.storePath) {
            return this.memory.get(recordKey(tenantId, userSub))?.secret;
        }
        return this.readRecords().find((record) => record.tenantId === tenantId && record.userSub === userSub)?.secret;
    }
    readRecords() {
        if (!this.storePath || !fs.existsSync(this.storePath)) {
            return [];
        }
        try {
            const parsed = JSON.parse(fs.readFileSync(path.resolve(this.storePath), "utf8"));
            return Array.isArray(parsed)
                ? parsed.filter(isMfaRecord)
                : [];
        }
        catch {
            return [];
        }
    }
    writeRecords(records) {
        if (!this.storePath) {
            return;
        }
        const resolved = path.resolve(this.storePath);
        fs.mkdirSync(path.dirname(resolved), { recursive: true });
        const tmpPath = `${resolved}.${process.pid}.tmp`;
        fs.writeFileSync(tmpPath, `${JSON.stringify(records, null, 2)}\n`, "utf8");
        fs.renameSync(tmpPath, resolved);
    }
}
export function createTotpSecret() {
    return base32Encode(crypto.randomBytes(20));
}
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
export function createTotpCode(secret, now = Date.now()) {
    return createTotpCodeForCounter(secret, Math.floor(now / 1000 / TOTP_PERIOD_SECONDS));
}
export function verifyTotpSecret(secret, code, now = Date.now()) {
    return verifyTotpCode(secret, code, now);
}
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
function createTotpCodeForCounter(secret, counter) {
    const key = base32Decode(secret);
    const message = Buffer.alloc(8);
    message.writeBigUInt64BE(BigInt(counter));
    const hmac = crypto.createHmac("sha1", key).update(message).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const value = (((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff)) % 10 ** TOTP_DIGITS;
    return String(value).padStart(TOTP_DIGITS, "0");
}
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
function recordKey(tenantId, userSub) {
    return `${tenantId}:${userSub}`;
}
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
