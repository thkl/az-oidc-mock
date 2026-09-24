import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
export class PasskeyStore {
    storePath;
    memory = new Map();
    constructor(storePath) {
        this.storePath = storePath;
    }
    list(tenantId, userSub) {
        return this.readRecords().filter((record) => record.tenantId === tenantId && record.userSub === userSub);
    }
    isEnrolled(tenantId, userSub) {
        return this.list(tenantId, userSub).length > 0;
    }
    add(record) {
        const saved = { ...record, createdAt: new Date().toISOString() };
        const records = this.readRecords().filter((candidate) => candidate.credentialId !== record.credentialId);
        records.push(saved);
        this.writeRecords(records);
        return saved;
    }
    remove(tenantId, userSub) {
        const records = this.readRecords();
        const filtered = records.filter((record) => record.tenantId !== tenantId || record.userSub !== userSub);
        if (filtered.length === records.length)
            return false;
        this.writeRecords(filtered);
        return true;
    }
    verify(input) {
        const records = this.readRecords();
        const index = records.findIndex((record) => record.tenantId === input.tenantId &&
            record.userSub === input.userSub &&
            record.credentialId === input.credentialId);
        const record = index >= 0 ? records[index] : undefined;
        if (!record || !verifyPasskeyAssertion({ ...input, publicKeyCose: record.publicKeyCose })) {
            return false;
        }
        const nextCounter = readCounter(fromBase64Url(input.authenticatorData));
        records[index] = { ...record, counter: Math.max(record.counter, nextCounter), lastUsedAt: new Date().toISOString() };
        this.writeRecords(records);
        return true;
    }
    readRecords() {
        if (!this.storePath) {
            return [...this.memory.values()].flat();
        }
        if (!fs.existsSync(this.storePath)) {
            return [];
        }
        try {
            const parsed = JSON.parse(fs.readFileSync(path.resolve(this.storePath), "utf8"));
            return Array.isArray(parsed) ? parsed.filter(isPasskeyRecord) : [];
        }
        catch {
            return [];
        }
    }
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
        fs.mkdirSync(path.dirname(resolved), { recursive: true });
        const tmpPath = `${resolved}.${process.pid}.tmp`;
        fs.writeFileSync(tmpPath, `${JSON.stringify(records, null, 2)}\n`, "utf8");
        fs.renameSync(tmpPath, resolved);
    }
}
export function createPasskeyChallenge() {
    return crypto.randomBytes(32).toString("base64url");
}
export function verifyPasskeyRegistration(input) {
    const client = parseClientData(input.clientDataJSON);
    if (!client || client.type !== "webauthn.create" || client.challenge !== input.expectedChallenge || client.origin !== input.expectedOrigin) {
        return { ok: false, description: "Passkey registration challenge is invalid" };
    }
    const attestation = decodeCbor(fromBase64Url(input.attestationObject));
    const authData = attestation instanceof Map ? attestation.get("authData") : undefined;
    if (!Buffer.isBuffer(authData)) {
        return { ok: false, description: "Passkey registration response is invalid" };
    }
    if (!verifyRpIdHash(authData, input.rpId) || !hasUserPresent(authData)) {
        return { ok: false, description: "Passkey registration authenticator data is invalid" };
    }
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
function verifyPasskeyAssertion(input) {
    const client = parseClientData(input.clientDataJSON);
    if (!client || client.type !== "webauthn.get" || client.challenge !== input.expectedChallenge || client.origin !== input.expectedOrigin) {
        return false;
    }
    const authData = fromBase64Url(input.authenticatorData);
    if (!verifyRpIdHash(authData, input.rpId) || !hasUserPresent(authData)) {
        return false;
    }
    const signed = Buffer.concat([authData, crypto.createHash("sha256").update(fromBase64Url(input.clientDataJSON)).digest()]);
    const publicKey = cosePublicKeyToKeyObject(fromBase64Url(input.publicKeyCose));
    return publicKey ? crypto.verify("sha256", signed, publicKey, fromBase64Url(input.signature)) : false;
}
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
function verifyRpIdHash(authData, rpId) {
    if (authData.length < 37)
        return false;
    return crypto.timingSafeEqual(authData.subarray(0, 32), crypto.createHash("sha256").update(rpId).digest());
}
function hasUserPresent(authData) {
    return authData.length >= 37 && (authData[32] & 0x01) === 0x01;
}
function readCounter(authData) {
    return authData.length >= 37 ? authData.readUInt32BE(33) : 0;
}
function parseAttestedCredentialData(authData) {
    if (authData.length < 55 || (authData[32] & 0x40) !== 0x40)
        return undefined;
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
function cosePublicKeyToKeyObject(cose) {
    const key = decodeCbor(cose);
    if (!(key instanceof Map))
        return undefined;
    const kty = key.get(1);
    const alg = key.get(3);
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
function decodeCbor(buffer) {
    const decoder = new CborDecoder(buffer);
    return decoder.decode();
}
class CborDecoder {
    buffer;
    offset = 0;
    constructor(buffer) {
        this.buffer = buffer;
    }
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
    readByte() {
        if (this.offset >= this.buffer.length)
            throw new Error("Unexpected CBOR end");
        return this.buffer[this.offset++];
    }
    readBytes(length) {
        const end = this.offset + length;
        if (end > this.buffer.length)
            throw new Error("Unexpected CBOR end");
        const value = this.buffer.subarray(this.offset, end);
        this.offset = end;
        return value;
    }
}
function fromBase64Url(value) {
    return Buffer.from(value, "base64url");
}
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
