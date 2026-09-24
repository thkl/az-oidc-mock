import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const TOTP_DIGITS = 6;
const TOTP_PERIOD_SECONDS = 30;
const TOTP_WINDOW = 1;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

type MfaRecord = {
  tenantId: string;
  userSub: string;
  type: "totp";
  secret: string;
  createdAt: string;
};

export class MfaStore {
  private readonly memory = new Map<string, MfaRecord>();

  constructor(private readonly storePath?: string) {}

  isEnrolled(tenantId: string, userSub: string): boolean {
    return Boolean(this.getTotpSecret(tenantId, userSub));
  }

  enrollTotp(tenantId: string, userSub: string, secret: string): void {
    const record: MfaRecord = {
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
    } else {
      records.push(record);
    }
    this.writeRecords(records);
  }

  remove(tenantId: string, userSub: string): boolean {
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

  verifyTotp(tenantId: string, userSub: string, code: string, now = Date.now()): boolean {
    const secret = this.getTotpSecret(tenantId, userSub);
    return secret ? verifyTotpCode(secret, code, now) : false;
  }

  private getTotpSecret(tenantId: string, userSub: string): string | undefined {
    if (!this.storePath) {
      return this.memory.get(recordKey(tenantId, userSub))?.secret;
    }

    return this.readRecords().find((record) => record.tenantId === tenantId && record.userSub === userSub)?.secret;
  }

  private readRecords(): MfaRecord[] {
    if (!this.storePath || !fs.existsSync(this.storePath)) {
      return [];
    }

    try {
      const parsed = JSON.parse(fs.readFileSync(path.resolve(this.storePath), "utf8"));
      return Array.isArray(parsed)
        ? parsed.filter(isMfaRecord)
        : [];
    } catch {
      return [];
    }
  }

  private writeRecords(records: MfaRecord[]): void {
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

export function createTotpSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

export function createTotpUri(input: {
  issuer: string;
  tenantId: string;
  accountName: string;
  secret: string;
}): string {
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

export function createTotpCode(secret: string, now = Date.now()): string {
  return createTotpCodeForCounter(secret, Math.floor(now / 1000 / TOTP_PERIOD_SECONDS));
}

export function verifyTotpSecret(secret: string, code: string, now = Date.now()): boolean {
  return verifyTotpCode(secret, code, now);
}

function verifyTotpCode(secret: string, code: string, now: number): boolean {
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

function createTotpCodeForCounter(secret: string, counter: number): string {
  const key = base32Decode(secret);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(message).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const value = (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  ) % 10 ** TOTP_DIGITS;
  return String(value).padStart(TOTP_DIGITS, "0");
}

function base32Encode(buffer: Buffer): string {
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

function base32Decode(value: string): Buffer {
  let bits = 0;
  let decoded = 0;
  const bytes: number[] = [];
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

function recordKey(tenantId: string, userSub: string): string {
  return `${tenantId}:${userSub}`;
}

function isMfaRecord(value: unknown): value is MfaRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return record.type === "totp" &&
    typeof record.tenantId === "string" &&
    typeof record.userSub === "string" &&
    typeof record.secret === "string" &&
    typeof record.createdAt === "string";
}
