import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
/**
 * Repairs an existing sensitive file to owner-only permissions.
 */
export function ensurePrivateFilePermissions(filePath) {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
        return;
    }
    const currentMode = fs.statSync(resolved).mode & 0o777;
    if (currentMode !== 0o600) {
        fs.chmodSync(resolved, 0o600);
    }
}
/**
 * Atomically writes a sensitive file with owner-only permissions.
 */
export function writePrivateFileAtomically(filePath, contents) {
    const resolved = path.resolve(filePath);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    const temporaryPath = `${resolved}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
    try {
        fs.writeFileSync(temporaryPath, contents, { encoding: "utf8", flag: "wx", mode: 0o600 });
        fs.chmodSync(temporaryPath, 0o600);
        fs.renameSync(temporaryPath, resolved);
        fs.chmodSync(resolved, 0o600);
    }
    catch (error) {
        try {
            fs.unlinkSync(temporaryPath);
        }
        catch {
            // The temporary file may already have been renamed or may not exist.
        }
        throw error;
    }
}
