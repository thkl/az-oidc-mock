import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
/**
 * Loads configured TLS material, generating a local self-signed certificate when requested.
 */
export function loadTlsOptions(tls, configPath) {
    const paths = resolveTlsPaths(tls, configPath);
    if (tls.autoGenerate) {
        ensureSelfSignedCertificate(tls, paths);
    }
    return {
        key: fs.readFileSync(paths.keyPath),
        cert: fs.readFileSync(paths.certPath)
    };
}
function resolveTlsPaths(tls, configPath) {
    if (tls.keyPath && tls.certPath) {
        return {
            keyPath: tls.keyPath,
            certPath: tls.certPath
        };
    }
    const dir = path.dirname(path.resolve(configPath));
    return {
        keyPath: path.join(dir, "localhost-key.pem"),
        certPath: path.join(dir, "localhost-cert.pem")
    };
}
function ensureSelfSignedCertificate(tls, paths) {
    if (fs.existsSync(paths.keyPath) && fs.existsSync(paths.certPath)) {
        return;
    }
    fs.mkdirSync(path.dirname(paths.keyPath), { recursive: true });
    fs.mkdirSync(path.dirname(paths.certPath), { recursive: true });
    try {
        execFileSync("openssl", [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            paths.keyPath,
            "-out",
            paths.certPath,
            "-days",
            String(tls.days),
            "-subj",
            `/CN=${tls.hosts[0] ?? "localhost"}`,
            "-addext",
            `subjectAltName=${subjectAltName(tls.hosts)}`
        ], { stdio: "ignore" });
    }
    catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(`Failed to auto-generate TLS certificate with openssl: ${detail}`);
    }
}
function subjectAltName(hosts) {
    const names = hosts.length > 0 ? hosts : ["localhost", "127.0.0.1"];
    return names.map((host) => `${isIpAddress(host) ? "IP" : "DNS"}:${host}`).join(",");
}
function isIpAddress(host) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":");
}
