/**
 * Creates the process logger used by the mock server.
 */
export function createLogger() {
    return {
        info: (message, context) => writeLog("info", message, context),
        warn: (message, context) => writeLog("warn", message, context),
        error: (message, context) => writeLog("error", message, context),
        verbose: (config, message, context) => {
            if (config.verbose) {
                writeLog("debug", message, context);
            }
        }
    };
}
/**
 * Writes one structured log line to stdout or stderr.
 */
function writeLog(level, message, context) {
    const entry = JSON.stringify({
        time: new Date().toISOString(),
        level,
        message,
        ...(context ? { context } : {})
    });
    if (level === "error") {
        console.error(entry);
        return;
    }
    if (level === "warn") {
        console.warn(entry);
        return;
    }
    console.log(entry);
}
