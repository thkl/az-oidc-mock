import { createApp } from "./app.js";
import { loadConfig, watchConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { createSigningKeys } from "./oidc/keys.js";
const configPath = process.env.CONFIG_PATH ?? "config.json";
let config = loadConfig(configPath);
const keys = await createSigningKeys();
const logger = createLogger();
const app = createApp({ config: () => config, keys, logger });
watchConfig(configPath, (reloaded) => {
    config = reloaded;
    logger.info("config reloaded", {
        configPath,
        tenantCount: config.tenants.length,
        verbose: config.verbose
    });
}, (error) => {
    logger.error("config reload failed; keeping last valid config", {
        configPath,
        error: error instanceof Error ? error.message : String(error)
    });
});
const port = Number(process.env.PORT ?? config.port);
app.listen(port, () => {
    logger.info("Azure OIDC mock listening", {
        baseUrl: config.baseUrl.replace(/\/$/, ""),
        port,
        tenantCount: config.tenants.length,
        verbose: config.verbose
    });
});
