import { createApp } from "./app.js";
import { loadConfig, watchConfig } from "./config.js";
import { createSigningKeys } from "./oidc/keys.js";
const configPath = process.env.CONFIG_PATH ?? "config.json";
let config = loadConfig(configPath);
const keys = await createSigningKeys();
const app = createApp({ config: () => config, keys });
watchConfig(configPath, (reloaded) => {
    config = reloaded;
});
const port = Number(process.env.PORT ?? config.port);
app.listen(port, () => {
    console.log(`Azure OIDC mock listening on ${config.baseUrl.replace(/\/$/, "")}`);
});
