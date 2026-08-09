import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createSigningKeys } from "./oidc/keys.js";
const config = loadConfig();
const keys = await createSigningKeys();
const app = createApp({ config, keys });
const port = Number(process.env.PORT ?? config.port);
app.listen(port, () => {
    console.log(`Azure OIDC mock listening on ${config.baseUrl.replace(/\/$/, "")}`);
});
