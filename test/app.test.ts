import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { loadConfig, watchConfig, type AppConfig } from "../src/config.js";
import type { Logger } from "../src/logger.js";
import { createSigningKeys, type SigningKeys } from "../src/oidc/keys.js";

const config: AppConfig = {
  port: 3000,
  baseUrl: "http://127.0.0.1:3000",
  verbose: false,
  tokenLifetimeSeconds: 3600,
  refreshTokenLifetimeSeconds: 86400,
  rotateRefreshTokens: true,
  tenants: [
    {
      tenantId: "common",
      displayName: "Default Tenant",
      clients: [
        {
          clientId: "local-app",
          clientSecret: "local-secret",
          redirectUris: ["http://app.test/callback"],
          allowedScopes: ["openid", "profile", "email", "offline_access"]
        }
      ],
      users: [
        {
          sub: "user-1",
          name: "Alice Example",
          email: "alice@example.test",
          preferred_username: "alice@example.test",
          roles: ["Admin"],
          claims: {}
        }
      ]
    },
    {
      tenantId: "contoso",
      displayName: "Contoso",
      clients: [
        {
          clientId: "contoso-app",
          redirectUris: ["http://contoso.test/callback"],
          allowedScopes: ["openid", "profile"]
        }
      ],
      users: [
        {
          sub: "contoso-user-1",
          name: "Casey Contoso",
          email: "casey@contoso.test",
          preferred_username: "casey@contoso.test",
          roles: [],
          claims: {}
        }
      ]
    }
  ]
};

let keys: SigningKeys;
const silentLogger: Logger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  verbose: () => undefined
};

beforeEach(async () => {
  keys = await createSigningKeys();
});

describe("Azure OIDC mock", () => {
  it("serves tenant-specific discovery metadata", async () => {
    const app = createApp({ config, keys, logger: silentLogger });

    const res = await request(app).get("/common/.well-known/openid-configuration").expect(200);

    expect(res.body.issuer).toBe("http://127.0.0.1:3000/common/v2.0");
    expect(res.body.authorization_endpoint).toBe("http://127.0.0.1:3000/common/oauth2/v2.0/authorize");
    expect(res.body.jwks_uri).toBe("http://127.0.0.1:3000/common/discovery/v2.0/keys");
  });

  it("uses the latest config provider value for new requests", async () => {
    let currentConfig = config;
    const app = createApp({ config: () => currentConfig, keys, logger: silentLogger });

    await request(app).get("/common/.well-known/openid-configuration").expect(200);

    currentConfig = {
      ...config,
      baseUrl: "http://changed.test",
      tenants: [
        ...config.tenants,
        {
          tenantId: "newtenant",
          displayName: "New Tenant",
          clients: [
            {
              clientId: "new-app",
              redirectUris: ["http://new.test/callback"],
              allowedScopes: ["openid"]
            }
          ],
          users: [
            {
              sub: "new-user",
              name: "New User",
              email: "new@example.test",
              preferred_username: "new@example.test",
              roles: [],
              claims: {}
            }
          ]
        }
      ]
    };

    const res = await request(app).get("/newtenant/.well-known/openid-configuration").expect(200);
    expect(res.body.issuer).toBe("http://changed.test/newtenant/v2.0");
  });

  it("rejects clients from another tenant", async () => {
    const app = createApp({ config, keys, logger: silentLogger });

    await request(app)
      .get("/common/oauth2/v2.0/authorize")
      .query({
        response_type: "code",
        client_id: "contoso-app",
        redirect_uri: "http://contoso.test/callback",
        scope: "openid"
      })
      .expect(302)
      .expect("location", /error=unauthorized_client/);
  });

  it("exchanges an interactive login authorization code for tokens", async () => {
    const app = createApp({ config, keys, logger: silentLogger });

    const loginPage = await request(app)
      .get("/common/oauth2/v2.0/authorize")
      .query(authorizeQuery())
      .expect(200);
    expect(loginPage.text).toContain("Alice Example");

    const login = await request(app)
      .post("/common/login")
      .type("form")
      .send({ ...authorizeQuery(), user_sub: "user-1" })
      .expect(302);

    const callback = new URL(login.header.location);
    const code = callback.searchParams.get("code");
    expect(code).toBeTruthy();
    expect(callback.searchParams.get("state")).toBe("state-1");

    const token = await request(app)
      .post("/common/oauth2/v2.0/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        client_id: "local-app",
        client_secret: "local-secret",
        code,
        redirect_uri: "http://app.test/callback"
      })
      .expect(200);

    expect(token.body.token_type).toBe("Bearer");
    expect(token.body.access_token).toBeTruthy();
    expect(token.body.id_token).toBeTruthy();
    expect(token.body.refresh_token).toBeTruthy();
  });

  it("renews tokens with a refresh token and rotates it", async () => {
    const app = createApp({ config, keys, logger: silentLogger });
    const login = await request(app)
      .post("/common/login")
      .type("form")
      .send({ ...authorizeQuery(), user_sub: "user-1" })
      .expect(302);
    const code = new URL(login.header.location).searchParams.get("code");

    const first = await request(app)
      .post("/common/oauth2/v2.0/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        client_id: "local-app",
        client_secret: "local-secret",
        code,
        redirect_uri: "http://app.test/callback"
      })
      .expect(200);

    const refreshed = await request(app)
      .post("/common/oauth2/v2.0/token")
      .type("form")
      .send({
        grant_type: "refresh_token",
        client_id: "local-app",
        client_secret: "local-secret",
        refresh_token: first.body.refresh_token
      })
      .expect(200);

    expect(refreshed.body.access_token).toBeTruthy();
    expect(refreshed.body.id_token).toBeTruthy();
    expect(refreshed.body.refresh_token).toBeTruthy();
    expect(refreshed.body.refresh_token).not.toBe(first.body.refresh_token);

    await request(app)
      .post("/common/oauth2/v2.0/token")
      .type("form")
      .send({
        grant_type: "refresh_token",
        client_id: "local-app",
        client_secret: "local-secret",
        refresh_token: first.body.refresh_token
      })
      .expect(400);
  });

  it("watches a config file and reloads valid changes", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-"));
    const configPath = path.join(dir, "config.json");
    let currentConfig = config;

    await fs.writeFile(configPath, JSON.stringify(config), "utf8");
    const watcher = watchConfig(
      configPath,
      (nextConfig) => {
        currentConfig = nextConfig;
      },
      () => undefined
    );

    try {
      await sleep(600);
      await fs.writeFile(configPath, JSON.stringify({ ...config, baseUrl: "http://reload.test" }), "utf8");
      await waitFor(() => currentConfig.baseUrl === "http://reload.test");

      await sleep(600);
      await fs.writeFile(configPath, "{ invalid json", "utf8");
      await sleep(700);
      expect(currentConfig.baseUrl).toBe("http://reload.test");
      expect(() => loadConfig(configPath)).toThrow();
    } finally {
      watcher.close();
      await fs.rm(dir, { recursive: true, force: true });
    }
  });
});

function authorizeQuery() {
  return {
    response_type: "code",
    client_id: "local-app",
    redirect_uri: "http://app.test/callback",
    scope: "openid profile email offline_access",
    state: "state-1",
    nonce: "nonce-1"
  };
}

async function waitFor(predicate: () => boolean, timeoutMs = 1500): Promise<void> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (predicate()) {
      return;
    }
    await sleep(25);
  }
  throw new Error("Timed out waiting for predicate");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
