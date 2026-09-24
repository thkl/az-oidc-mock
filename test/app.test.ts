import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { loadConfig, watchConfig, type AppConfig } from "../src/config.js";
import type { Logger } from "../src/logger.js";
import { createSigningKeys, type SigningKeys } from "../src/oidc/keys.js";
import { createPasswordHash, PasswordStore } from "../src/oidc/passwords.js";
import { OidcState } from "../src/oidc/state.js";
import { loadTlsOptions } from "../src/tls.js";

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
          allowedScopes: ["openid", "profile", "email", "offline_access"],
          enabled: true
        }
      ],
      devices: [
        {
          deviceId: "machine-1",
          displayName: "Build Agent 1",
          enabled: true
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
          allowedScopes: ["openid", "profile"],
          enabled: true
        }
      ],
      devices: [],
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
    expect(res.body.response_modes_supported).toContain("query");
    expect(res.body.grant_types_supported).toContain("refresh_token");
    expect(res.body.cloud_instance_name).toBe("mock");
  });

  it("serves the Azure v2.0 discovery path that MSAL commonly resolves", async () => {
    const app = createApp({ config, keys, logger: silentLogger });

    const res = await request(app).get("/common/v2.0/.well-known/openid-configuration").expect(200);

    expect(res.body.issuer).toBe("http://127.0.0.1:3000/common/v2.0");
    expect(res.body.token_endpoint).toBe("http://127.0.0.1:3000/common/oauth2/v2.0/token");
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
              allowedScopes: ["openid"],
              enabled: true
            }
          ],
          devices: [],
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
    expect(token.body.refresh_token_expires_in).toBeGreaterThan(0);
    expect(token.body.refresh_token_expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("uses email and password login for secure tenants and reuses the session cookie", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-passwd-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("correct horse battery staple")}\n`, "utf8");
      const app = createApp({
        config: secureConfig(),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath)
      });
      const agent = request.agent(app);

      const loginPage = await agent
        .get("/common/oauth2/v2.0/authorize")
        .query(authorizeQuery())
        .expect(200);
      expect(loginPage.text).not.toContain("Alice Example");
      expect(loginPage.text).toContain('name="username"');
      expect(loginPage.text).toContain('name="password"');

      const failedLogin = await agent
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "wrong" })
        .expect(401);
      expect(failedLogin.text).toContain("Invalid email or password");

      const login = await agent
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "correct horse battery staple" })
        .expect(302);
      expect(login.header["set-cookie"]?.join("\n")).toContain("az_oidc_mock_common=");

      const silentLogin = await agent
        .get("/common/oauth2/v2.0/authorize")
        .query({ ...authorizeQuery(), state: "state-2" })
        .expect(302);
      const callback = new URL(silentLogin.header.location);
      expect(callback.searchParams.get("code")).toBeTruthy();
      expect(callback.searchParams.get("state")).toBe("state-2");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("clears secure login sessions on logout", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-passwd-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("secret")}\n`, "utf8");
      const app = createApp({
        config: secureConfig(),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath)
      });
      const agent = request.agent(app);

      await agent
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "secret" })
        .expect(302);

      await agent.get("/common/oauth2/v2.0/logout").expect(204);

      const loginPage = await agent
        .get("/common/oauth2/v2.0/authorize")
        .query(authorizeQuery())
        .expect(200);
      expect(loginPage.text).toContain('name="password"');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("does not store secure login sessions when tenant sessions are disabled", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-passwd-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("secret")}\n`, "utf8");
      const app = createApp({
        config: secureConfig({ enableSessions: false }),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath)
      });
      const agent = request.agent(app);

      const login = await agent
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "secret" })
        .expect(302);
      expect(login.header["set-cookie"]).toBeUndefined();

      const loginPage = await agent
        .get("/common/oauth2/v2.0/authorize")
        .query(authorizeQuery())
        .expect(200);
      expect(loginPage.text).toContain('name="password"');
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("lets an authorized internal caller set and remove secure tenant passwords", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-passwd-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      const app = createApp({
        config: secureConfig(),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath),
        adminToken: "admin-secret"
      });

      await request(app)
        .post("/common/internal/passwords")
        .send({ username: "alice@example.test", password: "new-secret" })
        .expect(401);

      const update = await request(app)
        .post("/common/internal/passwords")
        .set("authorization", "Bearer admin-secret")
        .send({ username: "alice@example.test", password: "new-secret" })
        .expect(200);
      expect(update.body).toMatchObject({ updated: true, tenant_id: "common", user_sub: "user-1" });

      const contents = await fs.readFile(passwdPath, "utf8");
      expect(contents).toContain("common:user-1:pbkdf2-sha256$");
      expect(contents).not.toContain("new-secret");

      await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "new-secret" })
        .expect(302);

      const deletion = await request(app)
        .delete("/common/internal/passwords")
        .set("x-admin-token", "admin-secret")
        .send({ user_sub: "user-1" })
        .expect(200);
      expect(deletion.body).toMatchObject({ deleted: true, tenant_id: "common", user_sub: "user-1" });

      await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "new-secret" })
        .expect(401);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("verifies an issued access token through the internal endpoint", async () => {
    const app = createApp({ config, keys, logger: silentLogger });
    const token = await issueAccessToken(app);

    const verified = await request(app)
      .post("/common/internal/token/verify")
      .set("authorization", `Bearer ${token}`)
      .send({ audience: "local-app" })
      .expect(200);

    expect(verified.body.active).toBe(true);
    expect(verified.body.tenant_id).toBe("common");
    expect(verified.body.client_id).toBe("local-app");
    expect(verified.body.user_sub).toBe("user-1");
    expect(verified.body.claims.sub).toBe("user-1");
    expect(verified.body.claims.aud).toBe("local-app");
    expect(verified.body.claims.deviceid).toBe("machine-1");
    expect(verified.body.claims.scp).toBe("profile email offline_access");
  });

  it("rejects access token verification for the wrong audience", async () => {
    const app = createApp({ config, keys, logger: silentLogger });
    const token = await issueAccessToken(app);

    const verified = await request(app)
      .post("/common/internal/token/verify")
      .send({ token, audience: "another-service" })
      .expect(401);

    expect(verified.body.active).toBe(false);
    expect(verified.body.error).toBe("invalid_token");
  });

  it("rejects an issued access token after the client is disabled", async () => {
    let currentConfig = config;
    const app = createApp({ config: () => currentConfig, keys, logger: silentLogger });
    const token = await issueAccessToken(app);

    currentConfig = {
      ...config,
      tenants: [
        {
          ...config.tenants[0],
          clients: [
            {
              ...config.tenants[0].clients[0],
              enabled: false
            }
          ]
        },
        config.tenants[1]
      ]
    };

    const verified = await request(app)
      .post("/common/internal/token/verify")
      .send({ token, audience: "local-app" })
      .expect(401);

    expect(verified.body.active).toBe(false);
    expect(verified.body.error).toBe("invalid_token");
    expect(verified.body.error_description).toBe("Token audience client is disabled");
  });

  it("rejects an issued access token after the original login device is disabled", async () => {
    let currentConfig = config;
    const app = createApp({ config: () => currentConfig, keys, logger: silentLogger });
    const token = await issueAccessToken(app);

    currentConfig = disableCommonDevice();

    const verified = await request(app)
      .post("/common/internal/token/verify")
      .send({ token, audience: "local-app" })
      .expect(401);

    expect(verified.body.active).toBe(false);
    expect(verified.body.error).toBe("invalid_token");
    expect(verified.body.error_description).toBe("Token device is disabled");
  });

  it("rejects malformed access tokens through the internal endpoint", async () => {
    const app = createApp({ config, keys, logger: silentLogger });

    const verified = await request(app)
      .post("/common/internal/token/verify")
      .set("authorization", "Bearer not-a-jwt")
      .expect(401);

    expect(verified.body.active).toBe(false);
    expect(verified.body.error).toBe("invalid_token");
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
    expect(refreshed.body.refresh_token_expires_in).toBeGreaterThan(0);
    expect(refreshed.body.refresh_token_expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));

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

  it("persists refresh tokens to a file so renewal survives app restart", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-"));
    const refreshTokenStorePath = path.join(dir, "refresh-tokens.json");

    try {
      const firstApp = createApp({
        config,
        keys,
        logger: silentLogger,
        state: new OidcState(refreshTokenStorePath)
      });
      const first = await issueTokenSet(firstApp);

      await expect(fs.stat(refreshTokenStorePath)).resolves.toBeTruthy();

      const restartedApp = createApp({
        config,
        keys,
        logger: silentLogger,
        state: new OidcState(refreshTokenStorePath)
      });

      const refreshed = await request(restartedApp)
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
      expect(refreshed.body.refresh_token).toBeTruthy();
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects refresh token renewal after the original login device is disabled", async () => {
    let currentConfig = config;
    const app = createApp({ config: () => currentConfig, keys, logger: silentLogger });
    const first = await issueTokenSet(app);

    currentConfig = disableCommonDevice();

    const refreshed = await request(app)
      .post("/common/oauth2/v2.0/token")
      .type("form")
      .send({
        grant_type: "refresh_token",
        client_id: "local-app",
        client_secret: "local-secret",
        refresh_token: first.body.refresh_token
      })
      .expect(400);

    expect(refreshed.body.error).toBe("invalid_grant");
    expect(refreshed.body.error_description).toBe("Device used for original sign-in is inactive");
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

  it("loads TLS config with generated certificate settings", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-"));
    const configPath = path.join(dir, "config.json");

    try {
      await fs.writeFile(
        configPath,
        JSON.stringify({
          ...config,
          baseUrl: "https://localhost:3443",
          tls: {
            autoGenerate: true,
            hosts: ["localhost", "127.0.0.1"],
            days: 30
          }
        }),
        "utf8"
      );

      const loaded = loadConfig(configPath);
      expect(loaded.tls).toEqual({
        autoGenerate: true,
        hosts: ["localhost", "127.0.0.1"],
        days: 30
      });
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects incomplete static TLS config", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-"));
    const configPath = path.join(dir, "config.json");

    try {
      await fs.writeFile(
        configPath,
        JSON.stringify({
          ...config,
          tls: {
            keyPath: "./localhost-key.pem"
          }
        }),
        "utf8"
      );

      expect(() => loadConfig(configPath)).toThrow();
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("generates default TLS files next to the active config file", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-"));
    const configPath = path.join(dir, "config.json");

    try {
      loadTlsOptions({
        autoGenerate: true,
        hosts: ["localhost", "127.0.0.1"],
        days: 1
      }, configPath);

      await expect(fs.stat(path.join(dir, "localhost-key.pem"))).resolves.toBeTruthy();
      await expect(fs.stat(path.join(dir, "localhost-cert.pem"))).resolves.toBeTruthy();
    } finally {
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

async function issueAccessToken(app: ReturnType<typeof createApp>): Promise<string> {
  const token = await issueTokenSet(app);
  return token.body.access_token;
}

async function issueTokenSet(app: ReturnType<typeof createApp>): Promise<request.Response> {
  const login = await request(app)
    .post("/common/login")
    .type("form")
    .send({ ...authorizeQuery(), user_sub: "user-1" })
    .expect(302);
  const code = new URL(login.header.location).searchParams.get("code");

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

  return token;
}

function disableCommonDevice(): AppConfig {
  return {
    ...config,
    tenants: [
      {
        ...config.tenants[0],
        devices: [
          {
            ...config.tenants[0].devices[0],
            enabled: false
          }
        ]
      },
      config.tenants[1]
    ]
  };
}

function secureConfig(overrides: Partial<AppConfig["tenants"][number]> = {}): AppConfig {
  return {
    ...config,
    tenants: [
      {
        ...config.tenants[0],
        secure: true,
        enableSessions: true,
        ...overrides
      },
      config.tenants[1]
    ]
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
