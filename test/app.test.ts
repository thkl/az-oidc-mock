import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { decodeJwt } from "jose";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { loadConfig, parseConfig, watchConfig, type AppConfig } from "../src/config.js";
import type { Logger } from "../src/logger.js";
import { createSigningKeys, type SigningKeys } from "../src/oidc/keys.js";
import { createTotpCode, MfaStore } from "../src/oidc/mfa.js";
import { PasskeyStore } from "../src/oidc/passkeys.js";
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
      sharedUsers: [],
      secure: false,
      enableSessions: true,
      sessionLifetimeSeconds: 8 * 60 * 60,
      twoFactorEnabled: false,
      twoFactorMandatory: false,
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
      sharedUsers: [],
      secure: false,
      enableSessions: true,
      sessionLifetimeSeconds: 8 * 60 * 60,
      twoFactorEnabled: false,
      twoFactorMandatory: false,
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
    expect(res.body.userinfo_endpoint).toBe("http://127.0.0.1:3000/common/oidc/userinfo");
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
          secure: false,
          enableSessions: true,
          sessionLifetimeSeconds: 8 * 60 * 60,
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

  it("shows admin setup instructions until the internal tenant is configured", async () => {
    const app = createApp({ config, keys, logger: silentLogger });

    const res = await request(app).get("/internal/admin").expect(503);

    expect(res.text).toContain("Admin UI is not configured");
    expect(res.text).toContain("&quot;tenantId&quot;: &quot;internal&quot;");
    expect(res.text).toContain("&quot;clientId&quot;: &quot;internal-admin&quot;");
  });

  it("requires internal tenant login before showing the admin UI", async () => {
    const app = createApp({ config: adminConfig(), keys, logger: silentLogger });

    const res = await request(app).get("/internal/admin").expect(302);
    const redirect = new URL(res.header.location);

    expect(redirect.pathname).toBe("/internal/oauth2/v2.0/authorize");
    expect(redirect.searchParams.get("client_id")).toBe("internal-admin");
    expect(redirect.searchParams.get("redirect_uri")).toBe("http://127.0.0.1:3000/internal/admin/callback");
  });

  it("serves the self-contained admin UI after internal tenant login", async () => {
    const app = createApp({ config: adminConfig(), keys, logger: silentLogger });
    const agent = request.agent(app);

    const login = await agent
      .post("/internal/login")
      .type("form")
      .send({
        response_type: "code",
        client_id: "internal-admin",
        redirect_uri: "http://127.0.0.1:3000/internal/admin/callback",
        scope: "openid profile email",
        state: "admin",
        user_sub: "admin-1"
      })
      .expect(302);

    await agent.get(new URL(login.header.location).pathname + new URL(login.header.location).search).expect(302);

    const page = await agent.get("/internal/admin").expect(200);
    expect(page.text).not.toContain("https://unpkg.com");
    expect(page.text).toContain("OIDC Admin");
    expect(page.text).toContain("Generate");
    expect(page.text).toContain("Sign out");
    expect(page.text).toContain("az_mock-sk_");

    const api = await agent.get("/internal/admin/api/config").expect(200);
    expect(api.body.user.sub).toBe("admin-1");
    expect(api.body.csrfToken).toEqual(expect.any(String));
    expect(api.body.config.tenants.some((tenant: { tenantId: string }) => tenant.tenantId === "internal")).toBe(true);
    expect(JSON.stringify(api.body.config)).not.toContain("local-secret");
    expect(api.body.config.tenants[0].clients[0].clientSecret).toBe("********");
  });

  it("allows a shared internal admin user with the internal_admin claim", async () => {
    const app = createApp({ config: sharedInternalAdminConfig({ claim: true }), keys, logger: silentLogger });
    const agent = request.agent(app);

    const login = await agent
      .post("/internal/login")
      .type("form")
      .send({
        response_type: "code",
        client_id: "internal-admin",
        redirect_uri: "http://127.0.0.1:3000/internal/admin/callback",
        scope: "openid profile email",
        state: "admin",
        user_sub: "user-1"
      })
      .expect(302);

    await agent.get(new URL(login.header.location).pathname + new URL(login.header.location).search).expect(302);
    const api = await agent.get("/internal/admin/api/config").expect(200);
    expect(api.body.user.sub).toBe("user-1");
  });

  it("allows a shared internal admin user with the internal-admin role", async () => {
    const app = createApp({ config: sharedInternalAdminConfig({ role: true }), keys, logger: silentLogger });
    const agent = request.agent(app);

    const login = await agent
      .post("/internal/login")
      .type("form")
      .send({
        response_type: "code",
        client_id: "internal-admin",
        redirect_uri: "http://127.0.0.1:3000/internal/admin/callback",
        scope: "openid profile email",
        state: "admin",
        user_sub: "user-1"
      })
      .expect(302);

    await agent.get(new URL(login.header.location).pathname + new URL(login.header.location).search).expect(302);
    await agent.get("/internal/admin").expect(200);
  });

  it("rejects shared internal admin users without the admin role or claim", async () => {
    const app = createApp({ config: sharedInternalAdminConfig(), keys, logger: silentLogger });

    const login = await request(app)
      .post("/internal/login")
      .type("form")
      .send({
        response_type: "code",
        client_id: "internal-admin",
        redirect_uri: "http://127.0.0.1:3000/internal/admin/callback",
        scope: "openid profile email",
        state: "admin",
        user_sub: "user-1"
      })
      .expect(302);

    const callback = await request(app)
      .get(new URL(login.header.location).pathname + new URL(login.header.location).search)
      .expect(403);
    expect(callback.text).toContain("internal_admin");
  });

  it("saves admin UI config changes to the configured config file", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-admin-"));
    try {
      const configPath = path.join(dir, "config.json");
      await fs.writeFile(configPath, `${JSON.stringify(adminConfig(), null, 2)}\n`, "utf8");

      let currentConfig = adminConfig();
      const app = createApp({
        config: () => currentConfig,
        keys,
        logger: silentLogger,
        configPath,
        onConfigSaved: (saved) => {
          currentConfig = saved;
        }
      });
      const agent = request.agent(app);

      const login = await agent
        .post("/internal/login")
        .type("form")
        .send({
          response_type: "code",
          client_id: "internal-admin",
          redirect_uri: "http://127.0.0.1:3000/internal/admin/callback",
          scope: "openid profile email",
          state: "admin",
          user_sub: "admin-1"
        })
        .expect(302);
      await agent.get(new URL(login.header.location).pathname + new URL(login.header.location).search).expect(302);
      const csrfToken = await adminCsrfToken(agent);

      const nextConfig = {
        ...currentConfig,
        tenants: currentConfig.tenants.map((tenant) =>
          tenant.tenantId === "common" ? { ...tenant, displayName: "Updated Tenant" } : tenant
        )
      };
      await agent.put("/internal/admin/api/config").set("x-csrf-token", csrfToken).send({ config: nextConfig }).expect(200);

      expect(currentConfig.tenants.find((tenant) => tenant.tenantId === "common")?.displayName).toBe("Updated Tenant");
      const saved = JSON.parse(await fs.readFile(configPath, "utf8")) as AppConfig;
      expect(saved.tenants.find((tenant) => tenant.tenantId === "common")?.displayName).toBe("Updated Tenant");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("preserves masked client secrets when admin config is saved", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-admin-"));
    try {
      const configPath = path.join(dir, "config.json");
      await fs.writeFile(configPath, `${JSON.stringify(adminConfig(), null, 2)}\n`, "utf8");

      let currentConfig = adminConfig();
      const app = createApp({
        config: () => currentConfig,
        keys,
        logger: silentLogger,
        configPath,
        onConfigSaved: (saved) => {
          currentConfig = saved;
        }
      });
      const agent = request.agent(app);

      await loginInternalAdmin(agent);
      const masked = await agent.get("/internal/admin/api/config").expect(200);
      await agent.put("/internal/admin/api/config").set("x-csrf-token", masked.body.csrfToken).send({ config: masked.body.config }).expect(200);

      const saved = JSON.parse(await fs.readFile(configPath, "utf8")) as AppConfig;
      expect(saved.tenants[0].clients[0].clientSecret).toBe("local-secret");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("sets user passwords through the admin UI API without returning or storing plaintext", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-admin-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      const passwordStore = new PasswordStore(passwdPath);
      const app = createApp({
        config: adminConfig(),
        keys,
        logger: silentLogger,
        passwordStore
      });
      const agent = request.agent(app);

      await loginInternalAdmin(agent);
      const csrfToken = await adminCsrfToken(agent);
      const update = await agent
        .post("/internal/admin/api/passwords")
        .set("x-csrf-token", csrfToken)
        .send({ tenant_id: "common", user_sub: "user-1", password: "new-admin-password" })
        .expect(200);

      expect(update.body).toEqual({ updated: true, tenant_id: "common", user_sub: "user-1" });
      expect(update.text).not.toContain("new-admin-password");
      expect(passwordStore.verify("common", "user-1", "new-admin-password")).toBe(true);
      expect(await fs.readFile(passwdPath, "utf8")).not.toContain("new-admin-password");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("resets user passkeys through the admin UI API", async () => {
    const passkeyStore = new PasskeyStore();
    passkeyStore.add({
      tenantId: "common",
      userSub: "user-1",
      credentialId: "credential-1",
      publicKeyCose: "dummy",
      counter: 0
    });
    const app = createApp({
      config: adminConfig(),
      keys,
      logger: silentLogger,
      passkeyStore
    });
    const agent = request.agent(app);

    await loginInternalAdmin(agent);
    const csrfToken = await adminCsrfToken(agent);
    const reset = await agent
      .delete("/internal/admin/api/passkeys")
      .set("x-csrf-token", csrfToken)
      .send({ tenant_id: "common", user_sub: "user-1" })
      .expect(200);

    expect(reset.body).toEqual({ deleted: true, tenant_id: "common", user_sub: "user-1" });
    expect(passkeyStore.isEnrolled("common", "user-1")).toBe(false);
  });

  it("rejects admin UI mutations without the CSRF token", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-admin-"));
    try {
      const configPath = path.join(dir, "config.json");
      const currentConfig = adminConfig();
      await fs.writeFile(configPath, `${JSON.stringify(currentConfig, null, 2)}\n`, "utf8");
      const app = createApp({ config: currentConfig, keys, logger: silentLogger, configPath });
      const agent = request.agent(app);

      await loginInternalAdmin(agent);
      const rejected = await agent.put("/internal/admin/api/config").send({ config: currentConfig }).expect(403);
      expect(rejected.body.error).toBe("csrf_failed");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("normalizes whitespace-separated scope values when admin config is saved", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-admin-"));
    try {
      const configPath = path.join(dir, "config.json");
      await fs.writeFile(configPath, `${JSON.stringify(adminConfig(), null, 2)}\n`, "utf8");

      let currentConfig = adminConfig();
      const app = createApp({
        config: () => currentConfig,
        keys,
        logger: silentLogger,
        configPath,
        onConfigSaved: (saved) => {
          currentConfig = saved;
        }
      });
      const agent = request.agent(app);

      const login = await agent
        .post("/internal/login")
        .type("form")
        .send({
          response_type: "code",
          client_id: "internal-admin",
          redirect_uri: "http://127.0.0.1:3000/internal/admin/callback",
          scope: "openid profile email",
          state: "admin",
          user_sub: "admin-1"
        })
        .expect(302);
      await agent.get(new URL(login.header.location).pathname + new URL(login.header.location).search).expect(302);
      const csrfToken = await adminCsrfToken(agent);

      const nextConfig = {
        ...currentConfig,
        tenants: currentConfig.tenants.map((tenant) =>
          tenant.tenantId === "common"
            ? {
              ...tenant,
              clients: tenant.clients.map((client) =>
                client.clientId === "local-app" ? { ...client, allowedScopes: ["openid profile email"] } : client
              )
            }
            : tenant
        )
      };
      await agent.put("/internal/admin/api/config").set("x-csrf-token", csrfToken).send({ config: nextConfig }).expect(200);

      const saved = JSON.parse(await fs.readFile(configPath, "utf8")) as AppConfig;
      expect(saved.tenants[0].clients[0].allowedScopes).toEqual(["openid", "profile", "email"]);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
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
    expect(decodeJwt(token.body.access_token).auth_level).toBe("mock");
    expect(decodeJwt(token.body.access_token).auth_original_level).toBe("mock");
    expect(decodeJwt(token.body.id_token).auth_level).toBe("mock");
    expect(decodeJwt(token.body.id_token).auth_original_level).toBe("mock");
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
      const setCookie = login.header["set-cookie"]?.join("\n");
      expect(setCookie).toContain("az_oidc_mock_common=");
      expect(setCookie).not.toContain("user-1");

      const silentLogin = await agent
        .get("/common/oauth2/v2.0/authorize")
        .query({ ...authorizeQuery(), state: "state-2" })
        .expect(302);
      const callback = new URL(silentLogin.header.location);
      const code = callback.searchParams.get("code");
      expect(code).toBeTruthy();
      expect(callback.searchParams.get("state")).toBe("state-2");

      const token = await agent
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
      expect(decodeJwt(token.body.access_token).auth_level).toBe("cookie");
      expect(decodeJwt(token.body.access_token).auth_original_level).toBe("password");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects forged or tampered session cookies", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-passwd-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("secret")}\n`, "utf8");
      const app = createApp({
        config: secureConfig(),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath),
        sessionSecret: "test-session-secret"
      });

      const forged = await request(app)
        .get("/common/oauth2/v2.0/authorize")
        .set("cookie", "az_oidc_mock_common=user-1")
        .query(authorizeQuery())
        .expect(200);
      expect(forged.text).toContain('name="password"');

      const login = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "secret" })
        .expect(302);
      const signedCookie = login.header["set-cookie"]?.[0].split(";")[0];
      expect(signedCookie).toBeTruthy();

      const tampered = signedCookie!.replace(/.$/, signedCookie!.endsWith("a") ? "b" : "a");
      const tamperedLogin = await request(app)
        .get("/common/oauth2/v2.0/authorize")
        .set("cookie", tampered)
        .query(authorizeQuery())
        .expect(200);
      expect(tamperedLogin.text).toContain('name="password"');

      await request(app)
        .get("/common/oauth2/v2.0/authorize")
        .set("cookie", signedCookie!)
        .query(authorizeQuery())
        .expect(302);
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

  it("uses the tenant sessionLifetimeSeconds for the login cookie", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-passwd-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("secret")}\n`, "utf8");
      const app = createApp({
        config: secureConfig({ sessionLifetimeSeconds: 60 }),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath)
      });

      const login = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "secret" })
        .expect(302);

      expect(login.header["set-cookie"]?.join("\n")).toContain("Max-Age=60");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("marks secure login session cookies as Secure when the base URL is HTTPS", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-passwd-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("secret")}\n`, "utf8");
      const app = createApp({
        config: { ...secureConfig(), baseUrl: "https://mock.example.test" },
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath)
      });

      const login = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "secret" })
        .expect(302);

      expect(login.header["set-cookie"]?.join("\n")).toContain("Secure");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("offers passkey login and optional passkey setup for secure tenants", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-passkey-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("secret")}\n`, "utf8");
      const app = createApp({
        config: secureConfig({ passkeysEnabled: true }),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath),
        sessionSecret: "passkey-test-secret"
      });

      const page = await request(app)
        .get("/common/oauth2/v2.0/authorize")
        .query(authorizeQuery())
        .expect(200);
      expect(page.text).toContain("id=\"passkey-login\"");

      const setup = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "secret" })
        .expect(200);
      expect(setup.text).toContain("Set Up Passkey");
      expect(setup.text).toContain("Continue without passkey");

      const challenge = extractScriptString(setup.text, "challenge");
      const options = await request(app)
        .post("/common/passkeys/register/options")
        .send({ passkey_challenge: challenge })
        .expect(200);
      expect(options.body.publicKey.rp.id).toBe("127.0.0.1");
      expect(options.body.publicKey.user.name).toBe("alice@example.test");
      expect(options.body.registrationToken).toEqual(expect.any(String));

      const continued = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), passkey_challenge: challenge, passkey_action: "continue" })
        .expect(302);
      expect(new URL(continued.header.location).searchParams.get("code")).toBeTruthy();
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("requires passkey setup when passkeys are mandatory", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-passkey-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("secret")}\n`, "utf8");
      const app = createApp({
        config: secureConfig({ passkeysMandatory: true }),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath),
        sessionSecret: "passkey-test-secret"
      });

      const setup = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "secret" })
        .expect(200);

      expect(setup.text).toContain("Set up a passkey to continue.");
      expect(setup.text).not.toContain("Continue without passkey");
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects oversized JSON request bodies", async () => {
    const app = createApp({ config, keys, logger: silentLogger });

    await request(app)
      .post("/common/internal/token/verify")
      .send({ token: "x".repeat(110 * 1024) })
      .expect(413);
  });

  it("allows a shared account from another tenant to login and receive target-tenant tokens", async () => {
    const sharedConfig: AppConfig = {
      ...config,
      tenants: [
        config.tenants[0],
        {
          ...config.tenants[1],
          sharedUsers: [{ tenantId: "common", userSub: "user-1" }]
        }
      ]
    };
    const app = createApp({ config: sharedConfig, keys, logger: silentLogger });

    const loginPage = await request(app)
      .get("/contoso/oauth2/v2.0/authorize")
      .query(contosoAuthorizeQuery())
      .expect(200);
    expect(loginPage.text).toContain("Alice Example");

    const login = await request(app)
      .post("/contoso/login")
      .type("form")
      .send({ ...contosoAuthorizeQuery(), user_sub: "user-1" })
      .expect(302);
    const code = new URL(login.header.location).searchParams.get("code");

    const token = await request(app)
      .post("/contoso/oauth2/v2.0/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        client_id: "contoso-app",
        code,
        redirect_uri: "http://contoso.test/callback"
      })
      .expect(200);

    const userinfo = await request(app)
      .get("/contoso/oidc/userinfo")
      .set("authorization", `Bearer ${token.body.access_token}`)
      .expect(200);
    expect(userinfo.body).toMatchObject({
      sub: "user-1",
      name: "Alice Example",
      tid: "contoso"
    });
  });

  it("allows a target tenant with only shared users and no local users", async () => {
    const sharedConfig = parseConfig({
      ...config,
      tenants: [
        config.tenants[0],
        {
          ...config.tenants[1],
          users: [],
          sharedUsers: [{ tenantId: "common", userSub: "user-1" }]
        }
      ]
    });
    const app = createApp({ config: sharedConfig, keys, logger: silentLogger });

    const loginPage = await request(app)
      .get("/contoso/oauth2/v2.0/authorize")
      .query(contosoAuthorizeQuery())
      .expect(200);
    expect(loginPage.text).toContain("Alice Example");

    await request(app)
      .post("/contoso/login")
      .type("form")
      .send({ ...contosoAuthorizeQuery(), user_sub: "user-1" })
      .expect(302);
  });

  it("authenticates secure shared accounts with the source tenant password", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-shared-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("source-secret")}\n`, "utf8");
      const sharedConfig: AppConfig = {
        ...config,
        tenants: [
          config.tenants[0],
          {
            ...config.tenants[1],
            secure: true,
            sharedUsers: [{ tenantId: "common", userSub: "user-1" }]
          }
        ]
      };
      const app = createApp({
        config: sharedConfig,
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath)
      });

      await request(app)
        .post("/contoso/login")
        .type("form")
        .send({ ...contosoAuthorizeQuery(), username: "alice@example.test", password: "wrong" })
        .expect(401);

      const login = await request(app)
        .post("/contoso/login")
        .type("form")
        .send({ ...contosoAuthorizeQuery(), username: "alice@example.test", password: "source-secret" })
        .expect(302);
      expect(new URL(login.header.location).searchParams.get("code")).toBeTruthy();
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("lets users skip optional 2FA enrollment", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-mfa-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("secret")}\n`, "utf8");
      const app = createApp({
        config: secureConfig({ twoFactorEnabled: true, twoFactorMandatory: false }),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath),
        mfaStore: new MfaStore(path.join(dir, "mfa.json")),
        sessionSecret: "mfa-test-secret"
      });

      const choice = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "secret" })
        .expect(200);
      expect(choice.text).toContain("Set up 2FA");
      expect(choice.text).toContain("Continue without 2FA");

      const login = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), mfa_challenge: extractInputValue(choice.text, "mfa_challenge"), mfa_action: "continue" })
        .expect(302);
      expect(new URL(login.header.location).searchParams.get("code")).toBeTruthy();
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("requires mandatory 2FA setup before issuing the login code", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-mfa-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      const mfaStore = new MfaStore(path.join(dir, "mfa.json"));
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("secret")}\n`, "utf8");
      const app = createApp({
        config: secureConfig({ twoFactorEnabled: true, twoFactorMandatory: true }),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath),
        mfaStore,
        sessionSecret: "mfa-test-secret"
      });

      const setup = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "secret" })
        .expect(200);
      expect(setup.text).toContain("Two-factor authentication is required");
      expect(setup.text).not.toContain("Continue without 2FA");

      const secret = extractSecret(setup.text);
      const failed = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), mfa_challenge: extractInputValue(setup.text, "mfa_challenge"), mfa_action: "setup", mfa_code: "000000" })
        .expect(401);
      expect(failed.text).toContain("Authenticator code is invalid");

      const login = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), mfa_challenge: extractInputValue(failed.text, "mfa_challenge"), mfa_action: "setup", mfa_code: createTotpCode(secret) })
        .expect(302);
      expect(new URL(login.header.location).searchParams.get("code")).toBeTruthy();
      expect(mfaStore.isEnrolled("common", "user-1")).toBe(true);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("requires enrolled users to verify 2FA on login", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-mfa-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      const mfaStore = new MfaStore(path.join(dir, "mfa.json"));
      const secret = "JBSWY3DPEHPK3PXP";
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("secret")}\n`, "utf8");
      mfaStore.enrollTotp("common", "user-1", secret);
      const app = createApp({
        config: secureConfig({ twoFactorEnabled: true }),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath),
        mfaStore,
        sessionSecret: "mfa-test-secret"
      });

      const verify = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "secret" })
        .expect(200);
      expect(verify.text).toContain("Authenticator Code");

      await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), mfa_challenge: extractInputValue(verify.text, "mfa_challenge"), mfa_action: "verify", mfa_code: "000000" })
        .expect(401);

      const login = await request(app)
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), mfa_challenge: extractInputValue(verify.text, "mfa_challenge"), mfa_action: "verify", mfa_code: createTotpCode(secret) })
        .expect(302);
      expect(new URL(login.header.location).searchParams.get("code")).toBeTruthy();
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it("performs MFA step-up when a client requests the MFA ACR after cookie login", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "az-oidc-mock-mfa-"));
    try {
      const passwdPath = path.join(dir, "passwd");
      const mfaStore = new MfaStore(path.join(dir, "mfa.json"));
      const secret = "JBSWY3DPEHPK3PXP";
      await fs.writeFile(passwdPath, `common:user-1:${createPasswordHash("secret")}\n`, "utf8");
      mfaStore.enrollTotp("common", "user-1", secret);
      const app = createApp({
        config: secureConfig(),
        keys,
        logger: silentLogger,
        passwordStore: new PasswordStore(passwdPath),
        mfaStore,
        sessionSecret: "mfa-step-up-secret"
      });
      const agent = request.agent(app);

      await agent
        .post("/common/login")
        .type("form")
        .send({ ...authorizeQuery(), username: "alice@example.test", password: "secret" })
        .expect(302);

      const silentStepUp = await agent
        .get("/common/oauth2/v2.0/authorize")
        .query({ ...authorizeQuery(), prompt: "none", acr_values: "mfa" })
        .expect(302);
      expect(new URL(silentStepUp.header.location).searchParams.get("error")).toBe("interaction_required");

      const verify = await agent
        .get("/common/oauth2/v2.0/authorize")
        .query({ ...authorizeQuery(), state: "step-up", acr_values: "mfa" })
        .expect(200);
      expect(verify.text).toContain("Authenticator Code");

      const login = await agent
        .post("/common/login")
        .type("form")
        .send({
          ...authorizeQuery(),
          state: "step-up",
          acr_values: "mfa",
          mfa_challenge: extractInputValue(verify.text, "mfa_challenge"),
          mfa_action: "verify",
          mfa_code: createTotpCode(secret)
        })
        .expect(302);
      const code = new URL(login.header.location).searchParams.get("code");

      const token = await agent
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

      const accessClaims = decodeJwt(token.body.access_token);
      expect(accessClaims.auth_level).toBe("mfa");
      expect(accessClaims.auth_original_level).toBe("mfa");
      expect(accessClaims.acr).toBe("urn:az-oidc-mock:acr:mfa");
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

  it("does not let custom user claims override protected token claims", async () => {
    const app = createApp({
      config: {
        ...config,
        tenants: [
          {
            ...config.tenants[0],
            users: [
              {
                ...config.tenants[0].users[0],
                claims: {
                  aud: "other-client",
                  exp: 1,
                  roles: ["Owner"],
                  scp: "everything",
                  sub: "attacker",
                  tid: "other-tenant",
                  department: "engineering"
                }
              }
            ]
          },
          config.tenants[1]
        ]
      },
      keys,
      logger: silentLogger
    });

    const tokenSet = await issueTokenSet(app);
    const accessToken = decodeJwt(tokenSet.body.access_token);
    const idToken = decodeJwt(tokenSet.body.id_token);

    expect(accessToken.aud).toBe("local-app");
    expect(accessToken.exp).not.toBe(1);
    expect(accessToken.roles).toEqual(["Admin"]);
    expect(accessToken.scp).toBe("profile email offline_access");
    expect(accessToken.sub).toBe("user-1");
    expect(accessToken.tid).toBe("common");
    expect(accessToken.department).toBe("engineering");

    expect(idToken.aud).toBe("local-app");
    expect(idToken.exp).not.toBe(1);
    expect(idToken.roles).toEqual(["Admin"]);
    expect(idToken.sub).toBe("user-1");
    expect(idToken.tid).toBe("common");
    expect(idToken.department).toBe("engineering");
  });

  it("serves OIDC userinfo for a valid access token", async () => {
    const app = createApp({ config, keys, logger: silentLogger });
    const token = await issueAccessToken(app);

    const userinfo = await request(app)
      .get("/common/oidc/userinfo")
      .set("authorization", `Bearer ${token}`)
      .expect(200);

    expect(userinfo.body).toMatchObject({
      sub: "user-1",
      oid: "user-1",
      name: "Alice Example",
      email: "alice@example.test",
      preferred_username: "alice@example.test",
      tid: "common",
      roles: ["Admin"]
    });
  });

  it("rejects userinfo without an access token", async () => {
    const app = createApp({ config, keys, logger: silentLogger });

    const userinfo = await request(app)
      .get("/common/oidc/userinfo")
      .expect(401);

    expect(userinfo.body.error).toBe("invalid_token");
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
    expect(decodeJwt(refreshed.body.access_token).auth_level).toBe("mock");
    expect(decodeJwt(refreshed.body.access_token).auth_original_level).toBe("mock");

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

function contosoAuthorizeQuery() {
  return {
    response_type: "code",
    client_id: "contoso-app",
    redirect_uri: "http://contoso.test/callback",
    scope: "openid profile",
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

async function loginInternalAdmin(agent: request.Agent): Promise<void> {
  const login = await agent
    .post("/internal/login")
    .type("form")
    .send({
      response_type: "code",
      client_id: "internal-admin",
      redirect_uri: "http://127.0.0.1:3000/internal/admin/callback",
      scope: "openid profile email",
      state: "admin",
      user_sub: "admin-1"
    })
    .expect(302);
  await agent.get(new URL(login.header.location).pathname + new URL(login.header.location).search).expect(302);
}

async function adminCsrfToken(agent: request.Agent): Promise<string> {
  const api = await agent.get("/internal/admin/api/config").expect(200);
  expect(api.body.csrfToken).toEqual(expect.any(String));
  return api.body.csrfToken;
}

function extractInputValue(html: string, name: string): string {
  const pattern = new RegExp(`name="${name}" value="([^"]+)"`);
  const match = pattern.exec(html);
  if (!match) {
    throw new Error(`Input ${name} not found`);
  }
  return match[1].replaceAll("&quot;", "\"").replaceAll("&amp;", "&");
}

function extractScriptString(html: string, name: string): string {
  const pattern = new RegExp(`const ${name} = "([^"]+)"`);
  const match = pattern.exec(html);
  if (!match) {
    throw new Error(`Script string ${name} not found`);
  }
  return match[1];
}

function extractSecret(html: string): string {
  const match = /<div class="secret">([^<]+)<\/div>/.exec(html);
  if (!match) {
    throw new Error("TOTP secret not found");
  }
  return match[1];
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
        sessionLifetimeSeconds: 8 * 60 * 60,
        ...overrides
      },
      config.tenants[1]
    ]
  };
}

function adminConfig(): AppConfig {
  return {
    ...config,
    tenants: [
      ...config.tenants,
      {
        tenantId: "internal",
        displayName: "Internal Admin",
        clients: [
          {
            clientId: "internal-admin",
            redirectUris: ["http://127.0.0.1:3000/internal/admin/callback"],
            allowedScopes: ["openid", "profile", "email"],
            enabled: true
          }
        ],
        devices: [],
        secure: false,
        enableSessions: true,
        sessionLifetimeSeconds: 8 * 60 * 60,
        users: [
          {
            sub: "admin-1",
            name: "Admin User",
            email: "admin@example.test",
            preferred_username: "admin@example.test",
            roles: [],
            claims: { internal_admin: true }
          }
        ]
      }
    ]
  };
}

function sharedInternalAdminConfig(access: { role?: boolean; claim?: boolean } = {}): AppConfig {
  return {
    ...config,
    tenants: [
      {
        ...config.tenants[0],
        users: config.tenants[0].users.map((user) =>
          user.sub === "user-1"
            ? {
              ...user,
              roles: access.role ? ["internal-admin"] : [],
              claims: access.claim ? { ...user.claims, internal_admin: true } : user.claims
            }
            : user
        )
      },
      config.tenants[1],
      {
        tenantId: "internal",
        displayName: "Internal Admin",
        clients: [
          {
            clientId: "internal-admin",
            redirectUris: ["http://127.0.0.1:3000/internal/admin/callback"],
            allowedScopes: ["openid", "profile", "email"],
            enabled: true
          }
        ],
        devices: [],
        secure: false,
        enableSessions: true,
        sessionLifetimeSeconds: 8 * 60 * 60,
        sharedUsers: [{ tenantId: "common", userSub: "user-1" }],
        users: []
      }
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
