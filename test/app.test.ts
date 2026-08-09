import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import { createSigningKeys, type SigningKeys } from "../src/oidc/keys.js";

const config: AppConfig = {
  port: 3000,
  baseUrl: "http://127.0.0.1:3000",
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

beforeEach(async () => {
  keys = await createSigningKeys();
});

describe("Azure OIDC mock", () => {
  it("serves tenant-specific discovery metadata", async () => {
    const app = createApp({ config, keys });

    const res = await request(app).get("/common/.well-known/openid-configuration").expect(200);

    expect(res.body.issuer).toBe("http://127.0.0.1:3000/common/v2.0");
    expect(res.body.authorization_endpoint).toBe("http://127.0.0.1:3000/common/oauth2/v2.0/authorize");
    expect(res.body.jwks_uri).toBe("http://127.0.0.1:3000/common/discovery/v2.0/keys");
  });

  it("rejects clients from another tenant", async () => {
    const app = createApp({ config, keys });

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
    const app = createApp({ config, keys });

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
    const app = createApp({ config, keys });
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

