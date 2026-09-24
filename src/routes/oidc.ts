import type { Express, Request, Response } from "express";
import type { AppConfig, MockClient, MockTenant, MockUser } from "../config.js";
import { tenantIssuer } from "../config.js";
import type { Logger } from "../logger.js";
import type { SigningKeys } from "../oidc/keys.js";
import type { PasswordStore } from "../oidc/passwords.js";
import { clearSessionUser, getSessionUser, setSessionUser } from "../oidc/session.js";
import type { OidcState } from "../oidc/state.js";
import { isInactiveRefreshTokenDevice, resolveActiveTokenSubject } from "../oidc/token-subject.js";
import { createAccessToken, createIdToken } from "../oidc/tokens.js";
import {
  findClient,
  findDevice,
  findUser,
  parseScopes,
  validateRedirectUri,
  validateScopes
} from "../oidc/validation.js";
import { renderLoginPage } from "../views/login.js";
import {
  emptyToUndefined,
  getTenantOr404,
  readBearerToken,
  readString,
  sendAuthorizeError,
  sendTokenError
} from "./http.js";
import type { RouteContext } from "./types.js";

type AuthorizeQuery = {
  client_id?: string;
  redirect_uri?: string;
  response_type?: string;
  scope?: string;
  state?: string;
  nonce?: string;
  prompt?: string;
  device_id?: string;
};

export function registerOidcRoutes(app: Express, context: RouteContext): void {
  app.get(["/:tenantId/.well-known/openid-configuration", "/:tenantId/v2.0/.well-known/openid-configuration"], (req, res) => {
    const config = context.getConfig();
    const tenant = getTenantOr404(config, req, res);
    if (!tenant) return;
    context.logger.verbose(config, "serving discovery document", { tenantId: tenant.tenantId });

    res.json(createDiscoveryDocument(config, tenant));
  });

  app.get("/:tenantId/discovery/v2.0/keys", (req, res) => {
    const config = context.getConfig();
    const tenant = getTenantOr404(config, req, res);
    if (!tenant) return;
    context.logger.verbose(config, "serving jwks", { tenantId: tenant.tenantId, keyCount: context.keys.jwks.keys.length });
    res.json(context.keys.jwks);
  });

  app.get("/:tenantId/oauth2/v2.0/authorize", (req, res) => {
    const config = context.getConfig();
    const tenant = getTenantOr404(config, req, res);
    if (!tenant) return;
    const enableSessions = tenant.enableSessions;

    context.logger.verbose(config, "authorize request received", {
      tenantId: tenant.tenantId,
      clientId: req.query.client_id,
      prompt: req.query.prompt,
      enableSessions
    });

    const validation = validateAuthorizeRequest(tenant, req.query as AuthorizeQuery);
    if (!validation.ok) {
      context.logger.warn("authorize request rejected", {
        tenantId: tenant.tenantId,
        error: validation.error,
        description: validation.description
      });
      sendAuthorizeError(res, req.query.redirect_uri, req.query.state, validation.error, validation.description);
      return;
    }
    if (enableSessions === true) {
      const sessionUser = getSessionUser(req, tenant, context.sessionSecret);
      if (sessionUser) {
        context.logger.verbose(config, "authorize request satisfied from existing session", {
          tenantId: tenant.tenantId,
          clientId: validation.client.clientId,
          userSub: sessionUser.sub
        });
        redirectWithCode(res, context.state, tenant.tenantId, validation.client, validation.request, sessionUser.sub);
        return;
      }
    }
    if (req.query.prompt === "none") {
      context.logger.verbose(config, "silent authorize requires login", {
        tenantId: tenant.tenantId,
        clientId: validation.client.clientId
      });
      sendAuthorizeError(res, validation.request.redirectUri, validation.request.state, "login_required");
      return;
    }

    res.type("html").send(
      renderLoginPage(tenant, {
        client_id: validation.client.clientId,
        redirect_uri: validation.request.redirectUri,
        response_type: "code",
        scope: validation.request.scope.join(" "),
        state: validation.request.state ?? "",
        nonce: validation.request.nonce ?? "",
        device_id: validation.request.deviceId ?? ""
      }, readString(req.query.login_error))
    );
  });

  app.post("/:tenantId/login", (req, res) => {
    const config = context.getConfig();
    const tenant = getTenantOr404(config, req, res);
    if (!tenant) return;
    context.logger.verbose(config, "login form submitted", { tenantId: tenant.tenantId, clientId: req.body.client_id });

    const validation = validateAuthorizeRequest(tenant, req.body as AuthorizeQuery);
    if (!validation.ok) {
      context.logger.warn("login request rejected", {
        tenantId: tenant.tenantId,
        error: validation.error,
        description: validation.description
      });
      sendAuthorizeError(res, req.body.redirect_uri, req.body.state, validation.error, validation.description);
      return;
    }

    const login = authenticateLogin(tenant, req, context.passwordStore);
    if (!login.ok) {
      context.logger.warn("login rejected", { tenantId: tenant.tenantId, reason: login.description });
      if (tenant.secure) {
        res.type("html").status(401).send(renderLoginPage(tenant, {
          client_id: validation.client.clientId,
          redirect_uri: validation.request.redirectUri,
          response_type: "code",
          scope: validation.request.scope.join(" "),
          state: validation.request.state ?? "",
          nonce: validation.request.nonce ?? "",
          device_id: validation.request.deviceId ?? ""
        }, login.description));
        return;
      }
      sendAuthorizeError(res, validation.request.redirectUri, validation.request.state, "access_denied", login.description);
      return;
    }

    if (tenant.enableSessions) {
      setSessionUser(res, tenant, login.user.sub, context.sessionSecret);
    }
    context.logger.info("mock user selected", {
      tenantId: tenant.tenantId,
      clientId: validation.client.clientId,
      userSub: login.user.sub
    });
    redirectWithCode(res, context.state, tenant.tenantId, validation.client, validation.request, login.user.sub);
  });

  app.post("/:tenantId/oauth2/v2.0/token", async (req, res) => {
    const config = context.getConfig();
    const tenant = getTenantOr404(config, req, res);
    if (!tenant) return;
    context.logger.verbose(config, "token request received", {
      tenantId: tenant.tenantId,
      grantType: req.body.grant_type,
      clientId: req.body.client_id
    });

    const client = authenticateClient(tenant, req);
    if (!client) {
      context.logger.warn("token request rejected due to client authentication failure", {
        tenantId: tenant.tenantId,
        clientId: req.body.client_id
      });
      sendTokenError(res, "invalid_client", "Client authentication failed", 401);
      return;
    }

    const grantType = readString(req.body.grant_type);
    if (grantType === "authorization_code") {
      await handleAuthorizationCodeGrant({ ...context, config, tenant, client, req, res });
      return;
    }
    if (grantType === "refresh_token") {
      await handleRefreshTokenGrant({ ...context, config, tenant, client, req, res });
      return;
    }

    context.logger.warn("token request used unsupported grant type", {
      tenantId: tenant.tenantId,
      clientId: client.clientId,
      grantType
    });
    sendTokenError(res, "unsupported_grant_type", "Only authorization_code and refresh_token are supported");
  });

  app.all("/:tenantId/oidc/userinfo", async (req, res) => {
    const config = context.getConfig();
    const tenant = getTenantOr404(config, req, res);
    if (!tenant) return;

    const token = readBearerToken(req);
    if (!token) {
      res.status(401).json({
        error: "invalid_token",
        error_description: "Bearer access token is required"
      });
      return;
    }

    const subject = await resolveActiveTokenSubject({ config, keys: context.keys, tenant, token });
    if (!subject.ok) {
      context.logger.warn("userinfo request rejected", {
        tenantId: tenant.tenantId,
        error: subject.error
      });
      res.status(401).json({
        error: subject.error,
        error_description: subject.description
      });
      return;
    }

    const { user } = subject;
    res.json({
      sub: user.sub,
      oid: user.sub,
      name: user.name,
      email: user.email,
      preferred_username: user.preferred_username,
      roles: user.roles,
      tid: tenant.tenantId,
      ...user.claims
    });
  });

  app.get("/:tenantId/oauth2/v2.0/logout", (req, res) => {
    const config = context.getConfig();
    const tenant = getTenantOr404(config, req, res);
    if (!tenant) return;
    clearSessionUser(res, tenant.tenantId);
    context.logger.info("mock session cleared", { tenantId: tenant.tenantId });
    const redirect = readString(req.query.post_logout_redirect_uri);
    if (redirect) {
      res.redirect(redirect);
      return;
    }
    res.status(204).send();
  });
}

function createDiscoveryDocument(config: AppConfig, tenant: MockTenant): Record<string, unknown> {
  const base = config.baseUrl.replace(/\/$/, "");
  const encodedTenantId = encodeURIComponent(tenant.tenantId);
  const tenantBase = `${base}/${encodedTenantId}/oauth2/v2.0`;

  return {
    token_endpoint: `${tenantBase}/token`,
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    userinfo_endpoint: `${base}/${encodedTenantId}/oidc/userinfo`,
    jwks_uri: `${base}/${encodedTenantId}/discovery/v2.0/keys`,
    response_modes_supported: ["query", "form_post"],
    subject_types_supported: ["pairwise"],
    id_token_signing_alg_values_supported: ["RS256"],
    response_types_supported: ["code", "id_token", "code id_token"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    scopes_supported: tenantScopes(tenant),
    issuer: tenantIssuer(config, tenant.tenantId),
    authorization_endpoint: `${tenantBase}/authorize`,
    device_authorization_endpoint: `${tenantBase}/devicecode`,
    http_logout_supported: true,
    frontchannel_logout_supported: true,
    end_session_endpoint: `${tenantBase}/logout`,
    claims_supported: [
      "aud",
      "email",
      "exp",
      "iat",
      "iss",
      "name",
      "nbf",
      "nonce",
      "oid",
      "preferred_username",
      "roles",
      "sub",
      "tid",
      "ver"
    ],
    kerberos_endpoint: `${base}/${encodedTenantId}/kerberos`,
    tenant_region_scope: "NA",
    cloud_instance_name: "mock",
    cloud_graph_host_name: "graph.windows.net",
    msgraph_host: "graph.microsoft.com",
    rbac_url: "https://pas.windows.net"
  };
}

function validateAuthorizeRequest(tenant: MockTenant, query: AuthorizeQuery):
  | {
    ok: true;
    client: MockClient;
    request: {
      clientId: string;
      redirectUri: string;
      scope: string[];
      state?: string;
      nonce?: string;
      deviceId?: string;
    };
  }
  | { ok: false; error: string; description?: string } {
  if (query.response_type !== "code") {
    return { ok: false, error: "unsupported_response_type", description: "Only response_type=code is supported" };
  }

  const clientId = query.client_id;
  const redirectUri = query.redirect_uri;
  if (!clientId || !redirectUri) {
    return { ok: false, error: "invalid_request", description: "client_id and redirect_uri are required" };
  }

  const client = findClient(tenant, clientId);
  if (!client) {
    return { ok: false, error: "unauthorized_client", description: "Unknown client for tenant" };
  }
  if (!client.enabled) {
    return { ok: false, error: "unauthorized_client", description: "Client is disabled" };
  }

  if (!validateRedirectUri(client, redirectUri)) {
    return { ok: false, error: "invalid_request", description: "redirect_uri is not registered for client" };
  }

  const scope = parseScopes(query.scope);
  if (!scope.includes("openid")) {
    return { ok: false, error: "invalid_scope", description: "openid scope is required" };
  }
  if (!validateScopes(client, scope)) {
    return { ok: false, error: "invalid_scope", description: "Requested scope is not allowed for client" };
  }

  const device = resolveRequestedDevice(tenant, query.device_id);
  if (!device.ok) {
    return { ok: false, error: "access_denied", description: device.description };
  }

  return {
    ok: true,
    client,
    request: {
      clientId,
      redirectUri,
      scope,
      state: emptyToUndefined(query.state),
      nonce: emptyToUndefined(query.nonce),
      deviceId: device.deviceId
    }
  };
}

function resolveRequestedDevice(
  tenant: MockTenant,
  requestedDeviceId?: string
): { ok: true; deviceId?: string } | { ok: false; description: string } {
  if (requestedDeviceId) {
    const device = findDevice(tenant, requestedDeviceId);
    if (!device) {
      return { ok: false, description: "Unknown device for tenant" };
    }
    if (!device.enabled) {
      return { ok: false, description: "Device is disabled" };
    }
    return { ok: true, deviceId: device.deviceId };
  }

  const activeDevice = tenant.devices.find((device) => device.enabled);
  return { ok: true, deviceId: activeDevice?.deviceId };
}

function redirectWithCode(
  res: Response,
  oidcState: OidcState,
  tenantId: string,
  client: MockClient,
  request: { redirectUri: string; scope: string[]; state?: string; nonce?: string; deviceId?: string },
  userSub: string
): void {
  const code = oidcState.createCode(
    {
      tenantId,
      clientId: client.clientId,
      redirectUri: request.redirectUri,
      scope: request.scope,
      state: request.state,
      nonce: request.nonce,
      deviceId: request.deviceId
    },
    userSub
  );
  const redirectUrl = new URL(request.redirectUri);
  redirectUrl.searchParams.set("code", code);
  if (request.state) {
    redirectUrl.searchParams.set("state", request.state);
  }
  res.redirect(redirectUrl.toString());
}

async function handleAuthorizationCodeGrant(args: {
  config: AppConfig;
  keys: SigningKeys;
  logger: Logger;
  state: OidcState;
  tenant: MockTenant;
  client: MockClient;
  req: Request;
  res: Response;
}): Promise<void> {
  const code = readString(args.req.body.code);
  const redirectUri = readString(args.req.body.redirect_uri);
  if (!code || !redirectUri) {
    args.logger.warn("authorization code grant rejected because required fields are missing", {
      tenantId: args.tenant.tenantId,
      clientId: args.client.clientId
    });
    sendTokenError(args.res, "invalid_request", "code and redirect_uri are required");
    return;
  }

  const entry = args.state.consumeCode(code);
  if (
    !entry ||
    entry.tenantId !== args.tenant.tenantId ||
    entry.clientId !== args.client.clientId ||
    entry.redirectUri !== redirectUri
  ) {
    args.logger.warn("authorization code grant rejected", {
      tenantId: args.tenant.tenantId,
      clientId: args.client.clientId
    });
    sendTokenError(args.res, "invalid_grant", "Authorization code is invalid or expired");
    return;
  }

  const user = findUser(args.tenant, entry.userSub);
  if (!user) {
    args.logger.warn("authorization code grant rejected because user is missing", {
      tenantId: args.tenant.tenantId,
      clientId: args.client.clientId,
      userSub: entry.userSub
    });
    sendTokenError(args.res, "invalid_grant", "User no longer exists");
    return;
  }

  const refreshTokenExpiresAt = Date.now() + args.config.refreshTokenLifetimeSeconds * 1000;
  const refreshToken = entry.scope.includes("offline_access")
    ? args.state.createRefreshToken({
      tenantId: args.tenant.tenantId,
      clientId: args.client.clientId,
      userSub: user.sub,
      scope: entry.scope,
      nonce: entry.nonce,
      deviceId: entry.deviceId,
      expiresAt: refreshTokenExpiresAt
    })
    : undefined;

  await sendTokenSet(args.res, {
    config: args.config,
    keys: args.keys,
    state: args.state,
    tenant: args.tenant,
    client: args.client,
    user,
    scope: entry.scope,
    nonce: entry.nonce,
    deviceId: entry.deviceId,
    refreshToken,
    refreshTokenExpiresAt: refreshToken ? refreshTokenExpiresAt : undefined
  });
  args.logger.info("authorization code grant completed", {
    tenantId: args.tenant.tenantId,
    clientId: args.client.clientId,
    userSub: user.sub,
    refreshTokenIssued: Boolean(refreshToken)
  });
}

async function handleRefreshTokenGrant(args: {
  config: AppConfig;
  keys: SigningKeys;
  logger: Logger;
  state: OidcState;
  tenant: MockTenant;
  client: MockClient;
  req: Request;
  res: Response;
}): Promise<void> {
  const token = readString(args.req.body.refresh_token);
  if (!token) {
    args.logger.warn("refresh token grant rejected because refresh_token is missing", {
      tenantId: args.tenant.tenantId,
      clientId: args.client.clientId
    });
    sendTokenError(args.res, "invalid_request", "refresh_token is required");
    return;
  }

  const entry = args.state.getRefreshToken(token);
  if (!entry || entry.tenantId !== args.tenant.tenantId || entry.clientId !== args.client.clientId) {
    args.logger.warn("refresh token grant rejected", {
      tenantId: args.tenant.tenantId,
      clientId: args.client.clientId
    });
    sendTokenError(args.res, "invalid_grant", "Refresh token is invalid or expired");
    return;
  }

  const user = findUser(args.tenant, entry.userSub);
  if (!user) {
    args.logger.warn("refresh token grant rejected because user is missing", {
      tenantId: args.tenant.tenantId,
      clientId: args.client.clientId,
      userSub: entry.userSub
    });
    sendTokenError(args.res, "invalid_grant", "User no longer exists");
    return;
  }

  const device = entry.deviceId ? findDevice(args.tenant, entry.deviceId) : undefined;
  if (isInactiveRefreshTokenDevice(args.tenant, entry.deviceId, device)) {
    args.logger.warn("refresh token grant rejected because device is inactive", {
      tenantId: args.tenant.tenantId,
      clientId: args.client.clientId,
      userSub: entry.userSub,
      deviceId: entry.deviceId
    });
    sendTokenError(args.res, "invalid_grant", "Device used for original sign-in is inactive");
    return;
  }

  let refreshToken = token;
  let refreshTokenExpiresAt = entry.expiresAt;
  if (args.config.rotateRefreshTokens) {
    args.state.revokeRefreshToken(token);
    refreshTokenExpiresAt = Date.now() + args.config.refreshTokenLifetimeSeconds * 1000;
    refreshToken = args.state.createRefreshToken({
      tenantId: entry.tenantId,
      clientId: entry.clientId,
      userSub: entry.userSub,
      scope: entry.scope,
      nonce: entry.nonce,
      deviceId: entry.deviceId,
      expiresAt: refreshTokenExpiresAt
    });
  }

  await sendTokenSet(args.res, {
    config: args.config,
    keys: args.keys,
    state: args.state,
    tenant: args.tenant,
    client: args.client,
    user,
    scope: entry.scope,
    nonce: entry.nonce,
    deviceId: entry.deviceId,
    refreshToken,
    refreshTokenExpiresAt
  });
  args.logger.info("refresh token grant completed", {
    tenantId: args.tenant.tenantId,
    clientId: args.client.clientId,
    userSub: user.sub,
    refreshTokenRotated: args.config.rotateRefreshTokens
  });
}

async function sendTokenSet(
  res: Response,
  args: {
    config: AppConfig;
    keys: SigningKeys;
    state: OidcState;
    tenant: MockTenant;
    client: MockClient;
    user: MockUser;
    scope: string[];
    nonce?: string;
    deviceId?: string;
    refreshToken?: string;
    refreshTokenExpiresAt?: number;
  }
): Promise<void> {
  const input = {
    config: args.config,
    keys: args.keys,
    tenant: args.tenant,
    client: args.client,
    user: args.user,
    scope: args.scope,
    nonce: args.nonce,
    deviceId: args.deviceId
  };
  const raw = JSON.stringify({ uid: args.user.sub, utid: args.tenant.tenantId });
  const enc = Buffer.from(raw)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  res.json({
    client_info: enc,
    token_type: "Bearer",
    expires_in: args.config.tokenLifetimeSeconds,
    scope: args.scope.join(" "),
    access_token: await createAccessToken(input),
    id_token: await createIdToken(input),
    ...(args.refreshToken && args.refreshTokenExpiresAt ? {
      refresh_token: args.refreshToken,
      refresh_token_expires_in: Math.max(0, Math.floor((args.refreshTokenExpiresAt - Date.now()) / 1000)),
      refresh_token_expires_at: Math.floor(args.refreshTokenExpiresAt / 1000)
    } : {})
  });
}

function authenticateClient(tenant: MockTenant, req: Request): MockClient | undefined {
  const basic = parseBasicAuth(req);
  const clientId = basic?.clientId ?? readString(req.body.client_id);
  const clientSecret = basic?.clientSecret ?? readString(req.body.client_secret);
  if (!clientId) {
    return undefined;
  }

  const client = findClient(tenant, clientId);
  if (!client || !client.enabled) {
    return undefined;
  }

  if (client.clientSecret && client.clientSecret !== clientSecret) {
    return undefined;
  }

  return client;
}

function parseBasicAuth(req: Request): { clientId: string; clientSecret: string } | undefined {
  const header = req.header("authorization");
  if (!header?.startsWith("Basic ")) {
    return undefined;
  }
  const decoded = Buffer.from(header.slice("Basic ".length), "base64").toString("utf8");
  const separator = decoded.indexOf(":");
  if (separator < 0) {
    return undefined;
  }
  return {
    clientId: decodeURIComponent(decoded.slice(0, separator)),
    clientSecret: decodeURIComponent(decoded.slice(separator + 1))
  };
}

function authenticateLogin(
  tenant: MockTenant,
  req: Request,
  passwordStore: PasswordStore
): { ok: true; user: MockUser } | { ok: false; description: string } {
  if (!tenant.secure) {
    const userSub = readString(req.body.user_sub);
    const user = userSub ? findUser(tenant, userSub) : undefined;
    return user ? { ok: true, user } : { ok: false, description: "Unknown user" };
  }

  const username = readString(req.body.username)?.toLowerCase();
  const password = readString(req.body.password);
  if (!username || !password) {
    return { ok: false, description: "Email and password are required" };
  }

  const user = tenant.users.find((candidate) =>
    candidate.email.toLowerCase() === username ||
    candidate.preferred_username.toLowerCase() === username
  );
  if (!user || !passwordStore.verify(tenant.tenantId, user.sub, password)) {
    return { ok: false, description: "Invalid email or password" };
  }

  return { ok: true, user };
}

function tenantScopes(tenant: MockTenant): string[] {
  return [...new Set(tenant.clients.flatMap((client) => client.allowedScopes))].sort();
}
