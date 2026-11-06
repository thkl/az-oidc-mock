# Azure OIDC Mock

Small Azure-style OpenID Connect mock server for local development and integration tests.

It supports multi-tenant discovery, interactive mock login, authorization code exchange, signed JWT access and ID tokens, and silent renewal through refresh tokens.

## Run Locally

```bash
pnpm install
pnpm dev
```

The server reads `config.json` by default. Override it with:

```bash
CONFIG_PATH=/path/to/config.json pnpm start
```

`PORT` and `OIDC_MOCK_BASE_URL` can override the file at runtime:

```bash
PORT=3107 OIDC_MOCK_BASE_URL=http://localhost:3107 pnpm start
```

To run the mock directly over HTTPS, provide a local certificate and key either in `config.json`:

```json
{
  "baseUrl": "https://localhost:3443",
  "tls": {
    "keyPath": "./localhost-key.pem",
    "certPath": "./localhost-cert.pem"
  }
}
```

Or with environment variables:

```bash
PORT=3443 \
OIDC_MOCK_BASE_URL=https://localhost:3443 \
OIDC_MOCK_TLS_KEY_PATH=./localhost-key.pem \
OIDC_MOCK_TLS_CERT_PATH=./localhost-cert.pem \
pnpm start
```

The server can also generate and reuse a self-signed certificate at startup:

```json
{
  "baseUrl": "https://localhost:3443",
  "tls": {
    "autoGenerate": true,
    "hosts": ["localhost", "127.0.0.1"],
    "days": 365
  }
}
```

By default, generated certificates are stored next to the active config file as `localhost-cert.pem` and `localhost-key.pem`. For Docker, bind-mount the config directory, not just the config file, so the generated certificate and key persist:

```bash
docker run --rm -p 3443:3443 \
  -e CONFIG_PATH=/config/config.json \
  -v ./oidc-config:/config \
  az-oidc-mock
```

Set `tls.certPath` and `tls.keyPath` with `autoGenerate: true` to choose different output paths.

For a self-signed localhost certificate, `mkcert` is the least painful option because it also installs a local development CA trusted by your browser:

```bash
mkcert -install
mkcert -key-file localhost-key.pem -cert-file localhost-cert.pem localhost 127.0.0.1
```

MSAL will only trust a self-signed certificate if the runtime trusts it. Browser-based MSAL uses browser or operating-system certificate trust. MSAL Node uses Node's TLS trust store; for a custom CA, pass it through `NODE_EXTRA_CA_CERTS`.

TLS settings are read at startup. Restart the server after changing certificate paths.

`config.json` is watched while the server is running. Valid changes are reloaded automatically for new requests. If a changed file is invalid JSON or fails schema validation, the server keeps using the last valid config and logs the reload error.

Refresh tokens are persisted next to the active config file in `refresh-tokens.json`. If `CONFIG_PATH=/config/config.json`, the refresh-token cache is `/config/refresh-tokens.json`, which makes it suitable for Docker bind mounts or shared volumes. Expired refresh tokens are pruned when the cache is loaded or updated.

Secure tenant passwords are read from a `passwd` file next to the active config file. If `CONFIG_PATH=/config/config.json`, the password file is `/config/passwd`.

Set `OIDC_MOCK_ADMIN_TOKEN` to enable internal password-management endpoints for containerized deployments where editing `passwd` directly is inconvenient.

Clients can use a legacy single `clientSecret` or multiple named entries under `clientSecrets`. For example, a client can have separate `test` and `prod` values; the OAuth token request still sends only `client_id` and `client_secret`. Named values are supported by configuration and token authentication. An optional `clientSecretLifetimeDays` setting expires named secrets after activation; the admin client list shows their last five characters and expiry time. Enable manager access per client by setting allowed rotation names in the admin UI. A manager authenticates with the target client's current credential, exchanges it for a short-lived capability scoped to one named create or rotation, and uses that capability to start and activate the operation. See [client-secret-rotation.md](docs/client-secret-rotation.md) for setup and endpoints.

Verbose logging can be enabled in `config.json`:

```json
{
  "verbose": true
}
```

Or by environment variable:

```bash
OIDC_MOCK_VERBOSE=true pnpm start
```

Verbose mode logs request timing and OIDC control-flow events. Token and authorization code values are not logged.

## Docker

```bash
docker build -t az-oidc-mock .
docker run --rm -p 3000:3000 -v ./config.json:/app/config.json az-oidc-mock
```

## Azure-Style Endpoints

For tenant `common`:

```text
GET  http://localhost:3000/common/.well-known/openid-configuration
GET  http://localhost:3000/common/v2.0/.well-known/openid-configuration
GET  http://localhost:3000/common/discovery/v2.0/keys
GET  http://localhost:3000/common/oauth2/v2.0/authorize
POST http://localhost:3000/common/oauth2/v2.0/token
GET  http://localhost:3000/common/oidc/userinfo
GET  http://localhost:3000/common/oauth2/v2.0/logout
POST http://localhost:3000/common/internal/token/verify
GET  http://localhost:3000/internal/admin
```

The issuer is:

```text
http://localhost:3000/common/v2.0
```

For MSAL, use `http://localhost:3000/common` as the authority when the library appends the v2.0 discovery path itself. For non-Azure custom-authority mode, configure MSAL with the local authority as known/trusted according to the MSAL client you use.

## Admin UI

Open the built-in admin console at:

```text
http://localhost:3000/internal/admin
```

The admin console uses the mock itself for authentication. Configure a secure tenant named `internal` with a client named `internal-admin`. The signed-in user must have either the `internal-admin` role or `claims.internal_admin: true`.

```json
{
  "tenantId": "internal",
  "displayName": "Internal Admin",
  "secure": true,
  "enableSessions": true,
  "sessionLifetimeSeconds": 28800,
  "passkeysEnabled": false,
  "passkeysMandatory": false,
  "clients": [
    {
      "clientId": "internal-admin",
      "redirectUris": ["http://localhost:3000/internal/admin/callback"],
      "allowedScopes": ["openid", "profile", "email"],
      "enabled": true
    }
  ],
  "devices": [],
  "users": [
    {
      "sub": "admin-1",
      "name": "Admin User",
      "email": "admin@example.test",
      "preferred_username": "admin@example.test",
      "roles": [],
      "claims": { "internal_admin": true }
    }
  ]
}
```

Set the initial password for the internal admin user through the password endpoint:

```bash
curl -sS -X POST http://localhost:3000/internal/internal/passwords \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer change-this-admin-token' \
  -d '{"username":"admin@example.test","password":"change-me"}'
```

The admin UI is a Vue 3 page loaded from the public Vue CDN and writes changes back to the active `config.json`. It currently edits tenants, clients, users, tenant session settings, and device JSON.

## Authorization Code Flow

Open this in a browser:

```text
http://localhost:3000/common/oauth2/v2.0/authorize?response_type=code&client_id=local-app&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fauth%2Fcallback&scope=openid%20profile%20email%20offline_access&state=abc&nonce=xyz&device_id=machine-1
```

The mock login screen shows users from the selected tenant. Choosing one redirects to the configured callback with `code` and `state`.

If the tenant has `"secure": true`, the login screen shows email and password fields instead of the user picker. Users still come from the tenant config, but passwords are verified from the `passwd` file.

Pass `device_id=machine-1` on the authorize request to bind the login to a configured tenant device. If a tenant has devices and no `device_id` is passed, the first enabled device is used.

Exchange the code:

```bash
curl -sS -X POST http://localhost:3000/common/oauth2/v2.0/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'client_id=local-app' \
  -d 'client_secret=local-prod-secret' \
  -d 'code=PASTE_CODE_HERE' \
  -d 'redirect_uri=http://localhost:5173/auth/callback'
```

Refresh tokens are issued when the request includes `offline_access`.

The token response includes refresh-token expiry metadata when a refresh token is issued:

```json
{
  "refresh_token": "PASTE_REFRESH_TOKEN_HERE",
  "refresh_token_expires_in": 86400,
  "refresh_token_expires_at": 1786464000
}
```

## Silent Renewal

```bash
curl -sS -X POST http://localhost:3000/common/oauth2/v2.0/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d 'client_id=local-app' \
  -d 'client_secret=local-prod-secret' \
  -d 'refresh_token=PASTE_REFRESH_TOKEN_HERE'
```

If `rotateRefreshTokens` is `true`, the old refresh token is invalidated and a new one is returned.

Refresh tokens are stored in `refresh-tokens.json` next to the active config file, so renewal continues to work after restarting the mock as long as that config directory is persisted.

Refresh-token renewal also checks the device that was used for the original login. If that device is later removed from config or set to `"enabled": false`, renewal fails with `invalid_grant`.

## Shared Accounts

Use `sharedUsers` on a tenant when an account from one tenant should also be accepted by another tenant.

```json
{
  "tenantId": "tenant-b",
  "displayName": "Tenant B",
  "users": [],
  "sharedUsers": [
    {
      "tenantId": "tenant-a",
      "userSub": "00000000-0000-0000-0000-000000000001"
    }
  ]
}
```

The target tenant may have zero local users when it has shared users.

The user profile and password remain owned by the source tenant. If `tenant-b` is secure, logging in as the shared account checks the password stored under `tenant-a:userSub` in `passwd`.

Tokens are still issued for the target tenant. In the example above, the issued token has the `tenant-b` issuer/audience context, while user claims come from the source account.

In the admin UI, select the source user and use the `Share This User With` checkboxes to choose target tenants. The UI writes the `sharedUsers` entries for you.

## Secure Tenant Login

Set `"secure": true` on a tenant to make its interactive login behave more like a real SSO login. The page no longer lists configured users. Instead, the user enters their email or `preferred_username` and password.

```json
{
  "tenantId": "common",
  "displayName": "Default Tenant",
  "secure": true,
  "enableSessions": true,
  "sessionLifetimeSeconds": 28800,
  "twoFactorEnabled": false,
  "twoFactorMandatory": false,
  "passkeysEnabled": false,
  "passkeysMandatory": false,
  "users": [
    {
      "sub": "00000000-0000-0000-0000-000000000001",
      "name": "Alice Example",
      "email": "alice@example.test",
      "preferred_username": "alice@example.test",
      "roles": ["Admin"]
    }
  ]
}
```

Passwords are stored separately in `passwd` next to `config.json`. Each non-comment line is:

```text
tenantId:userSub:pbkdf2-sha256$iterations$salt$hash
```

Example:

```text
common:00000000-0000-0000-0000-000000000001:pbkdf2-sha256$310000$SALT$HASH
```

For local file-based setup, generate a compatible hash after building the project:

```bash
node -e 'import("./dist/oidc/passwords.js").then(({createPasswordHash}) => console.log(createPasswordHash(process.argv[1])))' 'change-me'
```

Then append the full record to the `passwd` file:

```text
common:00000000-0000-0000-0000-000000000001:PASTE_HASH_HERE
```

When `"enableSessions": true`, a successful login stores a tenant-scoped HTTP-only cookie so the next authorize request can proceed without entering the password again. `GET /{tenantId}/oauth2/v2.0/logout` clears that cookie. Set `"enableSessions": false` to require the password for every interactive login.

Use `sessionLifetimeSeconds` on the tenant to control how long the login-session cookie is valid. The default is `28800` seconds, which is 8 hours.

### Two-Factor Login

Set `twoFactorEnabled` on a tenant to offer TOTP-based authenticator setup after the primary login. If the user has not enrolled yet, the login page lets them either set up 2FA or continue without it.

Set `twoFactorMandatory` to require setup before the login can finish. Mandatory mode also implies `twoFactorEnabled` when the admin UI saves the config.

```json
{
  "tenantId": "common",
  "secure": true,
  "twoFactorEnabled": true,
  "twoFactorMandatory": true
}
```

Enrollments are stored in `mfa.json` next to the active config file, so they survive restarts when that config directory is persisted. The admin UI can reset a user's 2FA enrollment from the user editor.

### Passkey Login

Set `passkeysEnabled` on a secure tenant to offer browser passkey setup after a successful password login. After the user enrolls, the login page shows a `Use passkey` button that can complete the authorize request without entering the password.

Set `passkeysMandatory` to require passkey setup before the login can finish. Mandatory mode also implies `passkeysEnabled` when the admin UI saves the config.

```json
{
  "tenantId": "common",
  "secure": true,
  "passkeysEnabled": true,
  "passkeysMandatory": false
}
```

Passkey credentials are stored in `passkeys.json` next to the active config file, so they survive restarts when that config directory is persisted. The admin UI can reset a user's passkeys from the user editor. WebAuthn binds passkeys to the browser origin, so `baseUrl` must match the URL users open in the browser.

Session cookies are signed. By default, the server creates a random secret in a `session-secret` file next to the active config, so cookies remain valid across restarts for their configured lifetime. Keep this file with the config data. The config directory must be writable when the file is first created.

For Docker Swarm or any multi-replica deployment, set `OIDC_MOCK_SESSION_SECRET` to the same strong value for every replica:

```bash
OIDC_MOCK_SESSION_SECRET='change-this-long-random-session-secret'
```

When `OIDC_MOCK_SESSION_SECRET` is set, it takes precedence over the local secret file. A per-process secret is still used by applications that embed `createApp()` directly without passing a secret.

For Docker Swarm or other deployments where the config directory is mounted into the service, set an admin token:

```bash
OIDC_MOCK_ADMIN_TOKEN='change-this-admin-token'
```

Then set or rotate a password through the running service:

```bash
curl -sS -X POST http://localhost:3000/common/internal/passwords \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer change-this-admin-token' \
  -d '{"username":"alice@example.test","password":"new-password"}'
```

You can identify the user by `username` using either `email` or `preferred_username`, or by `user_sub`:

```bash
curl -sS -X POST http://localhost:3000/common/internal/passwords \
  -H 'content-type: application/json' \
  -H 'x-admin-token: change-this-admin-token' \
  -d '{"user_sub":"00000000-0000-0000-0000-000000000001","password":"new-password"}'
```

Remove a password entry:

```bash
curl -sS -X DELETE http://localhost:3000/common/internal/passwords \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer change-this-admin-token' \
  -d '{"username":"alice@example.test"}'
```

The password-management endpoints return `401` unless `OIDC_MOCK_ADMIN_TOKEN` is configured and the request passes the matching bearer token or `x-admin-token` header.

For rotation API authentication, allowlist setup, endpoint examples, and storage details, see [Client Secret Rotation API — Manager Handoff](docs/client-secret-rotation.md).

## Device-Bound Sessions

Tenant devices model the machine or service host that performed the original login. This lets the mock reproduce the Azure behavior where a refresh token stops working after the original device is no longer active in the tenant.

Configure devices on a tenant:

```json
{
  "tenantId": "common",
  "displayName": "Default Tenant",
  "devices": [
    {
      "deviceId": "machine-1",
      "displayName": "Build Agent 1",
      "enabled": true
    }
  ]
}
```

Bind a login to that device by adding `device_id` to the authorize request:

```text
http://localhost:3000/common/oauth2/v2.0/authorize?response_type=code&client_id=local-app&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fauth%2Fcallback&scope=openid%20profile%20email%20offline_access&device_id=machine-1
```

The device ID is stored with the authorization code and refresh token. Issued access tokens include it as the `deviceid` claim.

To simulate the machine being deactivated, update the tenant config while the server is running:

```json
{
  "deviceId": "machine-1",
  "displayName": "Build Agent 1",
  "enabled": false
}
```

After config reload:

- refresh-token renewal returns `invalid_grant`
- internal access-token verification returns `401` with `active: false`
- new authorization requests using that `device_id` are rejected

## Internal Token Verification

Mocked downstream Azure services can ask the OIDC mock to verify access tokens they receive:

```bash
curl -sS -X POST http://localhost:3000/common/internal/token/verify \
  -H 'content-type: application/json' \
  -H "authorization: Bearer PASTE_ACCESS_TOKEN_HERE" \
  -d '{"audience":"local-app"}'
```

The endpoint accepts the access token from `Authorization: Bearer ...`, JSON/form `token`, or JSON/form `access_token`. Pass `audience` or `client_id` to enforce the expected token audience. A valid token returns `200` with `active: true` and the verified claims. Invalid tokens return `401` with `active: false`.

The verifier uses the current in-memory config, so tokens are rejected after their client is removed or set to `"enabled": false`. Disabled clients also cannot start new auth flows or exchange refresh tokens. Device-bound tokens are rejected when their `deviceid` points to a removed or disabled tenant device.

## Config

See [config.example.json](config.example.json).
