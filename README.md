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
GET  http://localhost:3000/common/oauth2/v2.0/logout
POST http://localhost:3000/common/internal/token/verify
```

The issuer is:

```text
http://localhost:3000/common/v2.0
```

For MSAL, use `http://localhost:3000/common` as the authority when the library appends the v2.0 discovery path itself. For non-Azure custom-authority mode, configure MSAL with the local authority as known/trusted according to the MSAL client you use.

## Authorization Code Flow

Open this in a browser:

```text
http://localhost:3000/common/oauth2/v2.0/authorize?response_type=code&client_id=local-app&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fauth%2Fcallback&scope=openid%20profile%20email%20offline_access&state=abc&nonce=xyz&device_id=machine-1
```

The mock login screen shows users from the selected tenant. Choosing one redirects to the configured callback with `code` and `state`.

Pass `device_id=machine-1` on the authorize request to bind the login to a configured tenant device. If a tenant has devices and no `device_id` is passed, the first enabled device is used.

Exchange the code:

```bash
curl -sS -X POST http://localhost:3000/common/oauth2/v2.0/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'client_id=local-app' \
  -d 'client_secret=local-secret' \
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
  -d 'client_secret=local-secret' \
  -d 'refresh_token=PASTE_REFRESH_TOKEN_HERE'
```

If `rotateRefreshTokens` is `true`, the old refresh token is invalidated and a new one is returned.

Refresh tokens are stored in `refresh-tokens.json` next to the active config file, so renewal continues to work after restarting the mock as long as that config directory is persisted.

Refresh-token renewal also checks the device that was used for the original login. If that device is later removed from config or set to `"enabled": false`, renewal fails with `invalid_grant`.

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
