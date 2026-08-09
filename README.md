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

`config.json` is watched while the server is running. Valid changes are reloaded automatically for new requests. If a changed file is invalid JSON or fails schema validation, the server keeps using the last valid config and logs the reload error.

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
GET  http://localhost:3000/common/discovery/v2.0/keys
GET  http://localhost:3000/common/oauth2/v2.0/authorize
POST http://localhost:3000/common/oauth2/v2.0/token
GET  http://localhost:3000/common/oauth2/v2.0/logout
```

The issuer is:

```text
http://localhost:3000/common/v2.0
```

## Authorization Code Flow

Open this in a browser:

```text
http://localhost:3000/common/oauth2/v2.0/authorize?response_type=code&client_id=local-app&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fauth%2Fcallback&scope=openid%20profile%20email%20offline_access&state=abc&nonce=xyz
```

The mock login screen shows users from the selected tenant. Choosing one redirects to the configured callback with `code` and `state`.

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

## Config

See [config.example.json](config.example.json).
