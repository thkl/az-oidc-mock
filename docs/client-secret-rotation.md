# Client Secret Rotation API — Manager Handoff

**Status: Mixed.** The app supports named client secrets in configuration and token authentication. The external rotation API described here is still a proposed design. This document defines its intended setup and request flow for the team building the manager and server-side API.

## Goal and scope

Let an external credential manager create and rotate multiple independent client secrets for one OAuth client registration. A manager can assign short names such as `test` and `prod`, keep each value in its own vault entry, and rotate one name without interrupting the others.

The `client_id` remains the OAuth client identifier. A secret name is management metadata used by the rotation API; it is not sent to the OAuth token endpoint. Token authentication continues to use the client ID and presented secret.

The configuration supports a legacy optional `clientSecret` and a `clientSecrets` array. Token authentication accepts the legacy value or any named value. Existing `clientSecret` values remain valid while clients migrate to named slots such as `default`, `test`, and `prod`.

## Configure named secrets now

Add a `clientSecrets` array to a client in `config.json`:

```json
{
  "clientId": "orders-api",
  "clientSecrets": [
    { "name": "test", "secret": "<test-secret>" },
    { "name": "prod", "secret": "<prod-secret>" }
  ],
  "redirectUris": ["https://orders.example.test/callback"],
  "allowedScopes": ["openid", "profile"],
  "enabled": true
}
```

Names are case-insensitive and normalized to lowercase. They may contain letters, digits, `-`, and `_`, must start with a letter or digit, and may be up to 32 characters. A client may have up to 20 named secrets. Names and values must be unique within that client. Existing clients with only `clientSecret` continue to work.

The token endpoint does not receive the name; it matches the supplied `client_secret` against the client's configured values. The admin UI can view and edit named values in the client editor's JSON field. It masks saved values in API responses and restores unchanged masked values on save. The config file itself currently stores those values as plaintext, so protect its filesystem permissions and backups. The rotation API below will provide a manager-driven lifecycle without exposing values through config reads.

## Recommended setup

1. **Create or select a confidential client** in the target tenant. Record its tenant ID and client ID in the manager. Keep redirect URIs, scopes, and enabled state under the existing client configuration flow.
2. **Define a credential name per consumer environment**, for example `test` and `prod`. Names must be unique within a client, case-insensitive, and limited to a short safe set such as lowercase letters, digits, hyphens, and underscores. A name should identify the owning environment or workload, not contain a secret.
3. **Configure machine authentication for the manager.** Prefer mTLS or `private_key_jwt`, with authorization mapped to explicit tenant/client pairs. A simpler first deployment may use a dedicated high-entropy bearer token and an explicit allowlist. Do not use `OIDC_MOCK_ADMIN_TOKEN` or the client secret being rotated as the manager credential.
4. **Configure the manager's vault mapping** from `(tenant ID, client ID, credential name)` to a secret-store path. The manager also needs the API base URL, its service identity, rotation schedule, and a stable idempotency-key strategy.
5. **Use HTTPS with certificate validation** for every manager-to-server request. Limit network access to the manager where the deployment allows it.

Use separate client IDs for environments when they need separate redirect URIs, scopes, or client-level audit boundaries. Named credentials allow independent secret lifecycle for environments that must share one client ID; they do not create separate OAuth client identities.

## Proposed API

All routes are tenant-scoped and require the manager's service authentication. Authorization must check the exact tenant, client, and credential name on every operation. The bearer header below is shorthand; mTLS or a `private_key_jwt`-authenticated service token is preferred.

### List credential metadata

```http
GET /internal/v1/tenants/{tenantId}/clients/{clientId}/secrets
Authorization: Bearer <manager-token>
```

Return names, secret version IDs, states, and timestamps only. Never return secret values from a list or read endpoint.

### Create a named credential

```http
POST /internal/v1/tenants/{tenantId}/clients/{clientId}/secrets
Authorization: Bearer <manager-token>
Idempotency-Key: <unique-operation-id>
Content-Type: application/json

{"name":"prod"}
```

The server generates a 32-byte cryptographically random secret, encoded as base64url. It creates the credential in `pending` state and returns the secret once:

```json
{
  "rotation_id": "rot_...",
  "tenant_id": "common",
  "client_id": "orders-api",
  "name": "prod",
  "secret_version": "sv_...",
  "client_secret": "<shown once>",
  "state": "pending",
  "pending_expires_at": "<RFC3339 timestamp>"
}
```

### Rotate one named credential

```http
POST /internal/v1/tenants/{tenantId}/clients/{clientId}/secrets/{name}/rotations
Authorization: Bearer <manager-token>
Idempotency-Key: <unique-operation-id>
```

This creates a new pending version for that name. The previous version stays accepted while the operation is pending. Creating or rotating `prod` has no effect on `test`.

### Activate a pending version

```http
POST /internal/v1/tenants/{tenantId}/clients/{clientId}/secrets/{name}/rotations/{rotationId}/activate
Authorization: Bearer <manager-token>
```

The manager calls this only after it has durably saved the new value in its secret store and updated the consuming workload. The new version becomes current. The old version remains accepted for a short, bounded grace period, then expires. A pending operation that is not activated before its expiry is discarded and leaves the existing current version active.

The server should allow only one pending rotation per credential name. Other names for the same client can rotate independently. A separate abort operation may discard a pending rotation early.

### Revoke a named credential

```http
DELETE /internal/v1/tenants/{tenantId}/clients/{clientId}/secrets/{name}
Authorization: Bearer <manager-token>
```

Revocation immediately rejects all versions for that name, including pending and grace-period versions. The server must prevent this operation from leaving a confidential client with no required credential. The audit record should identify the revoked version IDs and the manager identity, never the secret values.

### Response and error behavior

- Secret-creating responses use `Cache-Control: no-store` and `Pragma: no-cache`.
- Repeating a request with the same idempotency key returns the same operation, never creates another rotation. To safely recover a lost response, keep the pending secret encrypted and recoverable only until activation or pending expiry; delete that ciphertext afterward.
- Invalid or missing manager credentials return `401`. A manager outside its tenant/client/name allowlist receives `403`. Unknown resources return `404`; conflicting pending work returns `409`; expired operations return `410`.
- A storage failure must leave the previous secret valid and return `503`.

## Manager rotation flow

1. The manager selects one `(tenant, client, name)` slot and creates a unique idempotency key.
2. It requests creation or rotation. The server checks service authorization, generates the secret, and stores a pending credential while leaving the current credential valid.
3. The manager writes the returned value to the corresponding vault path. It must not put the secret in job names, logs, traces, command-line arguments, or ticket comments.
4. The manager updates the workload that uses that environment's credential and waits for its secret refresh/reload to complete.
5. The manager activates the rotation. The server promotes the pending version and starts the old version's bounded grace period.
6. After grace expires, the old version is rejected. The manager records the completed rotation ID and timestamp, but never stores the plaintext in its own logs or rotation history.

If steps 3 or 4 fail, the manager leaves the operation pending or aborts it. The old value remains usable. Retries use the same idempotency key.

The current mock supports `authorization_code` and `refresh_token` grants; it does not support `client_credentials`. Manager implementations must not assume they can validate the new secret with a client-credentials token request. If independent proof of rollout is required, add an explicit verification operation or verify through the actual consumer's supported flow before activation.

## Server-side credential model and safeguards

Each client should have independent named records. A record needs a normalized name, opaque secret-version ID, credential verifier, creation/activation timestamps, and lifecycle state. During rotation, the record also tracks the pending version and the previous version's expiry.

Client authentication at the token endpoint must accept a presented secret if it matches a current, pending, or not-yet-expired previous verifier for that client. It should compare verifiers safely and update usage metadata without logging the credential. Secret names are not part of token requests. Reject duplicate secret values across names so usage attribution remains unambiguous.

Prefer storing verifiers for the long-lived values rather than plaintext. Since generated secrets have high entropy, a keyed HMAC verifier with a separately protected server key is suitable; short-lived encrypted storage is needed only for retrying a pending response. Never log raw secrets, authorization headers, or request bodies for these routes. Audit the manager identity, tenant, client, name, operation ID, version ID, state transition, and result.

Credential changes must persist atomically and become visible to all server instances before the API reports success. In this repository, `clientSecret` is currently stored directly in the config JSON, and `saveConfig()` writes that file atomically. A multi-replica deployment needs shared durable credential state or a coordinated config store; separate per-instance files would let instances disagree about which secrets are valid.

## References

- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html) recommends asymmetric client authentication such as mutual TLS or `private_key_jwt` when feasible.
- [RFC 7592: OAuth 2.0 Dynamic Client Registration Management](https://datatracker.ietf.org/doc/html/rfc7592) describes a TLS-protected client configuration endpoint authenticated by a registration access token. It is relevant when clients manage their own registration; this proposal is a central manager operating on explicitly authorized tenant/client pairs.
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) discusses lifecycle, rotation, and revocation practices for application secrets.
