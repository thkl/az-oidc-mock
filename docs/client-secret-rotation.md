# Client Secret Rotation API — Manager Handoff

**Status: Implemented.** Named secrets can be configured in `config.json` or managed through the rotation API. The manager proves possession of the target client's current credential to exchange it for a short-lived capability scoped to one named create or rotation.

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

The token endpoint does not receive the name; it matches the supplied `client_secret` against accepted values. The admin UI can create a named value in a dialog and displays names without their values afterward. Static values in `config.json` remain plaintext, so protect its filesystem permissions and backups. Values created by the rotation API are stored as verifiers and are never returned by list or config-read endpoints.

To remove the legacy single secret, clear the **Legacy Client Secret** field in the admin UI and save the configuration, or remove the `clientSecret` property from that client's config entry. Do this after a replacement named secret is current if the client must remain confidential. If no legacy or named secret remains, the client is treated as a public client. The rotation API will not let a manager revoke the last current named credential.

## Recommended setup

1. **Create or select a confidential client** in the target tenant. Record its tenant ID and client ID in the manager. Keep redirect URIs, scopes, and enabled state under the existing client configuration flow.
2. **Define a credential name per consumer environment**, for example `test` and `prod`. Names must be unique within a client, case-insensitive, and limited to a short safe set such as lowercase letters, digits, hyphens, and underscores. A name should identify the owning environment or workload, not contain a secret.
3. **Configure client-scoped authentication.** The manager authenticates as the target client using its current legacy or named client secret, then exchanges that credential for a short-lived rotation capability. An exact tenant/client/name allowlist also restricts which slots can be managed. The global `OIDC_MOCK_ROTATION_API_TOKEN` is no longer accepted. mTLS and `private_key_jwt` are not implemented by these routes.
4. **Configure the manager's vault mapping** from `(tenant ID, client ID, credential name)` to a secret-store path. The manager also needs the API base URL, an audit label, a rotation schedule, and a stable idempotency-key strategy.
5. **Use HTTPS with certificate validation** between the manager and the public endpoint. With a reverse proxy such as Traefik, TLS can terminate at the proxy; its hop to the app can use HTTP on a trusted private network, or HTTPS if that network is not trusted. Keep the app port private and do not send credentialed manager requests to a plaintext HTTP endpoint.

The app does not enforce HTTPS itself or validate `X-Forwarded-Proto`. The deployment must ensure that managers reach the API through the HTTPS proxy and cannot reach the app directly over a public plaintext port. A redirect from HTTP is not enough for requests carrying credentials, because those credentials would already have crossed the network in plaintext.

Use separate client IDs for environments when they need separate redirect URIs, scopes, or client-level audit boundaries. Named credentials allow independent secret lifecycle for environments that must share one client ID; they do not create separate OAuth client identities.

The allowlist is JSON in `OIDC_MOCK_ROTATION_ALLOWLIST`. Names are case-insensitive and must be listed individually; the list endpoint returns only allowed names. For example:

```json
[
  { "tenantId": "common", "clientId": "orders-api", "names": ["test", "prod"] }
]
```

Set `OIDC_MOCK_ROTATION_MANAGER_ID` to an audit label for the manager process. If it is unset, logs use `configured-secret-manager`; client authentication is still recorded separately. The rotation state and key are stored beside the active config as `client-secret-rotations.json` and `client-secret-rotation.key`; both files are restricted to owner read/write permissions. Keep both files on persistent storage. If the rotation state exists but its key is missing, the server refuses to start rather than invalidating managed credentials silently.

### Exchange client credentials for a rotation capability

The manager uses the target client's current credential with HTTP Basic authentication. Only a current legacy or named secret can log in; a previous grace-period value cannot mint a capability. The request also names the one allowed credential slot and operation:

```http
POST /internal/v1/tenants/common/clients/orders-api/rotation-tokens
Authorization: Basic base64(orders-api:<current-client-secret>)
Content-Type: application/json

{"name":"prod","operation":"rotate"}
```

The response contains an opaque bearer capability that expires after five minutes unless it starts a rotation first:

```json
{
  "access_token": "rct_...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": { "tenant_id": "common", "client_id": "orders-api", "name": "prod", "operation": "rotate" }
}
```

The capability can start exactly one create or rotation for that tenant, client, name, and operation. Once started, the same token can activate only that rotation; its lifetime extends to the pending rotation's expiry. It cannot list credentials, delete credentials, change another name, or start a second rotation. The server stores only a keyed verifier for this token. Store it in memory only as long as needed and never log it. All manager calls require HTTPS.

List and delete requests authenticate with the target client's current credential via HTTP Basic. The capability token is reserved for the one create/rotation flow.

## API

All routes are tenant-scoped and check the exact tenant, client, and credential name against the allowlist. Token exchange, list, and delete calls use the target client's current credential via HTTP Basic. Create, rotate, and activate calls use the scoped capability returned by the token exchange. mTLS and `private_key_jwt` are not implemented by these routes.

### List credential metadata

```http
GET /internal/v1/tenants/{tenantId}/clients/{clientId}/secrets
Authorization: Basic base64({clientId}:<current-client-secret>)
```

Return names and version metadata only. Version metadata includes the ID, state, creation/activation/expiry times, and optional last-use time. Never return secret values from a list or read endpoint. The response is `Cache-Control: no-store`.

### Create a named credential

```http
POST /internal/v1/tenants/{tenantId}/clients/{clientId}/secrets
Authorization: Bearer <rotation-capability>
Idempotency-Key: <unique-operation-id>
Content-Type: application/json

{"name":"prod"}
```

The server generates a 32-byte cryptographically random secret, encoded as base64url. It creates the credential in `pending` state for 15 minutes and returns the secret once. If the name already exists, use the rotation endpoint instead:

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
Authorization: Bearer <rotation-capability>
Idempotency-Key: <unique-operation-id>
```

This creates a new pending version for that name. The previous version stays accepted while the operation is pending. Creating or rotating `prod` has no effect on `test`.

### Activate a pending version

```http
POST /internal/v1/tenants/{tenantId}/clients/{clientId}/secrets/{name}/rotations/{rotationId}/activate
Authorization: Bearer <same-rotation-capability>
```

The manager calls this only after it has durably saved the new value in its secret store and updated the consuming workload. The new version becomes current. The old version remains accepted for a five-minute grace period, then expires. A pending operation that is not activated before its expiry is discarded and leaves the existing current version active.

The server allows only one pending rotation per credential name. Other names for the same client can rotate independently. There is no separate abort endpoint; `DELETE` revokes all versions for a name.

### Revoke a named credential

```http
DELETE /internal/v1/tenants/{tenantId}/clients/{clientId}/secrets/{name}
Authorization: Basic base64({clientId}:<current-client-secret>)
```

Revocation immediately rejects all versions for that name, including pending and grace-period versions, and returns `204`. The server refuses to revoke the client's last current credential; a legacy `clientSecret` or another named current value satisfies this requirement. The audit record identifies the revoked version IDs and manager identity, never the secret values.

### Response and error behavior

- Secret-management responses use `Cache-Control: no-store` and `Pragma: no-cache`.
- Repeating a request with the same idempotency key returns the same operation, never creates another rotation. To safely recover a lost response, keep the pending secret encrypted and recoverable only until activation or pending expiry; delete that ciphertext afterward.
- Invalid or missing client credentials or rotation capabilities return `401`. A client outside its tenant/client/name allowlist or a capability used outside its scope receives `403`. Unknown resources return `404`; conflicting pending work or reuse for another operation returns `409`; expired operations or capabilities return `410`.
- A storage failure must leave the previous secret valid and return `503`.
- A first create or new rotation returns `201`; an idempotent replay returns `200`; activation returns `200`.

## Manager rotation flow

1. The manager selects one `(tenant, client, name)` slot and creates a unique idempotency key.
2. It authenticates with the target client's current credential and exchanges it for a capability scoped to that slot and either `create` or `rotate`.
3. It starts the operation using that capability. The server generates the secret and stores a pending credential while leaving the current credential valid.
4. The manager writes the returned value to the corresponding vault path. It must not put the secret in job names, logs, traces, command-line arguments, or ticket comments.
5. The manager updates the workload that uses that environment's credential and waits for its secret refresh/reload to complete.
6. The manager activates the rotation with the same capability. The server promotes the pending version and starts the old version's bounded grace period.
7. After grace expires, the old version is rejected. The manager records the completed rotation ID and timestamp, but never stores the plaintext in its own logs or rotation history.

If storing the new value or updating the workload fails, do not activate the operation. The current value remains usable until the pending operation expires. Retries use the same capability and idempotency key.

The current mock supports `authorization_code` and `refresh_token` grants; it does not support `client_credentials`. Manager implementations must not assume they can validate the new secret with a client-credentials token request. If independent proof of rollout is required, add an explicit verification operation or verify through the actual consumer's supported flow before activation.

## Server-side credential model and safeguards

Each client should have independent named records. A record needs a normalized name, opaque secret-version ID, credential verifier, creation/activation timestamps, and lifecycle state. During rotation, the record also tracks the pending version and the previous version's expiry.

Client authentication at the token endpoint must accept a presented secret if it matches a current, pending, or not-yet-expired previous verifier for that client. It should compare verifiers safely and update usage metadata without logging the credential. Secret names are not part of token requests. Reject duplicate secret values across names so usage attribution remains unambiguous.

Long-lived values are stored as keyed HMAC verifiers. The HMAC key is separately generated and stored in `client-secret-rotation.key`; the pending response value is encrypted with AES-GCM and discarded on activation or expiry. Static values already in `config.json` remain plaintext as before, and are imported into the rotation store as verifiers when first encountered. Once a name is managed by this API, the rotation store controls its accepted values. Never log raw secrets, authorization headers, or request bodies for these routes. Audit the manager identity, tenant, client, name, operation ID, version ID, state transition, and result.

Credential changes must persist atomically and become visible to all server instances before the API reports success. In this repository, `clientSecret` is currently stored directly in the config JSON, and `saveConfig()` writes that file atomically. A multi-replica deployment needs shared durable credential state or a coordinated config store; separate per-instance files would let instances disagree about which secrets are valid.

## References

- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html) recommends asymmetric client authentication such as mutual TLS or `private_key_jwt` when feasible.
- [RFC 7592: OAuth 2.0 Dynamic Client Registration Management](https://datatracker.ietf.org/doc/html/rfc7592) describes a TLS-protected client configuration endpoint authenticated by a registration access token. It is relevant when clients manage their own registration; this proposal is a central manager operating on explicitly authorized tenant/client pairs.
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) discusses lifecycle, rotation, and revocation practices for application secrets.
