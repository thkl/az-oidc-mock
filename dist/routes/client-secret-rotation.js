import { ClientSecretRotationError } from "../oidc/client-secret-rotation.js";
import { findClient, findTenant } from "../oidc/validation.js";
import { readBearerToken, readObjectBody, readParamString, readString } from "./http.js";
const NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/;
/**
 * Registers tenant-scoped client authentication and named-secret rotation routes.
 */
export function registerClientSecretRotationRoutes(app, context) {
    app.post("/internal/v1/tenants/:tenantId/clients/:clientId/rotation-tokens", (req, res) => {
        setNoStoreHeaders(res);
        const tenantId = readParamString(req.params.tenantId);
        const clientId = readParamString(req.params.clientId);
        if (!tenantId || !clientId)
            return notFound(res);
        const body = readObjectBody(req);
        const name = normalizeName(readString(body.name));
        const kind = readString(body.operation);
        if (!name)
            return invalidRequest(res, "name must be 1–32 letters, numbers, hyphens, or underscores and start with a letter or number");
        if (kind !== "create" && kind !== "rotate")
            return invalidRequest(res, "operation must be create or rotate");
        if (!isAllowed(context.rotationApiAllowlist ?? [], tenantId, clientId, name))
            return forbidden(res);
        const config = context.getConfig();
        const store = synchronizeStore(context, res, { tenantId, clientId, name });
        if (!store)
            return;
        const target = findTarget(config, tenantId, clientId);
        if (!target)
            return notFound(res);
        const credentials = readBasicClientCredentials(req);
        if (!target.client.enabled || !credentials || credentials.clientId !== clientId) {
            return unauthorized(res, "Current client credentials are required");
        }
        try {
            if (!store.verifyCurrentClientSecret(tenantId, target.client, credentials.clientSecret)) {
                return unauthorized(res, "Current client credentials are required");
            }
            const capability = store.issueRotationCapability({ tenantId, clientId, name, kind });
            const managerId = context.rotationManagerId || `client:${clientId}`;
            context.logger.info("client secret rotation token issued", {
                managerId,
                authenticatedClientId: clientId,
                tenantId,
                clientId,
                name,
                operation: kind,
                expiresAt: new Date(capability.expiresAt).toISOString()
            });
            res.status(201).json({
                access_token: capability.accessToken,
                token_type: "Bearer",
                expires_in: Math.max(0, Math.ceil((capability.expiresAt - Date.now()) / 1000)),
                scope: { tenant_id: tenantId, client_id: clientId, name, operation: kind }
            });
        }
        catch (error) {
            handleStoreError(context, res, error, { tenantId, clientId, name });
        }
    });
    app.get("/internal/v1/tenants/:tenantId/clients/:clientId/secrets", (req, res) => {
        setNoStoreHeaders(res);
        const tenantId = readParamString(req.params.tenantId);
        const clientId = readParamString(req.params.clientId);
        if (!tenantId || !clientId)
            return notFound(res);
        const permissions = permissionsFor(context.rotationApiAllowlist ?? [], tenantId, clientId);
        if (!permissions.length)
            return forbidden(res);
        const config = context.getConfig();
        const store = synchronizeStore(context, res, { tenantId, clientId });
        if (!store)
            return;
        const target = findTarget(config, tenantId, clientId);
        if (!target)
            return notFound(res);
        try {
            if (!authenticateClient(req, tenantId, clientId, target.client, store)) {
                return unauthorized(res, "Current client credentials are required");
            }
            const allowedNames = new Set(permissions.flatMap((permission) => permission.names));
            const secrets = store
                .listClient(tenantId, target.client)
                .filter((credential) => allowedNames.has(credential.name));
            res.json({ tenant_id: tenantId, client_id: clientId, secrets });
        }
        catch (error) {
            handleStoreError(context, res, error, { tenantId, clientId });
        }
    });
    app.post("/internal/v1/tenants/:tenantId/clients/:clientId/secrets", (req, res) => {
        setNoStoreHeaders(res);
        const tenantId = readParamString(req.params.tenantId);
        const clientId = readParamString(req.params.clientId);
        if (!tenantId || !clientId)
            return notFound(res);
        const body = readObjectBody(req);
        const name = normalizeName(readString(body.name));
        if (!name)
            return invalidRequest(res, "name must be 1–32 letters, numbers, hyphens, or underscores and start with a letter or number");
        if (!isAllowed(context.rotationApiAllowlist ?? [], tenantId, clientId, name))
            return forbidden(res);
        return startRotation(context, req, res, { tenantId, clientId, name, kind: "create" });
    });
    app.post("/internal/v1/tenants/:tenantId/clients/:clientId/secrets/:name/rotations", (req, res) => {
        setNoStoreHeaders(res);
        const tenantId = readParamString(req.params.tenantId);
        const clientId = readParamString(req.params.clientId);
        const name = normalizeName(readParamString(req.params.name));
        if (!tenantId || !clientId)
            return notFound(res);
        if (!name)
            return invalidRequest(res, "Credential name is invalid");
        if (!isAllowed(context.rotationApiAllowlist ?? [], tenantId, clientId, name))
            return forbidden(res);
        return startRotation(context, req, res, { tenantId, clientId, name, kind: "rotate" });
    });
    app.post("/internal/v1/tenants/:tenantId/clients/:clientId/secrets/:name/rotations/:rotationId/activate", (req, res) => {
        setNoStoreHeaders(res);
        const tenantId = readParamString(req.params.tenantId);
        const clientId = readParamString(req.params.clientId);
        const name = normalizeName(readParamString(req.params.name));
        const rotationId = readParamString(req.params.rotationId);
        if (!tenantId || !clientId)
            return notFound(res);
        if (!name)
            return invalidRequest(res, "Credential name is invalid");
        if (!isAllowed(context.rotationApiAllowlist ?? [], tenantId, clientId, name))
            return forbidden(res);
        if (!rotationId)
            return invalidRequest(res, "Rotation ID is required");
        const store = synchronizeStore(context, res, { tenantId, clientId, name });
        if (!store)
            return;
        const accessToken = readBearerToken(req);
        if (!accessToken)
            return unauthorized(res, "Rotation capability token is required");
        try {
            store.authorizeRotationCapability({
                accessToken,
                tenantId,
                clientId,
                name,
                step: "activate",
                rotationId
            });
            const activated = store.activate({ tenantId, clientId, name, rotationId });
            store.completeRotationCapability({ accessToken, rotationId });
            context.logger.info("client secret rotation activated", {
                managerId: context.rotationManagerId || `client:${clientId}`,
                authenticatedClientId: clientId,
                tenantId,
                clientId,
                name,
                operationId: activated.rotationId,
                versionId: activated.secretVersion,
                state: activated.state,
                replayed: activated.replayed
            });
            res.json({
                rotation_id: activated.rotationId,
                tenant_id: activated.tenantId,
                client_id: activated.clientId,
                name: activated.name,
                secret_version: activated.secretVersion,
                state: activated.state,
                ...(activated.activatedAt !== undefined ? { activated_at: new Date(activated.activatedAt).toISOString() } : {}),
                ...(activated.previousSecretGraceExpiresAt !== undefined
                    ? { previous_secret_grace_expires_at: new Date(activated.previousSecretGraceExpiresAt).toISOString() }
                    : {})
            });
        }
        catch (error) {
            handleStoreError(context, res, error, { tenantId, clientId, name, rotationId });
        }
    });
    app.delete("/internal/v1/tenants/:tenantId/clients/:clientId/secrets/:name", (req, res) => {
        setNoStoreHeaders(res);
        const tenantId = readParamString(req.params.tenantId);
        const clientId = readParamString(req.params.clientId);
        const name = normalizeName(readParamString(req.params.name));
        if (!tenantId || !clientId)
            return notFound(res);
        if (!name)
            return invalidRequest(res, "Credential name is invalid");
        if (!isAllowed(context.rotationApiAllowlist ?? [], tenantId, clientId, name))
            return forbidden(res);
        const config = context.getConfig();
        const store = synchronizeStore(context, res, { tenantId, clientId, name });
        if (!store)
            return;
        const target = findTarget(config, tenantId, clientId);
        if (!target)
            return notFound(res);
        try {
            if (!authenticateClient(req, tenantId, clientId, target.client, store)) {
                return unauthorized(res, "Current client credentials are required");
            }
            const revoked = store.revoke({ tenantId, client: target.client, name });
            context.logger.info("client secret rotation revoked", {
                managerId: context.rotationManagerId || `client:${clientId}`,
                authenticatedClientId: clientId,
                tenantId,
                clientId,
                name,
                versionIds: revoked.revokedVersionIds,
                result: revoked.alreadyRevoked ? "already_revoked" : "revoked"
            });
            res.status(204).end();
        }
        catch (error) {
            handleStoreError(context, res, error, { tenantId, clientId, name });
        }
    });
}
function startRotation(context, req, res, scope) {
    const idempotencyKey = readIdempotencyKey(req);
    if (!idempotencyKey)
        return invalidRequest(res, "A valid Idempotency-Key header is required");
    const store = synchronizeStore(context, res, scope);
    if (!store)
        return;
    const target = findTarget(context.getConfig(), scope.tenantId, scope.clientId);
    if (!target)
        return notFound(res);
    if (!target.client.enabled)
        return forbidden(res);
    const accessToken = readBearerToken(req);
    if (!accessToken)
        return unauthorized(res, "Rotation capability token is required");
    try {
        store.authorizeRotationCapability({ ...scope, accessToken, step: "start", idempotencyKey });
        const issue = store.issuePending({
            kind: scope.kind,
            tenantId: scope.tenantId,
            client: target.client,
            name: scope.name,
            idempotencyKey,
            capabilityToken: accessToken
        });
        store.bindRotationCapability({
            accessToken,
            idempotencyKey,
            rotationId: issue.rotationId,
            pendingExpiresAt: issue.pendingExpiresAt
        });
        context.logger.info("client secret rotation started", {
            managerId: context.rotationManagerId || `client:${scope.clientId}`,
            authenticatedClientId: scope.clientId,
            tenantId: scope.tenantId,
            clientId: scope.clientId,
            name: scope.name,
            operationId: issue.rotationId,
            versionId: issue.secretVersion,
            state: issue.state,
            replayed: issue.replayed
        });
        res.location(`/internal/v1/tenants/${encodeURIComponent(scope.tenantId)}/clients/${encodeURIComponent(scope.clientId)}/secrets/${encodeURIComponent(scope.name)}/rotations/${encodeURIComponent(issue.rotationId)}/activate`)
            .status(issue.replayed ? 200 : 201)
            .json({
            rotation_id: issue.rotationId,
            tenant_id: issue.tenantId,
            client_id: issue.clientId,
            name: issue.name,
            secret_version: issue.secretVersion,
            ...(issue.clientSecret ? { client_secret: issue.clientSecret } : {}),
            state: issue.state,
            created_at: new Date(issue.createdAt).toISOString(),
            pending_expires_at: new Date(issue.pendingExpiresAt).toISOString()
        });
    }
    catch (error) {
        handleStoreError(context, res, error, scope);
    }
}
function authenticateClient(req, tenantId, clientId, client, store) {
    if (!client.enabled)
        return false;
    const credentials = readBasicClientCredentials(req);
    return Boolean(credentials && credentials.clientId === clientId &&
        store.verifyCurrentClientSecret(tenantId, client, credentials.clientSecret));
}
function readBasicClientCredentials(req) {
    const header = req.header("authorization");
    if (!header?.startsWith("Basic "))
        return undefined;
    const encoded = header.slice("Basic ".length);
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))
        return undefined;
    const decoded = Buffer.from(encoded, "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator < 1)
        return undefined;
    return { clientId: decoded.slice(0, separator), clientSecret: decoded.slice(separator + 1) };
}
function synchronizeStore(context, res, audit) {
    const store = context.clientSecretRotationStore;
    if (!store) {
        storeUnavailable(res);
        return undefined;
    }
    try {
        store.synchronizeConfig(context.getConfig());
        return store;
    }
    catch (error) {
        handleStoreError(context, res, error, audit);
        return undefined;
    }
}
function permissionsFor(allowlist, tenantId, clientId) {
    return allowlist.filter((permission) => permission.tenantId === tenantId && permission.clientId === clientId);
}
function isAllowed(allowlist, tenantId, clientId, name) {
    return permissionsFor(allowlist, tenantId, clientId).some((permission) => permission.names.includes(name));
}
function findTarget(config, tenantId, clientId) {
    const tenant = findTenant(config, tenantId);
    const client = tenant && findClient(tenant, clientId);
    return client ? { client } : undefined;
}
function normalizeName(value) {
    const name = value?.trim().toLowerCase();
    return name && NAME_PATTERN.test(name) ? name : undefined;
}
function readIdempotencyKey(req) {
    const key = readString(req.header("idempotency-key"))?.trim();
    return key && /^[A-Za-z0-9._:-]{1,128}$/.test(key) ? key : undefined;
}
function setNoStoreHeaders(res) {
    res.set({ "Cache-Control": "no-store, no-cache, must-revalidate", Pragma: "no-cache" });
}
function unauthorized(res, description = "Client authentication is required") {
    res.status(401).json({ error: "unauthorized", error_description: description });
}
function forbidden(res) {
    res.status(403).json({ error: "forbidden", error_description: "Client is not allowed to access this tenant, client, or credential name" });
}
function notFound(res) {
    res.status(404).json({ error: "not_found", error_description: "Tenant, client, credential, or rotation was not found" });
}
function invalidRequest(res, description) {
    res.status(400).json({ error: "invalid_request", error_description: description });
}
function storeUnavailable(res) {
    res.status(503).json({ error: "rotation_store_unavailable", error_description: "Rotation storage is unavailable" });
}
function handleStoreError(context, res, error, audit) {
    if (error instanceof ClientSecretRotationError) {
        res.status(error.status).json({ error: error.code, error_description: error.message });
        return;
    }
    context.logger.error("client secret rotation storage operation failed", {
        ...audit,
        error: error instanceof Error ? error.message : "unknown error"
    });
    storeUnavailable(res);
}
