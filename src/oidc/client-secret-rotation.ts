import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { AppConfig, MockClient } from "../config.js";
import { constantTimeEqual } from "./session.js";

const PENDING_LIFETIME_MS = 15 * 60 * 1000;
const PREVIOUS_SECRET_GRACE_MS = 5 * 60 * 1000;
const ROTATION_TOKEN_LIFETIME_MS = 5 * 60 * 1000;

export type ClientSecretRotationPermission = {
  tenantId: string;
  clientId: string;
  names: string[];
};

export type ClientSecretRotationVersionMetadata = {
  secret_version: string;
  secret_hint?: string;
  state: "pending" | "current" | "grace" | "expired" | "revoked";
  created_at: string;
  activated_at?: string;
  expires_at?: string;
  last_used_at?: string;
};

export type ClientSecretRotationCredentialMetadata = {
  name: string;
  source: "config" | "api";
  versions: ClientSecretRotationVersionMetadata[];
};

type SecretVersion = {
  versionId: string;
  verifier: string;
  secretHint?: string;
  state: ClientSecretRotationVersionMetadata["state"];
  createdAt: number;
  activatedAt?: number;
  lifetimeStartedAt?: number;
  expiresAt?: number;
  lastUsedAt?: number;
};

type CredentialRecord = {
  tenantId: string;
  clientId: string;
  name: string;
  source: "config" | "api";
  versions: SecretVersion[];
  lifetimeDaysApplied?: number;
  pendingRotationId?: string;
};

type EncryptedSecret = {
  nonce: string;
  ciphertext: string;
  tag: string;
};

type RotationOperation = {
  kind: "create" | "rotate";
  idempotencyKey: string;
  fingerprint: string;
  rotationId: string;
  tenantId: string;
  clientId: string;
  name: string;
  versionId: string;
  createdAt: number;
  pendingExpiresAt: number;
  status: "pending" | "activated" | "expired" | "revoked";
  encryptedSecret?: EncryptedSecret;
};

type RotationCapability = {
  verifier: string;
  tenantId: string;
  clientId: string;
  name: string;
  kind: "create" | "rotate";
  createdAt: number;
  expiresAt: number;
  status: "issued" | "pending" | "activated" | "expired" | "revoked";
  idempotencyKey?: string;
  rotationId?: string;
};

type RotationStoreData = {
  schemaVersion: 1;
  credentials: CredentialRecord[];
  operations: RotationOperation[];
  capabilities: RotationCapability[];
};

export type PendingRotationResult = {
  rotationId: string;
  tenantId: string;
  clientId: string;
  name: string;
  secretVersion: string;
  state: SecretVersion["state"];
  createdAt: number;
  pendingExpiresAt: number;
  clientSecret?: string;
  replayed: boolean;
};

export type ActivatedRotationResult = {
  rotationId: string;
  tenantId: string;
  clientId: string;
  name: string;
  secretVersion: string;
  state: SecretVersion["state"];
  activatedAt?: number;
  previousSecretGraceExpiresAt?: number;
  replayed: boolean;
};

export class ClientSecretRotationError extends Error {
  constructor(
    readonly status: 401 | 403 | 404 | 409 | 410,
    readonly code: string,
    message: string
  ) {
    super(message);
    this.name = "ClientSecretRotationError";
  }
}

/**
 * Persists verifier-only named credentials and encrypted, short-lived pending responses.
 */
export class ClientSecretRotationStore {
  private readonly verifierKey: Buffer;
  private readonly pendingEncryptionKey: Buffer;
  private lastConfigFingerprint = "";
  private data: RotationStoreData;

  constructor(private readonly storePath: string, masterKey: string) {
    const keyMaterial = Buffer.from(masterKey, "utf8");
    this.verifierKey = Buffer.from(crypto.hkdfSync(
      "sha256",
      keyMaterial,
      Buffer.from("az-oidc-mock-client-secret-rotation", "utf8"),
      Buffer.from("hmac-verifier", "utf8"),
      32
    ));
    this.pendingEncryptionKey = Buffer.from(crypto.hkdfSync(
      "sha256",
      keyMaterial,
      Buffer.from("az-oidc-mock-client-secret-rotation", "utf8"),
      Buffer.from("pending-response-aes-256-gcm", "utf8"),
      32
    ));
    this.data = this.readStore();
  }

  /**
   * Synchronizes static config secrets and permanently disables records for removed API clients.
   */
  synchronizeConfig(config: AppConfig, now = Date.now()): void {
    const configSnapshot = config.tenants.map((tenant) => ({
      tenantId: tenant.tenantId,
      clients: tenant.clients.map((client) => ({
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        clientSecrets: client.clientSecrets,
        clientSecretLifetimeDays: client.clientSecretLifetimeDays
      }))
    }));
    const fingerprint = crypto.createHash("sha256").update(JSON.stringify(configSnapshot)).digest("hex");
    if (fingerprint === this.lastConfigFingerprint) {
      return;
    }

    this.expire(now);
    const activeClientPairs = new Set(config.tenants.flatMap((tenant) =>
      tenant.clients.map((client) => `${tenant.tenantId}\u0000${client.clientId}`)
    ));
    for (const tenant of config.tenants) {
      for (const client of tenant.clients) {
        this.syncConfiguredClient(tenant.tenantId, client, now);
      }
    }

    const next = this.cloneData();
    let changed = false;
    for (const credential of next.credentials) {
      if (activeClientPairs.has(`${credential.tenantId}\u0000${credential.clientId}`)) {
        continue;
      }
      for (const version of credential.versions) {
        if (version.state !== "revoked" && credential.source === "api") {
          version.state = "revoked";
          changed = true;
        } else if (credential.source === "config" && (version.state === "current" || version.state === "grace" || version.state === "pending")) {
          version.state = "revoked";
          changed = true;
        }
      }
      if (credential.source === "api" && credential.pendingRotationId) {
        credential.pendingRotationId = undefined;
        changed = true;
      }
    }
    for (const operation of next.operations) {
      if (!activeClientPairs.has(`${operation.tenantId}\u0000${operation.clientId}`) && operation.status !== "revoked") {
        operation.status = "revoked";
        delete operation.encryptedSecret;
        changed = true;
      }
    }
    for (const capability of next.capabilities) {
      if (!activeClientPairs.has(`${capability.tenantId}\u0000${capability.clientId}`) && capability.status !== "revoked") {
        capability.status = "revoked";
        changed = true;
      }
    }
    if (changed) {
      this.commit(next);
    }
    this.lastConfigFingerprint = fingerprint;
  }

  /**
   * Returns metadata for all configured and API-managed named credentials.
   */
  listClient(
    tenantId: string,
    client: MockClient,
    now = Date.now()
  ): ClientSecretRotationCredentialMetadata[] {
    this.expire(now);
    this.syncConfiguredClient(tenantId, client, now);
    return this.data.credentials
      .filter((credential) => credential.tenantId === tenantId && credential.clientId === client.clientId)
      .sort((left, right) => left.name.localeCompare(right.name))
      .map((credential) => ({
        name: credential.name,
        source: credential.source,
        versions: credential.versions.map((version) => ({
          secret_version: version.versionId,
          ...(version.secretHint ? { secret_hint: version.secretHint } : {}),
          state: version.state === "current" && version.expiresAt !== undefined && version.expiresAt <= now
            ? "expired"
            : version.state,
          created_at: new Date(version.createdAt).toISOString(),
          ...(version.activatedAt !== undefined ? { activated_at: new Date(version.activatedAt).toISOString() } : {}),
          ...(version.expiresAt !== undefined ? { expires_at: new Date(version.expiresAt).toISOString() } : {}),
          ...(version.lastUsedAt !== undefined ? { last_used_at: new Date(version.lastUsedAt).toISOString() } : {})
        }))
      }));
  }

  /**
   * Creates a pending credential or rotation and supports safe idempotent recovery.
   */
  issuePending(input: {
    kind: "create" | "rotate";
    tenantId: string;
    client: MockClient;
    name: string;
    idempotencyKey: string;
    capabilityToken?: string;
    now?: number;
  }): PendingRotationResult {
    const now = input.now ?? Date.now();
    const clientId = input.client.clientId;
    const fingerprint = JSON.stringify([
      input.kind,
      input.tenantId,
      clientId,
      input.name,
      input.capabilityToken ? this.capabilityVerifier(input.capabilityToken) : undefined
    ]);
    this.expire(now);

    const previous = this.data.operations.find((operation) => operation.idempotencyKey === input.idempotencyKey);
    if (previous) {
      if (previous.fingerprint !== fingerprint) {
        throw new ClientSecretRotationError(409, "idempotency_key_conflict", "Idempotency key was already used for a different operation");
      }
      if (previous.status === "expired" || previous.status === "revoked") {
        throw new ClientSecretRotationError(410, "rotation_expired", "The pending rotation is no longer recoverable");
      }
      const version = this.findVersion(previous.tenantId, previous.clientId, previous.name, previous.versionId);
      if (!version) {
        throw new ClientSecretRotationError(410, "rotation_expired", "The pending rotation is no longer recoverable");
      }
      return {
        rotationId: previous.rotationId,
        tenantId: previous.tenantId,
        clientId: previous.clientId,
        name: previous.name,
        secretVersion: previous.versionId,
        state: version.state,
        createdAt: previous.createdAt,
        pendingExpiresAt: previous.pendingExpiresAt,
        ...(previous.encryptedSecret ? { clientSecret: this.decryptSecret(previous.encryptedSecret) } : {}),
        replayed: true
      };
    }

    this.syncConfiguredClient(input.tenantId, input.client, now);
    const existing = this.findCredential(input.tenantId, clientId, input.name);
    if (existing?.pendingRotationId) {
      throw new ClientSecretRotationError(409, "rotation_pending", "A rotation is already pending for this credential");
    }
    if (input.kind === "create" && existing && this.hasAcceptedVersion(existing, now)) {
      throw new ClientSecretRotationError(409, "credential_exists", "A named credential with this name already exists");
    }
    if (input.kind === "rotate" && !existing?.versions.some((version) => version.state === "current")) {
      throw new ClientSecretRotationError(404, "credential_not_found", "Named credential was not found");
    }
    if (input.kind === "create") {
      const activeNameCount = this.data.credentials.filter((credential) =>
        credential.tenantId === input.tenantId && credential.clientId === clientId && this.hasAcceptedVersion(credential, now)
      ).length;
      if (activeNameCount >= 20) {
        throw new ClientSecretRotationError(409, "credential_limit_reached", "A client can have at most 20 named credentials");
      }
    }

    let secret = crypto.randomBytes(32).toString("base64url");
    for (let attempt = 0; attempt < 4 && this.secretIsInUse(input.tenantId, clientId, input.client, secret); attempt += 1) {
      secret = crypto.randomBytes(32).toString("base64url");
    }
    if (this.secretIsInUse(input.tenantId, clientId, input.client, secret)) {
      throw new Error("Unable to generate a unique client secret");
    }

    const next = this.cloneData();
    let record = next.credentials.find((credential) =>
      credential.tenantId === input.tenantId && credential.clientId === clientId && credential.name === input.name
    );
    if (!record) {
      record = {
        tenantId: input.tenantId,
        clientId,
        name: input.name,
        source: "api",
        versions: [],
        lifetimeDaysApplied: input.client.clientSecretLifetimeDays
      };
      next.credentials.push(record);
    }
    record.source = "api";

    const versionId = this.createId("sv_");
    const rotationId = this.createId("rot_");
    const pendingExpiresAt = now + PENDING_LIFETIME_MS;
    const version: SecretVersion = {
      versionId,
      verifier: this.verifier(secret),
      secretHint: `...${secret.slice(-5)}`,
      state: "pending",
      createdAt: now,
      expiresAt: pendingExpiresAt
    };
    record.versions.push(version);
    record.pendingRotationId = rotationId;
    next.operations.push({
      kind: input.kind,
      idempotencyKey: input.idempotencyKey,
      fingerprint,
      rotationId,
      tenantId: input.tenantId,
      clientId,
      name: input.name,
      versionId,
      createdAt: now,
      pendingExpiresAt,
      status: "pending",
      encryptedSecret: this.encryptSecret(secret)
    });
    this.commit(next);

    return {
      rotationId,
      tenantId: input.tenantId,
      clientId,
      name: input.name,
      secretVersion: versionId,
      state: "pending",
      createdAt: now,
      pendingExpiresAt,
      clientSecret: secret,
      replayed: false
    };
  }

  /**
   * Promotes a pending version and starts a bounded grace period for the old current version.
   */
  activate(input: {
    tenantId: string;
    clientId: string;
    name: string;
    rotationId: string;
    now?: number;
  }): ActivatedRotationResult {
    const now = input.now ?? Date.now();
    this.expire(now);
    const operation = this.data.operations.find((candidate) =>
      candidate.rotationId === input.rotationId &&
      candidate.tenantId === input.tenantId &&
      candidate.clientId === input.clientId &&
      candidate.name === input.name
    );
    if (!operation) {
      throw new ClientSecretRotationError(404, "rotation_not_found", "Rotation was not found");
    }
    if (operation.status === "expired") {
      throw new ClientSecretRotationError(410, "rotation_expired", "Pending rotation has expired");
    }
    if (operation.status === "revoked") {
      throw new ClientSecretRotationError(410, "rotation_revoked", "Rotation was revoked");
    }

    const version = this.findVersion(input.tenantId, input.clientId, input.name, operation.versionId);
    const record = this.findCredential(input.tenantId, input.clientId, input.name);
    if (!version || !record) {
      throw new ClientSecretRotationError(404, "rotation_not_found", "Rotation was not found");
    }
    if (operation.status === "activated") {
      return {
        rotationId: operation.rotationId,
        tenantId: operation.tenantId,
        clientId: operation.clientId,
        name: operation.name,
        secretVersion: operation.versionId,
        state: version.state,
        ...(version.activatedAt !== undefined ? { activatedAt: version.activatedAt } : {}),
        ...(record.versions.find((candidate) => candidate.state === "grace")?.expiresAt
          ? { previousSecretGraceExpiresAt: record.versions.find((candidate) => candidate.state === "grace")?.expiresAt }
          : {}),
        replayed: true
      };
    }
    if (operation.status !== "pending" || record.pendingRotationId !== operation.rotationId || version.state !== "pending") {
      throw new ClientSecretRotationError(409, "rotation_state_conflict", "Rotation is no longer pending");
    }

    const next = this.cloneData();
    const nextRecord = next.credentials.find((candidate) =>
      candidate.tenantId === input.tenantId && candidate.clientId === input.clientId && candidate.name === input.name
    );
    const nextOperation = next.operations.find((candidate) => candidate.rotationId === input.rotationId);
    const nextVersion = nextRecord?.versions.find((candidate) => candidate.versionId === operation.versionId);
    if (!nextRecord || !nextOperation || !nextVersion) {
      throw new Error("Rotation store changed while activating a secret");
    }

    const previous = nextRecord.versions.find((candidate) => candidate.state === "current" && this.isAccepted(candidate, now));
    let previousSecretGraceExpiresAt: number | undefined;
    for (const olderVersion of nextRecord.versions) {
      if (olderVersion.state === "grace" || (olderVersion.state === "current" && olderVersion !== previous)) {
        olderVersion.state = "expired";
      }
    }
    if (previous) {
      previous.state = "grace";
      previous.expiresAt = now + PREVIOUS_SECRET_GRACE_MS;
      previousSecretGraceExpiresAt = previous.expiresAt;
    }
    nextVersion.state = "current";
    nextVersion.activatedAt = now;
    if (nextRecord.lifetimeDaysApplied) {
      nextVersion.lifetimeStartedAt = now;
      nextVersion.expiresAt = now + nextRecord.lifetimeDaysApplied * 24 * 60 * 60 * 1000;
    } else {
      delete nextVersion.lifetimeStartedAt;
      delete nextVersion.expiresAt;
    }
    if (!nextVersion.secretHint && nextOperation.encryptedSecret) {
      nextVersion.secretHint = `...${this.decryptSecret(nextOperation.encryptedSecret).slice(-5)}`;
    }
    if (nextVersion.expiresAt === undefined) delete nextVersion.expiresAt;
    nextRecord.pendingRotationId = undefined;
    nextOperation.status = "activated";
    delete nextOperation.encryptedSecret;
    this.commit(next);

    return {
      rotationId: input.rotationId,
      tenantId: input.tenantId,
      clientId: input.clientId,
      name: input.name,
      secretVersion: nextVersion.versionId,
      state: "current",
      activatedAt: now,
      ...(previousSecretGraceExpiresAt ? { previousSecretGraceExpiresAt } : {}),
      replayed: false
    };
  }

  /**
   * Revokes all versions for a name while preserving another current credential.
   */
  revoke(input: {
    tenantId: string;
    client: MockClient;
    name: string;
    now?: number;
  }): { revokedVersionIds: string[]; alreadyRevoked: boolean } {
    const now = input.now ?? Date.now();
    this.expire(now);
    this.syncConfiguredClient(input.tenantId, input.client, now);
    const clientId = input.client.clientId;
    const record = this.findCredential(input.tenantId, clientId, input.name);
    if (!record) {
      throw new ClientSecretRotationError(404, "credential_not_found", "Named credential was not found");
    }
    const activeVersions = record.versions.filter((version) => this.isAccepted(version, now));
    const hasCurrentVersion = record.versions.some((version) => version.state === "current" && this.isAccepted(version, now));
    if (hasCurrentVersion && !input.client.clientSecret && !this.hasCurrentCredentialExcept(input.tenantId, clientId, input.name, now)) {
      throw new ClientSecretRotationError(409, "last_credential", "Cannot revoke the client's last current credential");
    }
    if (activeVersions.length === 0 && record.versions.every((version) => version.state === "revoked")) {
      return { revokedVersionIds: record.versions.map((version) => version.versionId), alreadyRevoked: true };
    }

    const next = this.cloneData();
    const nextRecord = next.credentials.find((candidate) =>
      candidate.tenantId === input.tenantId && candidate.clientId === clientId && candidate.name === input.name
    );
    if (!nextRecord) {
      throw new Error("Rotation store changed while revoking a secret");
    }
    const revokedVersionIds = nextRecord.versions.map((version) => version.versionId);
    for (const version of nextRecord.versions) {
      version.state = "revoked";
    }
    nextRecord.source = "api";
    nextRecord.pendingRotationId = undefined;
    for (const operation of next.operations) {
      if (operation.tenantId === input.tenantId && operation.clientId === clientId && operation.name === input.name) {
        operation.status = "revoked";
        delete operation.encryptedSecret;
      }
    }
    for (const capability of next.capabilities) {
      if (capability.tenantId === input.tenantId && capability.clientId === clientId && capability.name === input.name) {
        capability.status = "revoked";
      }
    }
    this.commit(next);
    return { revokedVersionIds, alreadyRevoked: false };
  }

  /**
   * Checks managed named credentials and imports changed static config values as verifier records.
   */
  verifyNamedSecret(tenantId: string, client: MockClient, candidate: string): boolean {
    const now = Date.now();
    this.expire(now);
    this.syncConfiguredClient(tenantId, client, now);
    const candidateVerifier = this.verifier(candidate);
    let matchedVersionId: string | undefined;
    for (const credential of this.data.credentials
      .filter((credential) => credential.tenantId === tenantId && credential.clientId === client.clientId)
    ) {
      for (const version of credential.versions) {
        const matches = constantTimeEqual(candidateVerifier, version.verifier);
        if (this.isAccepted(version, now) && matches) {
          matchedVersionId = version.versionId;
        }
      }
    }
    if (matchedVersionId) {
      const version = this.data.credentials
        .filter((credential) => credential.tenantId === tenantId && credential.clientId === client.clientId)
        .flatMap((credential) => credential.versions)
        .find((candidateVersion) => candidateVersion.versionId === matchedVersionId);
      if (version && (!version.lastUsedAt || now - version.lastUsedAt >= 60_000)) {
        const next = this.cloneData();
        const nextVersion = next.credentials
          .find((credential) => credential.tenantId === tenantId && credential.clientId === client.clientId)
          ?.versions.find((candidateVersion) => candidateVersion.versionId === matchedVersionId);
        if (nextVersion) {
          nextVersion.lastUsedAt = now;
          this.commit(next);
        }
      }
    }
    return Boolean(matchedVersionId);
  }

  /**
   * Authenticates a client for a rotation-token exchange using its legacy or current secret.
   */
  verifyCurrentClientSecret(tenantId: string, client: MockClient, candidate: string): boolean {
    const now = Date.now();
    this.expire(now);
    this.syncConfiguredClient(tenantId, client, now);
    let matchedVersionId: string | undefined;
    const candidateVerifier = this.verifier(candidate);
    for (const credential of this.data.credentials
      .filter((credential) => credential.tenantId === tenantId && credential.clientId === client.clientId)
    ) {
      for (const version of credential.versions) {
        const matches = constantTimeEqual(candidateVerifier, version.verifier);
        if (version.state === "current" && this.isAccepted(version, now) && matches) {
          matchedVersionId = version.versionId;
        }
      }
    }
    const matchesLegacy = Boolean(client.clientSecret && constantTimeEqual(candidate, client.clientSecret));
    if (matchedVersionId) {
      const next = this.cloneData();
      const nextVersion = next.credentials
        .find((credential) => credential.tenantId === tenantId && credential.clientId === client.clientId)
        ?.versions.find((version) => version.versionId === matchedVersionId);
      if (nextVersion && (!nextVersion.lastUsedAt || now - nextVersion.lastUsedAt >= 60_000)) {
        nextVersion.lastUsedAt = now;
        this.commit(next);
      }
    }
    return matchesLegacy || Boolean(matchedVersionId);
  }

  /**
   * Verifies possession of the pending version for exactly one client and credential name.
   */
  verifyPendingSecret(tenantId: string, client: MockClient, name: string, candidate: string): boolean {
    const now = Date.now();
    this.expire(now);
    this.syncConfiguredClient(tenantId, client, now);
    const record = this.findCredential(tenantId, client.clientId, name);
    if (!record) return false;

    const candidateVerifier = this.verifier(candidate);
    let matchedVersionId: string | undefined;
    for (const version of record.versions) {
      const matches = constantTimeEqual(candidateVerifier, version.verifier);
      if (version.state === "pending" && this.isAccepted(version, now) && matches) {
        matchedVersionId = version.versionId;
      }
    }
    if (matchedVersionId) {
      const next = this.cloneData();
      const nextVersion = next.credentials
        .find((credential) => credential.tenantId === tenantId && credential.clientId === client.clientId && credential.name === name)
        ?.versions.find((version) => version.versionId === matchedVersionId);
      if (nextVersion && (!nextVersion.lastUsedAt || now - nextVersion.lastUsedAt >= 60_000)) {
        nextVersion.lastUsedAt = now;
        this.commit(next);
      }
    }
    return Boolean(matchedVersionId);
  }

  /**
   * Issues an opaque, short-lived capability for one named create or rotation operation.
   */
  issueRotationCapability(input: {
    tenantId: string;
    clientId: string;
    name: string;
    kind: "create" | "rotate";
    now?: number;
  }): { accessToken: string; expiresAt: number } {
    const now = input.now ?? Date.now();
    this.expire(now);
    const accessToken = `rct_${crypto.randomBytes(32).toString("base64url")}`;
    const expiresAt = now + ROTATION_TOKEN_LIFETIME_MS;
    const next = this.cloneData();
    next.capabilities.push({
      verifier: this.capabilityVerifier(accessToken),
      tenantId: input.tenantId,
      clientId: input.clientId,
      name: input.name,
      kind: input.kind,
      createdAt: now,
      expiresAt,
      status: "issued"
    });
    this.commit(next);
    return { accessToken, expiresAt };
  }

  /**
   * Validates the capability's exact scope and permitted step in its single rotation flow.
   */
  authorizeRotationCapability(input: {
    accessToken: string;
    tenantId: string;
    clientId: string;
    name: string;
    kind?: "create" | "rotate";
    step: "start" | "activate";
    idempotencyKey?: string;
    rotationId?: string;
    now?: number;
  }): void {
    const now = input.now ?? Date.now();
    this.expire(now);
    const capability = this.findCapability(input.accessToken);
    if (!capability || capability.status === "revoked") {
      throw new ClientSecretRotationError(401, "invalid_rotation_token", "Rotation token is invalid");
    }
    if (capability.tenantId !== input.tenantId || capability.clientId !== input.clientId || capability.name !== input.name ||
        (input.kind !== undefined && capability.kind !== input.kind)) {
      throw new ClientSecretRotationError(403, "rotation_token_scope_mismatch", "Rotation token is not authorized for this operation");
    }
    if (capability.status === "expired" || capability.expiresAt <= now) {
      throw new ClientSecretRotationError(410, "rotation_token_expired", "Rotation token has expired");
    }

    if (input.step === "start") {
      if (capability.status === "issued") return;
      if ((capability.status === "pending" || capability.status === "activated") && capability.idempotencyKey === input.idempotencyKey) return;
      throw new ClientSecretRotationError(409, "rotation_token_used", "Rotation token is already bound to another operation");
    }

    if ((capability.status === "pending" || capability.status === "activated") && capability.rotationId === input.rotationId) return;
    if (capability.status === "issued") {
      throw new ClientSecretRotationError(409, "rotation_not_started", "Rotation token has not started a rotation");
    }
    throw new ClientSecretRotationError(403, "rotation_token_scope_mismatch", "Rotation token is not authorized for this activation");
  }

  /**
   * Binds a capability to the one operation it started; retries must use the same idempotency key.
   */
  bindRotationCapability(input: {
    accessToken: string;
    idempotencyKey: string;
    rotationId: string;
    pendingExpiresAt: number;
    now?: number;
  }): void {
    const now = input.now ?? Date.now();
    const next = this.cloneData();
    const capability = next.capabilities.find((entry) =>
      constantTimeEqual(entry.verifier, this.capabilityVerifier(input.accessToken))
    );
    if (!capability || capability.expiresAt <= now || capability.status === "expired" || capability.status === "revoked") {
      throw new ClientSecretRotationError(410, "rotation_token_expired", "Rotation token has expired");
    }
    if (capability.status === "issued") {
      capability.status = "pending";
      capability.idempotencyKey = input.idempotencyKey;
      capability.rotationId = input.rotationId;
      capability.expiresAt = input.pendingExpiresAt;
      this.commit(next);
      return;
    }
    if (capability.idempotencyKey === input.idempotencyKey && capability.rotationId === input.rotationId) return;
    throw new ClientSecretRotationError(409, "rotation_token_used", "Rotation token is already bound to another operation");
  }

  /**
   * Marks a capability complete after activation while preserving safe activation retries.
   */
  completeRotationCapability(input: { accessToken: string; rotationId: string }): void {
    const next = this.cloneData();
    const capability = next.capabilities.find((entry) =>
      constantTimeEqual(entry.verifier, this.capabilityVerifier(input.accessToken))
    );
    if (!capability || capability.rotationId !== input.rotationId || capability.status === "expired" || capability.status === "revoked") {
      throw new ClientSecretRotationError(410, "rotation_token_expired", "Rotation token is no longer valid");
    }
    if (capability.status === "activated") return;
    if (capability.status !== "pending") {
      throw new ClientSecretRotationError(409, "rotation_not_started", "Rotation token has not started a rotation");
    }
    capability.status = "activated";
    this.commit(next);
  }

  /**
   * Indicates whether this client has any accepted named credential after rotation rules apply.
   */
  hasAcceptedNamedSecret(tenantId: string, clientId: string, now = Date.now()): boolean {
    this.expire(now);
    return this.data.credentials.some((credential) =>
      credential.tenantId === tenantId && credential.clientId === clientId &&
      credential.versions.some((version) => this.isAccepted(version, now))
    );
  }

  /**
   * Indicates whether token requests must present a secret, including after API revocation.
   */
  requiresClientSecret(tenantId: string, clientId: string, now = Date.now()): boolean {
    this.expire(now);
    return this.data.credentials.some((credential) =>
      credential.tenantId === tenantId && credential.clientId === clientId &&
      (credential.source === "api" || credential.versions.some((version) =>
        (version.state === "current" || version.state === "pending" || version.state === "grace") &&
        (this.isAccepted(version, now) || (version.state === "current" && version.expiresAt !== undefined))
      ))
    );
  }

  private syncConfiguredClient(tenantId: string, client: MockClient, now: number): void {
    const configured = new Map((client.clientSecrets ?? []).map((credential) => [credential.name.toLowerCase(), credential.secret]));
    const next = this.cloneData();
    let changed = false;

    for (const [name, secret] of configured) {
      let record = next.credentials.find((credential) =>
        credential.tenantId === tenantId && credential.clientId === client.clientId && credential.name === name
      );
      if (!record) {
        this.assertUniqueConfiguredVerifier(next, tenantId, client.clientId, name, this.verifier(secret));
        record = {
          tenantId,
          clientId: client.clientId,
          name,
          source: "config",
          versions: [{
            versionId: this.createId("sv_"),
            verifier: this.verifier(secret),
            secretHint: `...${secret.slice(-5)}`,
            state: "current",
            createdAt: now,
            activatedAt: now
          }]
        };
        next.credentials.push(record);
        changed = true;
        continue;
      }
      if (record.source !== "config") {
        continue;
      }
      const current = record.versions.find((version) => version.state === "current");
      const nextVerifier = this.verifier(secret);
      if (current && constantTimeEqual(current.verifier, nextVerifier)) {
        if (!current.secretHint) {
          current.secretHint = `...${secret.slice(-5)}`;
          changed = true;
        }
        continue;
      }
      this.assertUniqueConfiguredVerifier(next, tenantId, client.clientId, name, nextVerifier);
      for (const version of record.versions) {
        if (version.state === "current" || version.state === "grace" || version.state === "pending") {
          version.state = "expired";
        }
      }
      record.versions.push({
        versionId: this.createId("sv_"),
        verifier: nextVerifier,
        secretHint: `...${secret.slice(-5)}`,
        state: "current",
        createdAt: now,
        activatedAt: now
      });
      changed = true;
    }

    for (const record of next.credentials) {
      if (record.tenantId === tenantId && record.clientId === client.clientId) {
        for (const version of record.versions) {
          if (version.state !== "current") continue;
          if (!client.clientSecretLifetimeDays) {
            if (version.lifetimeStartedAt !== undefined || version.expiresAt !== undefined) changed = true;
            delete version.lifetimeStartedAt;
            delete version.expiresAt;
            continue;
          }
          if (version.lifetimeStartedAt === undefined) {
            version.lifetimeStartedAt = now;
            changed = true;
          }
          const expiresAt = version.lifetimeStartedAt + client.clientSecretLifetimeDays * 24 * 60 * 60 * 1000;
          if (version.expiresAt !== expiresAt) {
            version.expiresAt = expiresAt;
            changed = true;
          }
        }
        if (record.lifetimeDaysApplied !== client.clientSecretLifetimeDays) {
          record.lifetimeDaysApplied = client.clientSecretLifetimeDays;
          changed = true;
        }
      }
      if (record.tenantId !== tenantId || record.clientId !== client.clientId || record.source !== "config" || configured.has(record.name)) {
        continue;
      }
      for (const version of record.versions) {
        if (version.state === "current" || version.state === "grace" || version.state === "pending") {
          version.state = "revoked";
          changed = true;
        }
      }
    }

    if (changed) {
      this.commit(next);
    }
  }

  private assertUniqueConfiguredVerifier(
    data: RotationStoreData,
    tenantId: string,
    clientId: string,
    name: string,
    verifier: string
  ): void {
    for (const credential of data.credentials) {
      if (credential.tenantId !== tenantId || credential.clientId !== clientId || credential.name === name) {
        continue;
      }
      if (credential.versions.some((version) => constantTimeEqual(version.verifier, verifier))) {
        throw new ClientSecretRotationError(409, "duplicate_secret_value", "Client secret values must be unique within a client");
      }
    }
  }

  private secretIsInUse(tenantId: string, clientId: string, client: MockClient, candidate: string): boolean {
    if (client.clientSecret && constantTimeEqual(candidate, client.clientSecret)) {
      return true;
    }
    const verifier = this.verifier(candidate);
    return this.data.credentials
      .filter((credential) => credential.tenantId === tenantId && credential.clientId === clientId)
      .some((credential) => credential.versions.some((version) => constantTimeEqual(verifier, version.verifier)));
  }

  private hasCurrentCredentialExcept(tenantId: string, clientId: string, name: string, now: number): boolean {
    return this.data.credentials.some((credential) =>
      credential.tenantId === tenantId && credential.clientId === clientId && credential.name !== name &&
      credential.versions.some((version) => version.state === "current" && this.isAccepted(version, now))
    );
  }

  private hasAcceptedVersion(record: CredentialRecord, now: number): boolean {
    return record.versions.some((version) => this.isAccepted(version, now));
  }

  private isAccepted(version: SecretVersion, now: number): boolean {
    if (version.state === "current" || version.state === "pending") {
      return !version.expiresAt || version.expiresAt > now;
    }
    return version.state === "grace" && Boolean(version.expiresAt && version.expiresAt > now);
  }

  private expire(now: number): void {
    const next = this.cloneData();
    let changed = false;
    for (const credential of next.credentials) {
      for (const version of credential.versions) {
        const expiredPending = version.state === "pending";
        if ((expiredPending || version.state === "grace") && version.expiresAt !== undefined && version.expiresAt <= now) {
          version.state = "expired";
          changed = true;
          if (expiredPending && credential.pendingRotationId) {
            credential.pendingRotationId = undefined;
          }
        }
      }
    }
    for (const operation of next.operations) {
      if (operation.status === "pending" && operation.pendingExpiresAt <= now) {
        operation.status = "expired";
        delete operation.encryptedSecret;
        changed = true;
      }
    }
    for (const capability of next.capabilities) {
      if (capability.status !== "expired" && capability.status !== "revoked" && capability.expiresAt <= now) {
        capability.status = "expired";
        changed = true;
      }
    }
    if (changed) {
      this.commit(next);
    }
  }

  private findCredential(tenantId: string, clientId: string, name: string): CredentialRecord | undefined {
    return this.data.credentials.find((credential) =>
      credential.tenantId === tenantId && credential.clientId === clientId && credential.name === name
    );
  }

  private findVersion(tenantId: string, clientId: string, name: string, versionId: string): SecretVersion | undefined {
    return this.findCredential(tenantId, clientId, name)?.versions.find((version) => version.versionId === versionId);
  }

  private findCapability(accessToken: string): RotationCapability | undefined {
    const verifier = this.capabilityVerifier(accessToken);
    let matched: RotationCapability | undefined;
    for (const capability of this.data.capabilities) {
      if (constantTimeEqual(verifier, capability.verifier)) matched = capability;
    }
    return matched;
  }

  private verifier(secret: string): string {
    return crypto.createHmac("sha256", this.verifierKey).update(secret, "utf8").digest("hex");
  }

  private capabilityVerifier(accessToken: string): string {
    return crypto.createHmac("sha256", this.verifierKey)
      .update("rotation-capability\u0000", "utf8")
      .update(accessToken, "utf8")
      .digest("hex");
  }

  private encryptSecret(secret: string): EncryptedSecret {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.pendingEncryptionKey, nonce);
    const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
    return {
      nonce: nonce.toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url")
    };
  }

  private decryptSecret(encrypted: EncryptedSecret): string {
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.pendingEncryptionKey, Buffer.from(encrypted.nonce, "base64url"));
    decipher.setAuthTag(Buffer.from(encrypted.tag, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(encrypted.ciphertext, "base64url")),
      decipher.final()
    ]).toString("utf8");
  }

  private createId(prefix: "sv_" | "rot_"): string {
    return prefix + crypto.randomBytes(18).toString("base64url");
  }

  private cloneData(): RotationStoreData {
    return JSON.parse(JSON.stringify(this.data)) as RotationStoreData;
  }

  private commit(next: RotationStoreData): void {
    this.writeStore(next);
    this.data = next;
  }

  private readStore(): RotationStoreData {
    if (!fs.existsSync(this.storePath)) {
      return { schemaVersion: 1, credentials: [], operations: [], capabilities: [] };
    }
    try {
      fs.chmodSync(this.storePath, 0o600);
      const parsed = JSON.parse(fs.readFileSync(this.storePath, "utf8")) as RotationStoreData;
      if (parsed.schemaVersion !== 1 || !Array.isArray(parsed.credentials) || !Array.isArray(parsed.operations) || (parsed.capabilities !== undefined && !Array.isArray(parsed.capabilities))) {
        throw new Error("invalid schema");
      }
      return { ...parsed, capabilities: parsed.capabilities ?? [] };
    } catch {
      throw new Error("Client secret rotation store is invalid or unreadable");
    }
  }

  private writeStore(data: RotationStoreData): void {
    const resolved = path.resolve(this.storePath);
    const temporaryPath = `${resolved}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    try {
      fs.writeFileSync(temporaryPath, `${JSON.stringify(data, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
      fs.chmodSync(temporaryPath, 0o600);
      fs.renameSync(temporaryPath, resolved);
    } catch (error) {
      try {
        fs.unlinkSync(temporaryPath);
      } catch {
        // The temporary file may not have been created.
      }
      throw error;
    }
  }
}

/**
 * Loads or creates the separately protected key used for rotation verifiers and pending ciphertext.
 */
export function loadOrCreateClientSecretRotationKey(keyPath: string, storeExists: boolean): string {
  const resolved = path.resolve(keyPath);
  if (fs.existsSync(resolved)) {
    const key = fs.readFileSync(resolved, "utf8").trim();
    if (Buffer.from(key, "base64url").length !== 32) {
      throw new Error("Client secret rotation key is invalid");
    }
    fs.chmodSync(resolved, 0o600);
    return key;
  }
  if (storeExists) {
    throw new Error("Client secret rotation key is missing while a rotation store exists");
  }

  const key = crypto.randomBytes(32).toString("base64url");
  try {
    fs.writeFileSync(resolved, `${key}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    fs.chmodSync(resolved, 0o600);
    return key;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "EEXIST") {
      return loadOrCreateClientSecretRotationKey(resolved, true);
    }
    throw error;
  }
}

/**
 * Parses the exact tenant/client/name grants configured for the rotation manager.
 */
export function parseClientSecretRotationAllowlist(raw?: string): ClientSecretRotationPermission[] {
  if (!raw) {
    return [];
  }
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("OIDC_MOCK_ROTATION_ALLOWLIST must be a JSON array of tenant/client/name grants");
  }
  if (!Array.isArray(value)) {
    throw new Error("OIDC_MOCK_ROTATION_ALLOWLIST must be a JSON array of tenant/client/name grants");
  }
  return value.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error("OIDC_MOCK_ROTATION_ALLOWLIST contains an invalid grant");
    }
    const grant = entry as Record<string, unknown>;
    const tenantId = typeof grant.tenantId === "string" ? grant.tenantId.trim() : "";
    const clientId = typeof grant.clientId === "string" ? grant.clientId.trim() : "";
    if (!tenantId || !clientId || !Array.isArray(grant.names) || grant.names.length === 0) {
      throw new Error("OIDC_MOCK_ROTATION_ALLOWLIST grants require tenantId, clientId, and at least one name");
    }
    const names = grant.names.map((name) => typeof name === "string" ? name.trim().toLowerCase() : "");
    if (names.some((name) => !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(name))) {
      throw new Error("OIDC_MOCK_ROTATION_ALLOWLIST contains an invalid credential name");
    }
    return { tenantId, clientId, names: [...new Set(names)] };
  });
}
