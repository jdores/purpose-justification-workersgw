import { DurableObject } from "cloudflare:workers";
import { canonicalizeHost } from "../lib/host.js";
import { log, logError } from "../lib/log.js";
import type {
  Actor,
  ConfigInput,
  EvaluateInput,
  EvaluateResult,
  GrantStatus,
  GrantView,
  HoldStatus,
  HoldView,
  IdentityKind,
  ListInput,
  ListResult,
  Policy,
  PolicyConfig,
  RequestStatus,
  RequestView,
  StatusInput,
  StatusResult,
  StoreResult,
  SubmitInput,
  SubmitResult,
} from "../types.js";
import { MAX_EMAIL_LENGTH, MAX_IDENTITY_NAME_LENGTH } from "../types.js";
import { DEFAULT_CONFIG, normalizeConfiguredHost, resolvePolicy, validateConfig } from "./config.js";
import { decodeCursor, encodeCursor, normalizeLimit } from "./pagination.js";

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;
const EMAIL = /^[^\s@]+@[^\s@]+$/;
export const SCHEMA_VERSION = 2;

interface RequestRow extends Record<string, SqlStorageValue> {
  id: string;
  submission_nonce: string;
  identity_kind: IdentityKind;
  identity: string;
  identity_name: string | null;
  host: string;
  requested_url: string;
  justification: string;
  policy_kind: string;
  status: RequestStatus;
  created_at: number;
  expires_at: number;
  decided_at: number | null;
  decided_by: string | null;
  decided_by_source: Actor["source"] | null;
  decision_reason: string | null;
  grant_seconds: number | null;
  user_agent: string | null;
  config_version: number;
}

interface GrantRow extends Record<string, SqlStorageValue> {
  id: string;
  request_id: string;
  identity_kind: IdentityKind;
  identity: string;
  host: string;
  status: GrantStatus;
  granted_at: number;
  expires_at: number;
  granted_by: string;
  granted_by_source: Actor["source"];
  revoked_at: number | null;
  revoked_by: string | null;
  revoked_by_source: Actor["source"] | null;
}

interface HoldRow extends Record<string, SqlStorageValue> {
  id: string;
  request_id: string;
  identity_kind: IdentityKind;
  identity: string;
  host: string;
  status: HoldStatus;
  reason: string;
  denied_at: number;
  expires_at: number;
  denied_by: string;
  denied_by_source: Actor["source"];
  cleared_at: number | null;
  cleared_by: string | null;
  cleared_by_source: Actor["source"] | null;
}

export class GateStore extends DurableObject<Env> {
  private readonly sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => this.initialize());
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async evaluate(input: EvaluateInput): Promise<EvaluateResult> {
    validateScope(input);
    const now = Date.now();
    this.expireScope(input, now);
    const config = this.readConfig();
    const policy = resolvePolicy(config, input.host);

    const grant = this.findActiveGrant(input);
    if (grant) return { state: "granted", grant: toGrantView(grant), config, policy };

    const hold = this.findActiveHold(input);
    if (hold) {
      return {
        state: "denied",
        hold: toHoldView(hold),
        config,
        policy: this.resolveHistoricalPolicy(config, hold.request_id),
      };
    }

    const request = this.findPendingRequest(input);
    if (request) {
      return {
        state: "pending",
        request: this.toRequestView(request),
        config,
        policy: this.resolveHistoricalPolicy(config, request.id),
      };
    }
    return { state: "none", config, policy };
  }

  async submit(input: SubmitInput): Promise<SubmitResult> {
    if (!validSubmit(input)) return { state: "invalid" };
    validateScope(input);

    const now = Date.now();
    this.expireScope(input, now);
    const nonceRequest = this.one<RequestRow>(
      "SELECT * FROM requests WHERE submission_nonce = ?",
      input.submissionNonce,
    );
    if (
      nonceRequest &&
      (nonceRequest.identity_kind !== input.identityKind ||
        nonceRequest.identity !== input.identity ||
        nonceRequest.host !== input.host)
    ) {
      return { state: "invalid" };
    }
    if (nonceRequest?.status === "pending") {
      return { state: "existing", request: this.toRequestView(nonceRequest) };
    }

    const config = this.readConfig();
    const policy = resolvePolicy(config, input.host);
    if (config.version !== input.configVersion || policy.kind !== input.policyKind) {
      return { state: "config_changed" };
    }

    const grant = this.findActiveGrant(input);
    if (grant) return { state: "granted", grant: toGrantView(grant) };
    const hold = this.findActiveHold(input);
    if (hold) return { state: "denied", hold: toHoldView(hold) };
    if (nonceRequest) return { state: "invalid" };

    const pending = this.findPendingRequest(input);
    if (pending) return { state: "existing", request: this.toRequestView(pending) };

    const cutoff = now - HOUR_MS;
    const rate = this.one<{ count: number; oldest: number | null }>(
      `SELECT COUNT(*) AS count, MIN(created_at) AS oldest
       FROM requests WHERE identity_kind = ? AND identity = ? AND created_at > ?`,
      input.identityKind,
      input.identity,
      cutoff,
    );
    if (rate && rate.count >= config.submissionLimitPerHour) {
      const retryAfterSeconds = Math.max(1, Math.ceil(((rate.oldest ?? now) + HOUR_MS - now) / 1000));
      return { state: "rate_limited", retryAfterSeconds };
    }

    const id = crypto.randomUUID();
    const expiresAt = now + config.pendingExpirySeconds * 1000;
    this.sql.exec(
      `INSERT INTO requests
       (id, submission_nonce, identity_kind, identity, identity_name, host, requested_url, justification,
        policy_kind, status, created_at, expires_at, user_agent, config_version)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)`,
      id,
      input.submissionNonce,
      input.identityKind,
      input.identity,
      input.identityName,
      input.host,
      input.requestedUrl,
      input.justification.trim(),
      input.policyKind,
      now,
      expiresAt,
      sanitizeUserAgent(input.userAgent),
      input.configVersion,
    );
    await this.scheduleAlarm(now);
    this.broadcast({ type: "request.created", requestId: id, at: iso(now) });
    const created = this.one<RequestRow>("SELECT * FROM requests WHERE id = ?", id);
    if (!created) throw new Error("created request missing");
    return { state: "created", request: this.toRequestView(created) };
  }

  async status(input: StatusInput): Promise<StatusResult> {
    validateStatusInput(input);
    const request = this.one<RequestRow>("SELECT * FROM requests WHERE id = ?", input.requestId);
    if (!request || request.identity !== input.identity || request.host !== input.host) return { state: "invalid" };

    const now = Date.now();
    this.expireScope(input, now);
    const current = this.one<RequestRow>("SELECT * FROM requests WHERE id = ?", input.requestId);
    if (!current) return { state: "invalid" };
    if (current.status === "pending") return { state: "pending", request: this.toRequestView(current) };
    if (current.status === "approved") {
      const grant = this.one<GrantRow>(
        "SELECT * FROM grants WHERE request_id = ? AND status = 'active' AND expires_at > ?",
        current.id,
        now,
      );
      if (grant) return { state: "approved", requestId: current.id, grant: toGrantView(grant) };
    }
    if (current.status === "denied") {
      const hold = this.one<HoldRow>(
        "SELECT * FROM denial_holds WHERE request_id = ? AND status = 'active' AND expires_at > ?",
        current.id,
        now,
      );
      if (hold) return { state: "denied", requestId: current.id, hold: toHoldView(hold) };
    }
    return { state: "expired", requestId: current.id };
  }

  async getConfig(): Promise<PolicyConfig> {
    return this.readConfig();
  }

  async putConfig(input: ConfigInput, actor: Actor): Promise<StoreResult<PolicyConfig>> {
    const started = Date.now();
    const invocationId = crypto.randomUUID();
    validateActor(actor);
    const validation = validateConfig(input);
    if (!validation.value) {
      return {
        ok: false,
        code: "validation_failed",
        message: "Configuration validation failed.",
        details: validation.errors,
      };
    }
    const previous = this.readConfig();
    const config: PolicyConfig = {
      ...validation.value,
      version: previous.version + 1,
      updatedAt: new Date().toISOString(),
    };
    const serialized = JSON.stringify(config);
    if (new TextEncoder().encode(serialized).byteLength > 65_536) {
      return {
        ok: false,
        code: "validation_failed",
        message: "Configuration validation failed.",
        details: ["config must not exceed 65536 bytes"],
      };
    }
    this.sql.exec("UPDATE app_config SET document = ? WHERE id = 1", serialized);
    await this.scheduleAlarm();
    this.broadcast({ type: "config.updated", version: config.version, at: config.updatedAt });
    log("pj_config_updated", {
      ...operationFields(invocationId, started),
      version: config.version,
      actor_source: actor.source,
    });
    return { ok: true, value: config };
  }

  async resetConfig(actor: Actor): Promise<StoreResult<PolicyConfig>> {
    validateActor(actor);
    const previous = this.readConfig();
    return this.putConfig(
      {
        ...DEFAULT_CONFIG,
        version: previous.version,
        updatedAt: previous.updatedAt,
      },
      actor,
    );
  }

  async listRequests(input: ListInput): Promise<ListResult<RequestView>> {
    const statuses = ["pending", "approved", "denied", "expired", "terminal"];
    validateListInput(input, statuses);
    this.expireAll(Date.now());
    const direction = input.status === "pending" ? "asc" : "desc";
    const limit = normalizeLimit(input.limit);
    const cursor = decodeCursor(input.cursor, direction);
    const where: string[] = [];
    const params: (string | number)[] = [];
    if (input.status === "terminal") {
      where.push("status != 'pending'");
    } else if (input.status) {
      where.push("status = ?");
      params.push(input.status);
    }
    if (input.host) {
      where.push("host = ?");
      params.push(input.host);
    }
    if (cursor) {
      const operator = direction === "asc" ? ">" : "<";
      where.push(`(created_at ${operator} ? OR (created_at = ? AND id ${operator} ?))`);
      params.push(cursor.at, cursor.at, cursor.id);
    }
    const order = direction === "asc" ? "ASC" : "DESC";
    const sql = `SELECT * FROM requests${where.length ? ` WHERE ${where.join(" AND ")}` : ""}
      ORDER BY created_at ${order}, id ${order} LIMIT ?`;
    const rows = this.sql.exec<RequestRow>(sql, ...params, limit + 1).toArray();
    const listComplete = rows.length <= limit;
    const page = rows.slice(0, limit);
    const last = page.at(-1);
    const grants = this.relatedByRequest<GrantRow>("grants", page.map((row) => row.id));
    const holds = this.relatedByRequest<HoldRow>("denial_holds", page.map((row) => row.id));
    return {
      entries: page.map((row) => this.toRequestView(row, grants.get(row.id) ?? null, holds.get(row.id) ?? null)),
      cursor: !listComplete && last ? encodeCursor({ at: last.created_at, id: last.id, direction }) : null,
      listComplete,
    };
  }

  async getRequest(id: string): Promise<RequestView | null> {
    if (!validId(id)) return null;
    this.expireAll(Date.now());
    const row = this.one<RequestRow>("SELECT * FROM requests WHERE id = ?", id);
    return row ? this.toRequestView(row) : null;
  }

  async approve(
    id: string,
    grantSeconds: number | undefined,
    actor: Actor,
  ): Promise<StoreResult<{ requestId: string; status: "approved"; grant: GrantView }>> {
    const started = Date.now();
    const invocationId = crypto.randomUUID();
    validateActor(actor);
    if (!validId(id)) return notFound("Request not found.");
    const now = Date.now();
    this.expireRequest(id, now);
    const request = this.one<RequestRow>("SELECT * FROM requests WHERE id = ?", id);
    const invalid = decisionError(request);
    if (invalid) return invalid;
    if (!request) throw new Error("request disappeared");

    const config = this.readConfig();
    const seconds = grantSeconds ?? config.defaultGrantSeconds;
    if (!Number.isInteger(seconds) || seconds < 60 || seconds > config.maxGrantSeconds) {
      return {
        ok: false,
        code: "validation_failed",
        message: `grantSeconds must be an integer between 60 and ${config.maxGrantSeconds}.`,
      };
    }

    const grantId = crypto.randomUUID();
    const expiresAt = now + seconds * 1000;
    this.sql.exec(
      `UPDATE grants SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_by_source = ?
       WHERE identity_kind = ? AND identity = ? AND host = ? AND status = 'active'`,
      now,
      actor.value,
      actor.source,
      request.identity_kind,
      request.identity,
      request.host,
    );
    this.sql.exec(
      `UPDATE denial_holds SET status = 'cleared', cleared_at = ?, cleared_by = ?, cleared_by_source = ?
       WHERE identity_kind = ? AND identity = ? AND host = ? AND status = 'active'`,
      now,
      actor.value,
      actor.source,
      request.identity_kind,
      request.identity,
      request.host,
    );
    this.sql.exec(
      `UPDATE requests SET status = 'approved', decided_at = ?, decided_by = ?, decided_by_source = ?,
       decision_reason = NULL, grant_seconds = ? WHERE id = ? AND status = 'pending'`,
      now,
      actor.value,
      actor.source,
      seconds,
      id,
    );
    this.sql.exec(
      `INSERT INTO grants
       (id, request_id, identity_kind, identity, host, status, granted_at, expires_at, granted_by, granted_by_source)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)`,
      grantId,
      id,
      request.identity_kind,
      request.identity,
      request.host,
      now,
      expiresAt,
      actor.value,
      actor.source,
    );
    await this.scheduleAlarm(now);
    this.broadcast({ type: "request.decided", requestId: id, at: iso(now) });
    log("pj_admin_decision", {
      ...operationFields(invocationId, started),
      request_id: id,
      decision: "approved",
      host: request.host,
    });
    const grant = this.one<GrantRow>("SELECT * FROM grants WHERE id = ?", grantId);
    if (!grant) throw new Error("created grant missing");
    return { ok: true, value: { requestId: id, status: "approved", grant: toGrantView(grant) } };
  }

  async deny(
    id: string,
    reason: string,
    actor: Actor,
  ): Promise<StoreResult<{ requestId: string; status: "denied"; hold: HoldView }>> {
    const started = Date.now();
    const invocationId = crypto.randomUUID();
    validateActor(actor);
    if (!validId(id)) return notFound("Request not found.");
    if (typeof reason !== "string") {
      return { ok: false, code: "validation_failed", message: "reason must be 5-500 characters." };
    }
    const cleanReason = reason.trim();
    if ([...cleanReason].length < 5 || [...cleanReason].length > 500) {
      return {
        ok: false,
        code: "validation_failed",
        message: "reason must be 5-500 characters.",
      };
    }
    const now = Date.now();
    this.expireRequest(id, now);
    const request = this.one<RequestRow>("SELECT * FROM requests WHERE id = ?", id);
    const invalid = decisionError(request);
    if (invalid) return invalid;
    if (!request) throw new Error("request disappeared");

    const config = this.readConfig();
    const holdId = crypto.randomUUID();
    const expiresAt = now + config.denyHoldSeconds * 1000;
    this.sql.exec(
      `UPDATE grants SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_by_source = ?
       WHERE identity_kind = ? AND identity = ? AND host = ? AND status = 'active'`,
      now,
      actor.value,
      actor.source,
      request.identity_kind,
      request.identity,
      request.host,
    );
    this.sql.exec(
      `UPDATE requests SET status = 'denied', decided_at = ?, decided_by = ?, decided_by_source = ?,
       decision_reason = ?, grant_seconds = NULL WHERE id = ? AND status = 'pending'`,
      now,
      actor.value,
      actor.source,
      cleanReason,
      id,
    );
    this.sql.exec(
      `INSERT INTO denial_holds
       (id, request_id, identity_kind, identity, host, status, reason, denied_at, expires_at, denied_by, denied_by_source)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)`,
      holdId,
      id,
      request.identity_kind,
      request.identity,
      request.host,
      cleanReason,
      now,
      expiresAt,
      actor.value,
      actor.source,
    );
    await this.scheduleAlarm(now);
    this.broadcast({ type: "request.decided", requestId: id, at: iso(now) });
    log("pj_admin_decision", {
      ...operationFields(invocationId, started),
      request_id: id,
      decision: "denied",
      host: request.host,
    });
    const hold = this.one<HoldRow>("SELECT * FROM denial_holds WHERE id = ?", holdId);
    if (!hold) throw new Error("created hold missing");
    return { ok: true, value: { requestId: id, status: "denied", hold: toHoldView(hold) } };
  }

  async listGrants(input: ListInput): Promise<ListResult<GrantView>> {
    return this.listState<GrantRow, GrantView>(
      "grants",
      "granted_at",
      ["active", "expired", "revoked"],
      input,
      toGrantView,
    );
  }

  async revokeGrant(id: string, actor: Actor): Promise<StoreResult<GrantView>> {
    const started = Date.now();
    const invocationId = crypto.randomUUID();
    validateActor(actor);
    if (!validId(id)) return notFound("Grant not found.");
    this.expireAll(Date.now());
    const row = this.one<GrantRow>("SELECT * FROM grants WHERE id = ?", id);
    if (!row) return notFound("Grant not found.");
    if (row.status === "revoked") return { ok: true, value: toGrantView(row) };
    if (row.status !== "active") return notActive("Grant is not active.");
    const now = Date.now();
    this.sql.exec(
      "UPDATE grants SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_by_source = ? WHERE id = ?",
      now,
      actor.value,
      actor.source,
      id,
    );
    await this.scheduleAlarm(now);
    this.broadcast({ type: "grant.revoked", grantId: id, at: iso(now) });
    log("pj_grant_revoked", {
      ...operationFields(invocationId, started),
      grant_id: id,
      host: row.host,
    });
    const updated = this.one<GrantRow>("SELECT * FROM grants WHERE id = ?", id);
    if (!updated) throw new Error("updated grant missing");
    return { ok: true, value: toGrantView(updated) };
  }

  async listHolds(input: ListInput): Promise<ListResult<HoldView>> {
    return this.listState<HoldRow, HoldView>(
      "denial_holds",
      "denied_at",
      ["active", "expired", "cleared"],
      input,
      toHoldView,
    );
  }

  async clearHold(id: string, actor: Actor): Promise<StoreResult<HoldView>> {
    const started = Date.now();
    const invocationId = crypto.randomUUID();
    validateActor(actor);
    if (!validId(id)) return notFound("Denial hold not found.");
    this.expireAll(Date.now());
    const row = this.one<HoldRow>("SELECT * FROM denial_holds WHERE id = ?", id);
    if (!row) return notFound("Denial hold not found.");
    if (row.status === "cleared") return { ok: true, value: toHoldView(row) };
    if (row.status !== "active") return notActive("Denial hold is not active.");
    const now = Date.now();
    this.sql.exec(
      `UPDATE denial_holds SET status = 'cleared', cleared_at = ?, cleared_by = ?, cleared_by_source = ?
       WHERE id = ?`,
      now,
      actor.value,
      actor.source,
      id,
    );
    await this.scheduleAlarm(now);
    this.broadcast({ type: "hold.cleared", holdId: id, at: iso(now) });
    log("pj_hold_cleared", {
      ...operationFields(invocationId, started),
      hold_id: id,
      host: row.host,
    });
    const updated = this.one<HoldRow>("SELECT * FROM denial_holds WHERE id = ?", id);
    if (!updated) throw new Error("updated hold missing");
    return { ok: true, value: toHoldView(updated) };
  }

  override async alarm(): Promise<void> {
    const now = Date.now();
    const invocationId = crypto.randomUUID();
    try {
      this.expireAll(now);
      const config = this.readConfig();
      const cutoff = now - config.retentionDays * DAY_MS;
      this.sql.exec(
        "DELETE FROM grants WHERE status != 'active' AND COALESCE(revoked_at, expires_at) <= ?",
        cutoff,
      );
      this.sql.exec(
        "DELETE FROM denial_holds WHERE status != 'active' AND COALESCE(cleared_at, expires_at) <= ?",
        cutoff,
      );
      this.sql.exec(
        `DELETE FROM requests WHERE status != 'pending' AND COALESCE(decided_at, expires_at) <= ?
         AND NOT EXISTS (SELECT 1 FROM grants WHERE grants.request_id = requests.id)
         AND NOT EXISTS (SELECT 1 FROM denial_holds WHERE denial_holds.request_id = requests.id)`,
        cutoff,
      );
      this.broadcast({ type: "state.refresh", at: iso(now) });
      log("pj_alarm_cleanup", operationFields(invocationId, now));
    } catch (error) {
      logError("alarm_cleanup_failed", error, operationFields(invocationId, now, "error"));
      throw error;
    } finally {
      await this.scheduleAlarm(now);
    }
  }

  override async fetch(request: Request): Promise<Response> {
    if (request.method !== "GET" || request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Expected WebSocket upgrade.", { status: 426 });
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server, ["admins"]);
    server.send(JSON.stringify({ type: "ready", at: new Date().toISOString() }));
    return new Response(null, { status: 101, webSocket: client });
  }

  override webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): void {
    if (message !== "ping") ws.close(1008, "Client messages are not accepted.");
  }

  override webSocketError(ws: WebSocket): void {
    ws.close(1011, "WebSocket error.");
  }

  private initialize(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS app_config (
        id INTEGER PRIMARY KEY CHECK (id = 1), document TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS requests (
        id TEXT PRIMARY KEY, submission_nonce TEXT NOT NULL UNIQUE,
        identity_kind TEXT NOT NULL, identity TEXT NOT NULL, host TEXT NOT NULL,
        requested_url TEXT NOT NULL, justification TEXT NOT NULL, policy_kind TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER,
        decided_by TEXT,
        decided_by_source TEXT CHECK (decided_by_source IS NULL OR decided_by_source IN ('access-header', 'unknown')),
        decision_reason TEXT, grant_seconds INTEGER, user_agent TEXT, config_version INTEGER NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS requests_one_pending_scope
        ON requests(identity_kind, identity, host) WHERE status = 'pending';
      CREATE INDEX IF NOT EXISTS requests_queue ON requests(status, created_at DESC, id DESC);
      CREATE INDEX IF NOT EXISTS requests_created ON requests(created_at DESC, id DESC);
      CREATE INDEX IF NOT EXISTS requests_identity_rate ON requests(identity_kind, identity, created_at DESC);
      CREATE INDEX IF NOT EXISTS requests_expiry ON requests(status, expires_at);
      CREATE TABLE IF NOT EXISTS grants (
        id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
        identity_kind TEXT NOT NULL, identity TEXT NOT NULL, host TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('active', 'expired', 'revoked')),
        granted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        granted_by TEXT NOT NULL,
        granted_by_source TEXT NOT NULL CHECK (granted_by_source IN ('access-header', 'unknown')),
        revoked_at INTEGER, revoked_by TEXT,
        revoked_by_source TEXT CHECK (revoked_by_source IS NULL OR revoked_by_source IN ('access-header', 'unknown'))
      );
      CREATE UNIQUE INDEX IF NOT EXISTS grants_one_active_scope
        ON grants(identity_kind, identity, host) WHERE status = 'active';
      CREATE INDEX IF NOT EXISTS grants_list ON grants(status, granted_at DESC, id DESC);
      CREATE INDEX IF NOT EXISTS grants_expiry ON grants(status, expires_at);
      CREATE TABLE IF NOT EXISTS denial_holds (
        id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
        identity_kind TEXT NOT NULL, identity TEXT NOT NULL, host TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('active', 'expired', 'cleared')),
        reason TEXT NOT NULL, denied_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        denied_by TEXT NOT NULL,
        denied_by_source TEXT NOT NULL CHECK (denied_by_source IN ('access-header', 'unknown')),
        cleared_at INTEGER, cleared_by TEXT,
        cleared_by_source TEXT CHECK (cleared_by_source IS NULL OR cleared_by_source IN ('access-header', 'unknown'))
      );
      CREATE UNIQUE INDEX IF NOT EXISTS holds_one_active_scope
        ON denial_holds(identity_kind, identity, host) WHERE status = 'active';
      CREATE INDEX IF NOT EXISTS holds_list ON denial_holds(status, denied_at DESC, id DESC);
      CREATE INDEX IF NOT EXISTS holds_expiry ON denial_holds(status, expires_at);
    `);
    this.sql.exec(
      "INSERT OR IGNORE INTO app_config (id, document) VALUES (1, ?)",
      JSON.stringify(DEFAULT_CONFIG),
    );
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS schema_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL
      );
      INSERT OR IGNORE INTO schema_meta (id, version) VALUES (1, 1);
    `);
    const version = this.one<{ version: number }>("SELECT version FROM schema_meta WHERE id = 1")?.version ?? 1;
    if (version < 2) this.migrateToEmailIdentity();
  }

  /** Schema v2: identity moves from source IP to Gateway user email; IP-keyed state is purged. */
  private migrateToEmailIdentity(): void {
    const started = Date.now();
    const count = (table: "requests" | "grants" | "denial_holds") =>
      this.one<{ count: number }>(`SELECT COUNT(*) AS count FROM ${table} WHERE identity_kind = 'ip'`)?.count ?? 0;
    const purged = { requests: count("requests"), grants: count("grants"), holds: count("denial_holds") };
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM grants WHERE identity_kind = 'ip'");
      this.sql.exec("DELETE FROM denial_holds WHERE identity_kind = 'ip'");
      this.sql.exec("DELETE FROM requests WHERE identity_kind = 'ip'");
      this.sql.exec("ALTER TABLE requests ADD COLUMN identity_name TEXT");
      this.sql.exec("UPDATE schema_meta SET version = ? WHERE id = 1", SCHEMA_VERSION);
    });
    log("pj_schema_migrated", {
      ...operationFields(crypto.randomUUID(), started),
      schema_version: SCHEMA_VERSION,
      purged_requests: purged.requests,
      purged_grants: purged.grants,
      purged_holds: purged.holds,
    });
  }

  private readConfig(): PolicyConfig {
    const row = this.one<{ document: string }>("SELECT document FROM app_config WHERE id = 1");
    if (!row) throw new Error("config missing");
    let parsed: unknown;
    try {
      parsed = JSON.parse(row.document);
    } catch {
      this.throwCorruptConfig();
    }
    if (!isRecord(parsed) || !Number.isInteger(parsed.version) || typeof parsed.updatedAt !== "string") {
      this.throwCorruptConfig();
    }
    const validation = validateConfig(parsed);
    if (!validation.value) this.throwCorruptConfig();
    return {
      ...validation.value,
      version: parsed.version as number,
      updatedAt: parsed.updatedAt,
    };
  }

  private throwCorruptConfig(): never {
    const error = new Error("config corrupt");
    logError("config_corrupt", error, operationFields(crypto.randomUUID(), Date.now(), "error"));
    throw error;
  }

  private findActiveGrant(input: EvaluateInput): GrantRow | null {
    return this.one<GrantRow>(
      `SELECT * FROM grants WHERE identity_kind = ? AND identity = ? AND host = ? AND status = 'active' LIMIT 1`,
      input.identityKind,
      input.identity,
      input.host,
    );
  }

  private findActiveHold(input: EvaluateInput): HoldRow | null {
    return this.one<HoldRow>(
      `SELECT * FROM denial_holds WHERE identity_kind = ? AND identity = ? AND host = ? AND status = 'active' LIMIT 1`,
      input.identityKind,
      input.identity,
      input.host,
    );
  }

  private findPendingRequest(input: EvaluateInput): RequestRow | null {
    return this.one<RequestRow>(
      `SELECT * FROM requests WHERE identity_kind = ? AND identity = ? AND host = ? AND status = 'pending' LIMIT 1`,
      input.identityKind,
      input.identity,
      input.host,
    );
  }

  private toRequestView(
    row: RequestRow,
    suppliedGrant?: GrantRow | null,
    suppliedHold?: HoldRow | null,
  ): RequestView {
    const grant = suppliedGrant === undefined
      ? this.one<GrantRow>("SELECT * FROM grants WHERE request_id = ?", row.id)
      : suppliedGrant;
    const hold = suppliedHold === undefined
      ? this.one<HoldRow>("SELECT * FROM denial_holds WHERE request_id = ?", row.id)
      : suppliedHold;
    return {
      id: row.id,
      status: row.status,
      identityKind: row.identity_kind,
      identity: row.identity,
      identityName: row.identity_name,
      host: row.host,
      requestedUrl: row.requested_url,
      justification: row.justification,
      policyKind: row.policy_kind,
      createdAt: iso(row.created_at),
      expiresAt: iso(row.expires_at),
      decidedAt: nullableIso(row.decided_at),
      decidedBy: row.decided_by,
      decidedBySource: row.decided_by_source,
      decisionReason: row.decision_reason,
      grantSeconds: row.grant_seconds,
      userAgent: row.user_agent,
      configVersion: row.config_version,
      grant: grant ? toGrantView(grant) : null,
      hold: hold ? toHoldView(hold) : null,
    };
  }

  private expireScope(input: EvaluateInput, now: number): void {
    this.sql.exec(
      `UPDATE requests SET status = 'expired' WHERE identity_kind = ? AND identity = ? AND host = ?
       AND status = 'pending' AND expires_at <= ?`,
      input.identityKind,
      input.identity,
      input.host,
      now,
    );
    this.sql.exec(
      `UPDATE grants SET status = 'expired' WHERE identity_kind = ? AND identity = ? AND host = ?
       AND status = 'active' AND expires_at <= ?`,
      input.identityKind,
      input.identity,
      input.host,
      now,
    );
    this.sql.exec(
      `UPDATE denial_holds SET status = 'expired' WHERE identity_kind = ? AND identity = ? AND host = ?
       AND status = 'active' AND expires_at <= ?`,
      input.identityKind,
      input.identity,
      input.host,
      now,
    );
  }

  private expireRequest(id: string, now: number): void {
    this.sql.exec(
      "UPDATE requests SET status = 'expired' WHERE id = ? AND status = 'pending' AND expires_at <= ?",
      id,
      now,
    );
  }

  private expireAll(now: number): void {
    this.sql.exec("UPDATE requests SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?", now);
    this.sql.exec("UPDATE grants SET status = 'expired' WHERE status = 'active' AND expires_at <= ?", now);
    this.sql.exec("UPDATE denial_holds SET status = 'expired' WHERE status = 'active' AND expires_at <= ?", now);
  }

  private async listState<
    Row extends Record<string, SqlStorageValue> & { id: string; status: string; host: string },
    View,
  >(
    table: "grants" | "denial_holds",
    dateColumn: "granted_at" | "denied_at",
    statuses: string[],
    input: ListInput,
    convert: (row: Row) => View,
  ): Promise<ListResult<View>> {
    validateListInput(input, statuses);
    this.expireAll(Date.now());
    const limit = normalizeLimit(input.limit);
    const cursor = decodeCursor(input.cursor, "desc");
    const where: string[] = [];
    const params: (string | number)[] = [];
    if (input.status) {
      where.push("status = ?");
      params.push(input.status);
    }
    if (input.host) {
      where.push("host = ?");
      params.push(input.host);
    }
    if (cursor) {
      where.push(`(${dateColumn} < ? OR (${dateColumn} = ? AND id < ?))`);
      params.push(cursor.at, cursor.at, cursor.id);
    }
    const sql = `SELECT * FROM ${table}${where.length ? ` WHERE ${where.join(" AND ")}` : ""}
      ORDER BY ${dateColumn} DESC, id DESC LIMIT ?`;
    const rows = this.sql.exec<Row>(sql, ...params, limit + 1).toArray();
    const listComplete = rows.length <= limit;
    const page = rows.slice(0, limit);
    const last = page.at(-1);
    const lastAt = last ? Number(last[dateColumn]) : 0;
    return {
      entries: page.map(convert),
      cursor: !listComplete && last ? encodeCursor({ at: lastAt, id: last.id, direction: "desc" }) : null,
      listComplete,
    };
  }

  private async scheduleAlarm(now = Date.now()): Promise<void> {
    const config = this.readConfig();
    const retentionMs = config.retentionDays * DAY_MS;
    const candidates = [
      this.min("SELECT MIN(expires_at) AS value FROM requests WHERE status = 'pending'"),
      this.min("SELECT MIN(expires_at) AS value FROM grants WHERE status = 'active'"),
      this.min("SELECT MIN(expires_at) AS value FROM denial_holds WHERE status = 'active'"),
      this.min(
        `SELECT MIN(COALESCE(decided_at, expires_at) + ?) AS value FROM requests
         WHERE status != 'pending'
         AND NOT EXISTS (SELECT 1 FROM grants WHERE grants.request_id = requests.id)
         AND NOT EXISTS (SELECT 1 FROM denial_holds WHERE denial_holds.request_id = requests.id)`,
        retentionMs,
      ),
      this.min(
        "SELECT MIN(COALESCE(revoked_at, expires_at) + ?) AS value FROM grants WHERE status != 'active'",
        retentionMs,
      ),
      this.min(
        "SELECT MIN(COALESCE(cleared_at, expires_at) + ?) AS value FROM denial_holds WHERE status != 'active'",
        retentionMs,
      ),
    ].filter((value): value is number => value !== null);

    if (!candidates.length) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    await this.ctx.storage.setAlarm(Math.max(now + 1000, Math.min(Math.min(...candidates), now + DAY_MS)));
  }

  private min(query: string, ...params: number[]): number | null {
    return this.one<{ value: number | null }>(query, ...params)?.value ?? null;
  }

  private resolveHistoricalPolicy(config: PolicyConfig, requestId: string): Policy {
    const request = this.one<Pick<RequestRow, "policy_kind">>(
      "SELECT policy_kind FROM requests WHERE id = ?",
      requestId,
    );
    if (request && Object.hasOwn(config.policies, request.policy_kind)) {
      return config.policies[request.policy_kind]!;
    }
    return Object.hasOwn(config.policies, config.defaultPolicyKind)
      ? config.policies[config.defaultPolicyKind]!
      : DEFAULT_CONFIG.policies.generic!;
  }

  private relatedByRequest<Row extends Record<string, SqlStorageValue> & { request_id: string }>(
    table: "grants" | "denial_holds",
    requestIds: string[],
  ): Map<string, Row> {
    if (!requestIds.length) return new Map();
    const placeholders = requestIds.map(() => "?").join(",");
    const rows = this.sql.exec<Row>(
      `SELECT * FROM ${table} WHERE request_id IN (${placeholders})`,
      ...requestIds,
    ).toArray();
    return new Map(rows.map((row) => [row.request_id, row]));
  }

  private broadcast(event: Record<string, unknown>): void {
    const payload = JSON.stringify(event);
    for (const socket of this.ctx.getWebSockets("admins")) {
      try {
        socket.send(payload);
      } catch {
        socket.close(1011, "Delivery failed.");
      }
    }
  }

  private one<T>(query: string, ...params: (string | number)[]): T | null {
    const row = this.sql.exec<Record<string, SqlStorageValue>>(query, ...params).toArray()[0];
    return row ? (row as T) : null;
  }
}

function validateScope(input: unknown): asserts input is EvaluateInput {
  if (
    !isRecord(input) ||
    !validIdentity(input.identityKind, input.identity) ||
    typeof input.host !== "string" ||
    normalizeConfiguredHost(input.host) !== input.host
  ) {
    throw new RangeError("invalid scope");
  }
}

function validIdentity(kind: unknown, identity: unknown): boolean {
  return (
    kind === "email" &&
    typeof identity === "string" &&
    identity.length >= 3 &&
    identity.length <= MAX_EMAIL_LENGTH &&
    identity === identity.trim().toLowerCase() &&
    EMAIL.test(identity)
  );
}

function validIdentityName(value: unknown): boolean {
  return (
    value === null ||
    (typeof value === "string" &&
      value.length > 0 &&
      value === value.trim() &&
      [...value].length <= MAX_IDENTITY_NAME_LENGTH &&
      !/[\u0000-\u001f\u007f]/.test(value))
  );
}

function validateStatusInput(input: unknown): asserts input is StatusInput {
  validateScope(input);
  if (!("requestId" in input) || !validId(input.requestId)) throw new RangeError("invalid request ID");
}

function validateListInput(input: unknown, statuses: string[]): asserts input is ListInput {
  if (!isRecord(input)) throw new RangeError("list input is invalid");
  if (input.status !== undefined && (typeof input.status !== "string" || !statuses.includes(input.status))) {
    throw new RangeError("status is invalid");
  }
  if (input.host !== undefined && (typeof input.host !== "string" || normalizeConfiguredHost(input.host) !== input.host)) {
    throw new RangeError("host is invalid");
  }
  if (input.cursor !== undefined && (typeof input.cursor !== "string" || input.cursor.length < 1 || input.cursor.length > 4096)) {
    throw new RangeError("cursor is invalid");
  }
  if (input.limit !== undefined && typeof input.limit !== "number") throw new RangeError("limit is invalid");
}

function validateActor(actor: unknown): asserts actor is Actor {
  if (
    !isRecord(actor) ||
    (actor.source !== "access-header" && actor.source !== "unknown") ||
    typeof actor.value !== "string" ||
    !actor.value ||
    actor.value.trim() !== actor.value ||
    actor.value.length > 254
  ) {
    throw new RangeError("invalid actor");
  }
}

function validSubmit(input: unknown): input is SubmitInput {
  if (
    !isRecord(input) ||
    !validIdentity(input.identityKind, input.identity) ||
    !validIdentityName(input.identityName) ||
    typeof input.host !== "string" ||
    normalizeConfiguredHost(input.host) !== input.host ||
    typeof input.justification !== "string" ||
    typeof input.submissionNonce !== "string" ||
    typeof input.requestedUrl !== "string" ||
    typeof input.policyKind !== "string" ||
    typeof input.userAgent !== "string"
  ) {
    return false;
  }
  const count = [...input.justification.trim()].length;
  return (
    count >= 20 &&
    count <= 1000 &&
    /^[A-Za-z0-9_-]{22}$/.test(input.submissionNonce) &&
    input.requestedUrl.length >= 1 &&
    input.requestedUrl.length <= 2048 &&
    validRequestedUrl(input.requestedUrl, input.host) &&
    input.policyKind.length >= 1 &&
    input.policyKind.length <= 64 &&
    Number.isInteger(input.configVersion)
  );
}

function validRequestedUrl(value: string, host: string): boolean {
  if (value.includes("?") || value.includes("#")) return false;
  try {
    const url = new URL(value);
    const normalizedUrlHost = canonicalizeHost(url.hostname);
    return (
      value === `${url.origin}${url.pathname}` &&
      (url.protocol === "http:" || url.protocol === "https:") &&
      !url.username &&
      !url.password &&
      normalizedUrlHost === host
    );
  } catch {
    return false;
  }
}

function sanitizeUserAgent(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 512);
}

function decisionError(request: RequestRow | null): StoreResult<never> | null {
  if (!request) return notFound("Request not found.");
  if (request.status === "expired") {
    return { ok: false, code: "request_expired", message: "This request has expired." };
  }
  if (request.status !== "pending") {
    return { ok: false, code: "already_decided", message: "This request has already been decided." };
  }
  return null;
}

function notFound(message: string): StoreResult<never> {
  return { ok: false, code: "not_found", message };
}

function notActive(message: string): StoreResult<never> {
  return { ok: false, code: "not_active", message };
}

function toGrantView(row: GrantRow): GrantView {
  return {
    id: row.id,
    requestId: row.request_id,
    identityKind: row.identity_kind,
    identity: row.identity,
    host: row.host,
    status: row.status,
    grantedAt: iso(row.granted_at),
    expiresAt: iso(row.expires_at),
    grantedBy: row.granted_by,
    grantedBySource: row.granted_by_source,
    revokedAt: nullableIso(row.revoked_at),
    revokedBy: row.revoked_by,
    revokedBySource: row.revoked_by_source,
  };
}

function toHoldView(row: HoldRow): HoldView {
  return {
    id: row.id,
    requestId: row.request_id,
    identityKind: row.identity_kind,
    identity: row.identity,
    host: row.host,
    status: row.status,
    reason: row.reason,
    deniedAt: iso(row.denied_at),
    expiresAt: iso(row.expires_at),
    deniedBy: row.denied_by,
    deniedBySource: row.denied_by_source,
    clearedAt: nullableIso(row.cleared_at),
    clearedBy: row.cleared_by,
    clearedBySource: row.cleared_by_source,
  };
}

function iso(value: number): string {
  return new Date(value).toISOString();
}

function nullableIso(value: number | null): string | null {
  return value === null ? null : iso(value);
}

function validId(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 64;
}

function operationFields(
  invocationId: string,
  started: number,
  outcome = "complete",
): Record<string, unknown> {
  return { invocation_id: invocationId, duration_ms: Date.now() - started, outcome };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
