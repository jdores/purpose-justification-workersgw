import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import type { GateStore } from "../src/index.js";
import { DEFAULT_CONFIG } from "../src/store/config.js";
import type { ConfigInput, SubmitInput } from "../src/types.js";
import { ACTOR, scope, store, submission } from "./helpers.js";

function config(overrides: Partial<ConfigInput> = {}): ConfigInput {
  return {
    defaultGrantSeconds: DEFAULT_CONFIG.defaultGrantSeconds,
    maxGrantSeconds: DEFAULT_CONFIG.maxGrantSeconds,
    denyHoldSeconds: DEFAULT_CONFIG.denyHoldSeconds,
    pendingExpirySeconds: DEFAULT_CONFIG.pendingExpirySeconds,
    retentionDays: DEFAULT_CONFIG.retentionDays,
    submissionLimitPerHour: DEFAULT_CONFIG.submissionLimitPerHour,
    defaultPolicyKind: DEFAULT_CONFIG.defaultPolicyKind,
    policies: DEFAULT_CONFIG.policies,
    hostPolicies: DEFAULT_CONFIG.hostPolicies,
    ...overrides,
  };
}

async function createPending(stub: ReturnType<typeof store>, overrides: Partial<SubmitInput> = {}) {
  const result = await stub.submit(submission(overrides));
  if (result.state !== "created") throw new Error(`Expected a created request, received ${result.state}`);
  return result.request;
}

async function within<T>(promise: Promise<T>, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error(`Timed out: ${label}`)), 2_000)),
  ]);
}

describe("GateStore configuration", () => {
  it("initializes defaults once and preserves configuration across eviction", async () => {
    const stub = store();
    expect(await stub.getConfig()).toEqual(DEFAULT_CONFIG);

    const work = { ...DEFAULT_CONFIG.policies.generic!, kind: "work", formTitle: "Business purpose" };
    const saved = await stub.putConfig(config({
      defaultPolicyKind: "work",
      policies: { generic: DEFAULT_CONFIG.policies.generic!, work },
      hostPolicies: { "example.com": "generic" },
    }), ACTOR);
    expect(saved.ok).toBe(true);
    if (!saved.ok) return;
    expect(saved.value.version).toBe(2);
    expect(saved.value.updatedAt).not.toBe(DEFAULT_CONFIG.updatedAt);

    expect((await stub.evaluate(scope("user@example.com", "example.com"))).policy.kind).toBe("generic");
    expect((await stub.evaluate(scope("user@example.com", "child.example.com"))).policy.kind).toBe("generic");
    expect((await stub.evaluate(scope("user@example.com", "other.example"))).policy.kind).toBe("work");

    await evictDurableObject(stub);
    expect((await stub.getConfig()).version).toBe(2);
  });

  it("keeps a pending or denied request on its recorded policy with a safe fallback", async () => {
    const stub = store();
    const historical = { ...DEFAULT_CONFIG.policies.generic!, kind: "historical", pendingTitle: "Historical pending" };
    const current = { ...DEFAULT_CONFIG.policies.generic!, kind: "current", pendingTitle: "Current pending" };
    const firstConfig = await stub.putConfig(config({
      policies: { generic: DEFAULT_CONFIG.policies.generic!, historical, current },
      hostPolicies: { "example.com": "historical" },
    }), ACTOR);
    if (!firstConfig.ok) throw new Error("Expected valid historical config");
    const request = await createPending(stub, {
      policyKind: "historical",
      configVersion: firstConfig.value.version,
    });

    const remapped = await stub.putConfig(config({
      defaultPolicyKind: "current",
      policies: { generic: DEFAULT_CONFIG.policies.generic!, historical, current },
      hostPolicies: { "example.com": "current" },
    }), ACTOR);
    if (!remapped.ok) throw new Error("Expected valid remapped config");
    expect((await stub.evaluate(scope())).policy.pendingTitle).toBe("Historical pending");

    await stub.deny(request.id, "A valid historical denial reason.", ACTOR);
    const removed = await stub.putConfig(config({
      defaultPolicyKind: "current",
      policies: { generic: DEFAULT_CONFIG.policies.generic!, current },
      hostPolicies: { "example.com": "current" },
    }), ACTOR);
    if (!removed.ok) throw new Error("Expected valid fallback config");
    expect((await stub.evaluate(scope())).policy.pendingTitle).toBe("Current pending");
  });

  it("rejects invalid and oversized configuration and increments reset versions", async () => {
    const stub = store();
    const invalid = await stub.putConfig(config({ defaultGrantSeconds: 30 }), ACTOR);
    expect(invalid).toMatchObject({ ok: false, code: "validation_failed" });

    const policies = Object.fromEntries(Array.from({ length: 30 }, (_, index) => {
      const kind = `policy${index}`;
      return [kind, {
        kind,
        formTitle: "x".repeat(200),
        formPrompt: "x".repeat(1000),
        pendingTitle: "x".repeat(200),
        pendingMessage: "x".repeat(1000),
        blockTitle: "x".repeat(200),
        blockMessage: "x".repeat(1000),
      }];
    }));
    const oversized = await stub.putConfig(config({ defaultPolicyKind: "policy0", policies }), ACTOR);
    expect(oversized).toMatchObject({ ok: false, code: "validation_failed" });
    if (!oversized.ok) expect(oversized.details).toContain("config must not exceed 65536 bytes");

    const reset = await stub.resetConfig(ACTOR);
    expect(reset.ok).toBe(true);
    if (reset.ok) expect(reset.value.version).toBe(2);
  });

  it("fails closed when stored configuration is corrupt", async () => {
    const stub = store();
    await stub.getConfig();
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("UPDATE app_config SET document = ? WHERE id = 1", "not-json");
    });
    const message = await runInDurableObject(stub, async (instance) => {
      try {
        await instance.getConfig();
        return null;
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(message).toBe("config corrupt");
  });
});

describe("GateStore schema migration", () => {
  it("purges IP-keyed state once and adds the identity name column", async () => {
    const stub = store();
    const kept = await createPending(stub, { host: "kept.example.com", requestedUrl: "https://kept.example.com/" });
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      sql.exec("ALTER TABLE requests DROP COLUMN identity_name");
      sql.exec("UPDATE schema_meta SET version = 1 WHERE id = 1");
      const now = Date.now();
      for (const [id, status] of [["ip-pending", "pending"], ["ip-approved", "approved"], ["ip-denied", "denied"]] as const) {
        sql.exec(
          `INSERT INTO requests (id, submission_nonce, identity_kind, identity, host, requested_url, justification,
           policy_kind, status, created_at, expires_at, config_version)
           VALUES (?, ?, 'ip', '192.0.2.10', ?, ?, 'Legacy justification text for testing.', 'generic', ?, ?, ?, 1)`,
          id, `nonce-${id}`, `${id}.example.com`, `https://${id}.example.com/`, status, now, now + 3_600_000,
        );
      }
      sql.exec(
        `INSERT INTO grants (id, request_id, identity_kind, identity, host, status, granted_at, expires_at, granted_by, granted_by_source)
         VALUES ('ip-grant', 'ip-approved', 'ip', '192.0.2.10', 'ip-approved.example.com', 'active', ?, ?, 'admin', 'unknown')`,
        now, now + 3_600_000,
      );
      sql.exec(
        `INSERT INTO denial_holds (id, request_id, identity_kind, identity, host, status, reason, denied_at, expires_at, denied_by, denied_by_source)
         VALUES ('ip-hold', 'ip-denied', 'ip', '192.0.2.10', 'ip-denied.example.com', 'active', 'Legacy reason', ?, ?, 'admin', 'unknown')`,
        now, now + 3_600_000,
      );
    });

    const consoleLog = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      await evictDurableObject(stub);
      expect((await stub.listRequests({})).entries.map((entry) => entry.id)).toEqual([kept.id]);
      expect(consoleLog).toHaveBeenCalledWith(expect.objectContaining({
        event: "pj_schema_migrated",
        schema_version: 2,
        purged_requests: 3,
        purged_grants: 1,
        purged_holds: 1,
      }));
    } finally {
      consoleLog.mockRestore();
    }
    expect((await stub.listGrants({})).entries).toHaveLength(0);
    expect((await stub.listHolds({})).entries).toHaveLength(0);
    expect(await stub.getRequest(kept.id)).toMatchObject({ identityName: null });

    const version = await runInDurableObject(stub, (_instance, state) =>
      state.storage.sql.exec<{ version: number }>("SELECT version FROM schema_meta WHERE id = 1").one().version);
    expect(version).toBe(2);

    await evictDurableObject(stub);
    expect((await stub.listRequests({})).entries).toHaveLength(1);
  });
});

describe("GateStore request state", () => {
  it("creates, deduplicates, sanitizes, and paginates pending requests", async () => {
    const stub = store();
    expect(await stub.evaluate(scope())).toMatchObject({ state: "none" });

    const firstInput = submission({ userAgent: `browser\u0000-agent${"x".repeat(600)}` });
    const first = await stub.submit(firstInput);
    expect(first.state).toBe("created");
    if (first.state !== "created") return;
    expect(first.request.justification).toBe(firstInput.justification);
    expect(first.request).toMatchObject({ identityKind: "email", identity: "user@example.com", identityName: "Example User" });
    expect(first.request.userAgent).not.toContain("\u0000");
    expect(first.request.userAgent?.length).toBe(512);

    const replay = await stub.submit({ ...firstInput, justification: "A replacement justification that must not be stored." });
    expect(replay).toMatchObject({ state: "existing", request: { id: first.request.id } });
    if (replay.state === "existing") expect(replay.request.justification).toBe(firstInput.justification);

    const sameScope = await stub.submit(submission({ justification: "Another valid purpose that must not replace the first." }));
    expect(sameScope).toMatchObject({ state: "existing", request: { id: first.request.id } });

    await createPending(stub, { host: "second.example.com", requestedUrl: "https://second.example.com/path" });
    await createPending(stub, { host: "third.example.com", requestedUrl: "https://third.example.com/path" });
    const page1 = await stub.listRequests({ status: "pending", limit: 2 });
    expect(page1.entries).toHaveLength(2);
    expect(page1.listComplete).toBe(false);
    expect(page1.cursor).not.toBeNull();
    if (!page1.cursor) throw new Error("Expected another page");
    const page2 = await stub.listRequests({ status: "pending", limit: 2, cursor: page1.cursor });
    expect(page2.entries).toHaveLength(1);
    expect(new Set([...page1.entries, ...page2.entries].map((item) => item.id)).size).toBe(3);

    expect(await stub.getRequest(first.request.id)).toMatchObject({ id: first.request.id, status: "pending" });
    expect(await stub.getRequest("x".repeat(65))).toBeNull();
    const withoutName = await stub.submit(submission({
      host: "noname.example.com",
      requestedUrl: "https://noname.example.com/",
      identityName: null,
    }));
    expect(withoutName).toMatchObject({ state: "created", request: { identityName: null } });
    const listError = await runInDurableObject(stub, async (instance) => {
      try {
        await instance.listRequests({ status: "unknown" });
        return null;
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(listError).toBe("status is invalid");
  });

  it("validates submissions, scopes, config versions, and rate limits", async () => {
    const stub = store();
    const scopeError = await runInDurableObject(stub, async (instance) => {
      try {
        await instance.evaluate({ ...scope(), identityKind: "ip" as "email" });
        return null;
      } catch (error) {
        return error instanceof Error ? error.message : "unknown";
      }
    });
    expect(scopeError).toBe("invalid scope");
    expect(await stub.submit(submission({ justification: "too short" }))).toEqual({ state: "invalid" });
    expect(await stub.submit(submission({ configVersion: 99 }))).toEqual({ state: "config_changed" });

    const saved = await stub.putConfig(config({ submissionLimitPerHour: 1 }), ACTOR);
    if (!saved.ok) throw new Error("Expected valid configuration");
    const created = await stub.submit(submission({ configVersion: saved.value.version }));
    expect(created.state).toBe("created");
    const duplicate = await stub.submit(submission({ configVersion: saved.value.version }));
    expect(duplicate.state).toBe("existing");
    const limited = await stub.submit(submission({
      host: "other.example.com",
      requestedUrl: "https://other.example.com/",
      configVersion: saved.value.version,
    }));
    expect(limited).toMatchObject({ state: "rate_limited" });
    if (limited.state === "rate_limited") expect(limited.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("recovers a scope-matching nonce replay before rejecting a stale config", async () => {
    const stub = store();
    const input = submission();
    const created = await stub.submit(input);
    if (created.state !== "created") throw new Error("Expected a created request");

    const saved = await stub.putConfig(config(), ACTOR);
    if (!saved.ok) throw new Error("Expected valid configuration");
    expect(saved.value.version).toBeGreaterThan(input.configVersion);

    expect(await stub.submit(input)).toMatchObject({ state: "existing", request: { id: created.request.id } });
    expect(await stub.submit({ ...input, identity: "other@example.com" })).toEqual({ state: "invalid" });
  });

  it("rejects malformed runtime submissions without persisting them", async () => {
    const stub = store();
    const malformed: unknown[] = [
      { ...submission(), requestedUrl: "https://example.com/private?token=secret" },
      { ...submission(), requestedUrl: "https://example.com/private#fragment" },
      { ...submission(), requestedUrl: "https://other.example.com/private" },
      { ...submission(), host: "WWW.Example.com", requestedUrl: "https://WWW.Example.com/private" },
      { ...submission(), submissionNonce: null },
      { ...submission(), submissionNonce: "not-a-16-byte-nonce" },
      { ...submission(), userAgent: null },
      { ...submission(), identity: "User@Example.com" },
      { ...submission(), identity: "not-an-email" },
      { ...submission(), identityKind: "ip", identity: "192.0.2.10" },
      { ...submission(), identityName: "" },
      { ...submission(), identityName: " padded " },
      { ...submission(), identityName: "x".repeat(201) },
      { ...submission(), identityName: "bad\u0000name" },
      { ...submission(), identityName: 42 },
      null,
    ];

    for (const input of malformed) {
      expect(await stub.submit(input as SubmitInput)).toEqual({ state: "invalid" });
    }
    expect((await stub.listRequests({})).entries).toHaveLength(0);
  });

  it("returns active grant and hold states and rejects a terminal nonce replay", async () => {
    const stub = store();
    const grantInput = submission();
    const grantRequest = await stub.submit(grantInput);
    if (grantRequest.state !== "created") throw new Error("Expected grant request");
    const approved = await stub.approve(grantRequest.request.id, undefined, ACTOR);
    if (!approved.ok) throw new Error("Expected approval");
    expect(approved.value.grant.expiresAt).toBeTruthy();
    expect(await stub.submit(submission())).toMatchObject({ state: "granted" });
    expect((await stub.listRequests({})).entries[0]).toMatchObject({
      id: grantRequest.request.id,
      grant: { id: approved.value.grant.id },
    });

    await stub.revokeGrant(approved.value.grant.id, ACTOR);
    expect(await stub.submit(grantInput)).toEqual({ state: "invalid" });

    const holdRequest = await createPending(stub);
    const denied = await stub.deny(holdRequest.id, "A valid active denial reason.", ACTOR);
    if (!denied.ok) throw new Error("Expected denial");
    expect(await stub.submit(submission())).toMatchObject({ state: "denied", hold: { id: denied.value.hold.id } });
    expect((await stub.listRequests({})).entries[0]).toMatchObject({
      id: holdRequest.id,
      hold: { id: denied.value.hold.id },
    });
  });

  it("approves atomically, evaluates the exact scope, and revokes idempotently", async () => {
    const stub = store();
    const request = await createPending(stub);
    expect(await stub.status({ ...scope(), requestId: request.id })).toMatchObject({ state: "pending" });
    expect(await stub.approve("missing", 60, ACTOR)).toMatchObject({ ok: false, code: "not_found" });
    expect(await stub.approve(request.id, 59, ACTOR)).toMatchObject({ ok: false, code: "validation_failed" });

    const approved = await stub.approve(request.id, 120, ACTOR);
    expect(approved.ok).toBe(true);
    if (!approved.ok) return;
    expect(await stub.status({ ...scope(), requestId: request.id })).toMatchObject({
      state: "approved",
      requestId: request.id,
    });
    expect(await stub.evaluate(scope())).toMatchObject({ state: "granted", grant: { id: approved.value.grant.id } });
    expect(await stub.evaluate(scope("user@example.com", "sibling.example.com"))).toMatchObject({ state: "none" });
    expect(await stub.evaluate(scope("other@example.com", "example.com"))).toMatchObject({ state: "none" });
    expect(await stub.approve(request.id, 120, ACTOR)).toMatchObject({ ok: false, code: "already_decided" });

    const active = await stub.listGrants({ status: "active", host: "example.com", limit: 1 });
    expect(active.entries).toHaveLength(1);
    const revoked = await stub.revokeGrant(approved.value.grant.id, ACTOR);
    expect(revoked).toMatchObject({ ok: true, value: { status: "revoked" } });
    expect(await stub.revokeGrant(approved.value.grant.id, ACTOR)).toMatchObject({ ok: true, value: { status: "revoked" } });
    expect(await stub.revokeGrant("missing", ACTOR)).toMatchObject({ ok: false, code: "not_found" });
    expect(await stub.evaluate(scope())).toMatchObject({ state: "none" });
  });

  it("denies, exposes status, and clears holds idempotently", async () => {
    const stub = store();
    const request = await createPending(stub);
    expect(await stub.deny(request.id, "no", ACTOR)).toMatchObject({ ok: false, code: "validation_failed" });
    expect(await stub.deny("missing", "A valid denial reason.", ACTOR)).toMatchObject({ ok: false, code: "not_found" });

    const denied = await stub.deny(request.id, "  This destination is not approved for this work.  ", ACTOR);
    expect(denied.ok).toBe(true);
    if (!denied.ok) return;
    expect(denied.value.hold.reason).toBe("This destination is not approved for this work.");
    expect(await stub.status({ ...scope(), requestId: request.id })).toMatchObject({
      state: "denied",
      hold: { reason: denied.value.hold.reason },
    });
    expect(await stub.status({ ...scope("other@example.com"), requestId: request.id })).toEqual({ state: "invalid" });
    expect(await stub.evaluate(scope())).toMatchObject({ state: "denied" });
    expect((await stub.listHolds({ status: "active" })).entries).toHaveLength(1);

    expect(await stub.clearHold(denied.value.hold.id, ACTOR)).toMatchObject({ ok: true, value: { status: "cleared" } });
    expect(await stub.clearHold(denied.value.hold.id, ACTOR)).toMatchObject({ ok: true, value: { status: "cleared" } });
    expect(await stub.clearHold("missing", ACTOR)).toMatchObject({ ok: false, code: "not_found" });
    expect(await stub.evaluate(scope())).toMatchObject({ state: "none" });
  });

  it("serializes competing admin decisions", async () => {
    const stub = store();
    const request = await createPending(stub);
    const results = await Promise.all([
      stub.approve(request.id, 120, ACTOR),
      stub.deny(request.id, "A valid competing denial reason.", ACTOR),
    ]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(results.filter((result) => !result.ok && result.code === "already_decided")).toHaveLength(1);
  });

  it("paginates request history, grants, and holds in descending order", async () => {
    const stub = store();
    for (let index = 0; index < 3; index += 1) {
      const host = `host${index}.example.com`;
      const item = await createPending(stub, { host, requestedUrl: `https://${host}/` });
      await stub.approve(item.id, 120, ACTOR);
    }
    const requestPage = await stub.listRequests({ limit: 1 });
    expect(requestPage.cursor).not.toBeNull();
    if (!requestPage.cursor) throw new Error("Expected request cursor");
    expect((await stub.listRequests({ limit: 1, cursor: requestPage.cursor })).entries).toHaveLength(1);

    const grantPage = await stub.listGrants({ limit: 1 });
    expect(grantPage.cursor).not.toBeNull();
    if (!grantPage.cursor) throw new Error("Expected grant cursor");
    expect((await stub.listGrants({ limit: 1, cursor: grantPage.cursor })).entries).toHaveLength(1);

    await expectInvalidInside(stub, (instance) => instance.listGrants({ status: "invalid" }), "status is invalid");
    await expectInvalidInside(stub, (instance) => instance.listHolds({ status: "invalid" }), "status is invalid");
  });
});

describe("GateStore expiry and alarms", () => {
  it("expires pending requests, grants, and holds lazily", async () => {
    const stub = store();
    const pending = await createPending(stub);
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("UPDATE requests SET expires_at = ? WHERE id = ?", Date.now() - 1, pending.id);
    });
    expect(await stub.evaluate(scope())).toMatchObject({ state: "none" });
    expect(await stub.status({ ...scope(), requestId: pending.id })).toEqual({ state: "expired", requestId: pending.id });
    expect(await stub.approve(pending.id, 120, ACTOR)).toMatchObject({ ok: false, code: "request_expired" });

    const grantRequest = await createPending(stub, { host: "grant.example.com", requestedUrl: "https://grant.example.com/" });
    const approved = await stub.approve(grantRequest.id, 120, ACTOR);
    if (!approved.ok) throw new Error("Expected approval");
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("UPDATE grants SET expires_at = ? WHERE id = ?", Date.now() - 1, approved.value.grant.id);
    });
    expect(await stub.revokeGrant(approved.value.grant.id, ACTOR)).toMatchObject({ ok: false, code: "not_active" });

    const holdRequest = await createPending(stub, { host: "hold.example.com", requestedUrl: "https://hold.example.com/" });
    const denied = await stub.deny(holdRequest.id, "A valid hold reason.", ACTOR);
    if (!denied.ok) throw new Error("Expected denial");
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("UPDATE denial_holds SET expires_at = ? WHERE id = ?", Date.now() - 1, denied.value.hold.id);
    });
    expect(await stub.clearHold(denied.value.hold.id, ACTOR)).toMatchObject({ ok: false, code: "not_active" });
  });

  it("runs scheduled cleanup and purges retained terminal state in dependency order", async () => {
    const stub = store();
    const request = await createPending(stub);
    const approved = await stub.approve(request.id, 120, ACTOR);
    if (!approved.ok) throw new Error("Expected approval");
    const old = Date.now() - 31 * 86_400_000;
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        "UPDATE grants SET status = 'revoked', revoked_at = ?, expires_at = ? WHERE id = ?",
        old,
        old,
        approved.value.grant.id,
      );
      state.storage.sql.exec("UPDATE requests SET decided_at = ?, expires_at = ? WHERE id = ?", old, old, request.id);
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(await stub.getRequest(request.id)).toBeNull();
    expect((await stub.listGrants({})).entries).toHaveLength(0);
  });

  it("does not reschedule every second when a retained request still has active dependent state", async () => {
    const stub = store();
    const request = await createPending(stub);
    const approved = await stub.approve(request.id, 3600, ACTOR);
    if (!approved.ok) throw new Error("Expected approval");
    const old = Date.now() - 31 * 86_400_000;
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("UPDATE requests SET decided_at = ? WHERE id = ?", old, request.id);
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const nextAlarm = await runInDurableObject(stub, (_instance, state) => state.storage.getAlarm());
    expect(nextAlarm).not.toBeNull();
    expect((nextAlarm ?? 0) - Date.now()).toBeGreaterThan(60_000);
  });
});

describe("GateStore RPC validation", () => {
  it("filters terminal request history before pagination", async () => {
    const stub = store();
    const approvedRequest = await createPending(stub, {
      host: "approved.example.com",
      requestedUrl: "https://approved.example.com/",
    });
    expect((await stub.approve(approvedRequest.id, undefined, ACTOR)).ok).toBe(true);
    await createPending(stub, {
      host: "pending.example.com",
      requestedUrl: "https://pending.example.com/",
    });

    const history = await stub.listRequests({ status: "terminal", limit: 1 });
    expect(history.entries).toHaveLength(1);
    expect(history.entries[0]).toMatchObject({ id: approvedRequest.id, status: "approved" });
    expect(history.listComplete).toBe(true);
  });

  it("rejects malformed public RPC inputs without touching storage", async () => {
    const stub = store();
    await expectInvalidInside(stub, (instance) => instance.evaluate(null as never), "invalid scope");
    await expectInvalidInside(
      stub,
      (instance) => instance.evaluate({ ...scope(), host: "WWW.Example.com" }),
      "invalid scope",
    );
    await expectInvalidInside(
      stub,
      (instance) => instance.status({ ...scope(), requestId: null } as never),
      "invalid request ID",
    );
    await expectInvalidInside(stub, (instance) => instance.listRequests(null as never), "list input is invalid");
    await expectInvalidInside(
      stub,
      (instance) => instance.listRequests({ host: "WWW.Example.com" }),
      "host is invalid",
    );
    await expectInvalidInside(
      stub,
      (instance) => instance.listGrants({ cursor: 42 } as never),
      "cursor is invalid",
    );
    await expectInvalidInside(
      stub,
      (instance) => instance.listHolds({ limit: "10" } as never),
      "limit is invalid",
    );
    await expectInvalidInside(
      stub,
      (instance) => instance.approve("missing", undefined, { value: 42, source: "unknown" } as never),
      "invalid actor",
    );
    expect(await stub.approve(null as never, undefined, ACTOR)).toMatchObject({ ok: false, code: "not_found" });
    expect(await stub.deny("missing", null as never, ACTOR)).toMatchObject({ ok: false, code: "validation_failed" });
    expect(await stub.revokeGrant(null as never, ACTOR)).toMatchObject({ ok: false, code: "not_found" });
    expect(await stub.clearHold(null as never, ACTOR)).toMatchObject({ ok: false, code: "not_found" });
    expect((await stub.listRequests({})).entries).toHaveLength(0);
  });
});

describe("GateStore WebSockets", () => {
  it("requires upgrades and broadcasts only non-sensitive hints across eviction", async () => {
    const stub = store();
    const notUpgrade = await stub.fetch("https://store.example/ws");
    expect(notUpgrade.status).toBe(426);
    await notUpgrade.text();

    const response = await stub.fetch("https://store.example/ws", { headers: { upgrade: "websocket" } });
    expect(response.status).toBe(101);
    const socket = response.webSocket;
    if (!socket) throw new Error("Expected a WebSocket");
    socket.accept();

    const message = () => new Promise<string>((resolve) => {
      socket.addEventListener("message", (event) => resolve(String(event.data)), { once: true });
    });
    expect(JSON.parse(await within(message(), "ready message"))).toMatchObject({ type: "ready" });

    await within(evictDurableObject(stub), "eviction");
    const afterEviction = message();
    const request = await createPending(stub);
    const event = await within(afterEviction, "broadcast after eviction");
    expect(JSON.parse(event)).toMatchObject({ type: "request.created", requestId: request.id });
    expect(event).not.toContain(request.justification);
    expect(event).not.toContain(request.identity);

    const pong = message();
    socket.send("ping");
    expect(await within(pong, "auto-response")).toBe("pong");
    const closed = new Promise<CloseEvent>((resolve) => {
      socket.addEventListener("close", (event) => resolve(event), { once: true });
    });
    socket.send("unsupported");
    expect((await within(closed, "unsupported message close")).code).toBe(1008);
  }, 15_000);
});

async function expectInvalidInside(
  stub: ReturnType<typeof store>,
  action: (instance: GateStore) => Promise<unknown>,
  expected: string,
): Promise<void> {
  const message = await runInDurableObject(stub, async (instance) => {
    try {
      await action(instance);
      return null;
    } catch (error) {
      return error instanceof Error ? error.message : "unknown";
    }
  });
  expect(message).toBe(expected);
}
