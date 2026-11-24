import { describe, expect, it } from "vitest";
import { handleAdmin } from "../src/admin/router.js";
import { DEFAULT_CONFIG } from "../src/store/config.js";
import type { GateStore } from "../src/store/gate-store.js";
import type { ListInput } from "../src/types.js";
import { ACTOR, store, submission } from "./helpers.js";

const ORIGIN = "https://admin.example.com";
const LOCAL_ORIGIN = "http://localhost:8787";

function request(path: string, init: RequestInit = {}): Request {
  return new Request(`${ORIGIN}${path}`, init);
}

function mutation(path: string, body: unknown, headers: HeadersInit = {}): Request {
  return request(path, {
    method: "POST",
    headers: { origin: ORIGIN, "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

async function pending(stub: ReturnType<typeof store>) {
  const current = await stub.getConfig();
  const result = await stub.submit(submission({ configVersion: current.version }));
  if (result.state !== "created") throw new Error(`Expected created request, received ${result.state}`);
  return result.request;
}

describe("admin HTTP surface", () => {
  it("serves the console and health response with locked-down headers", async () => {
    const stub = store();
    const page = await handleAdmin(request("/"), stub);
    expect(page.status).toBe(200);
    expect(page.headers.get("content-security-policy")).toContain("script-src 'nonce-");
    expect(page.headers.get("x-frame-options")).toBe("DENY");
    expect(page.headers.get("content-security-policy")).toContain("connect-src 'self' wss://admin.example.com;");
    const html = await page.text();
    expect(html).toContain("Purpose approval console");
    expect(html).toContain("All terminal statuses");
    expect(html).toContain("Load more");
    expect(html).not.toContain("Shared egress");
    expect(html).not.toContain("IP-based identity");
    expect(html).toContain("el('strong','requester',item.identityName)");

    const health = await handleAdmin(request("/health"), stub);
    expect(await health.json()).toMatchObject({ ok: true, worker: "purpose-justification-workersgw" });
  });

  it("returns exact not-found and method errors", async () => {
    const stub = store();
    const missing = await handleAdmin(request("/missing"), stub);
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ error: "not_found", message: "Route not found." });

    const wrongMethod = await handleAdmin(request("/health", { method: "POST" }), stub);
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get("allow")).toBe("GET");
    expect(await wrongMethod.json()).toEqual({ error: "method_not_allowed", message: "Method not allowed." });
  });

  it("enforces exact same-origin and JSON guards on mutations", async () => {
    const stub = store();
    const noOrigin = await handleAdmin(request("/api/config/reset", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }), stub);
    expect(noOrigin.status).toBe(403);
    expect(await noOrigin.json()).toMatchObject({ error: "invalid_origin" });

    for (const origin of [`${ORIGIN}.attacker.example`, "http://admin.example.com", "https://admin.example.com:8443", "null"]) {
      const wrongOrigin = await handleAdmin(mutation("/api/config/reset", {}, { origin }), stub);
      expect(wrongOrigin.status).toBe(403);
    }

    const wrongType = await handleAdmin(request("/api/config/reset", {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "text/plain" },
      body: "{}",
    }), stub);
    expect(wrongType.status).toBe(400);
    expect(await wrongType.json()).toMatchObject({ error: "invalid_request" });

    const parameterized = await handleAdmin(mutation(
      "/api/config/reset",
      {},
      { "content-type": "Application/JSON; charset=utf-8" },
    ), stub);
    expect(parameterized.status).toBe(200);

    const prefixedType = await handleAdmin(mutation(
      "/api/config/reset",
      {},
      { "content-type": "application/json-patch+json" },
    ), stub);
    expect(prefixedType.status).toBe(400);
    expect(await prefixedType.json()).toMatchObject({ error: "invalid_request" });
  });

  it("reads, validates, saves, and resets configuration", async () => {
    const stub = store();
    const get = await handleAdmin(request("/api/config"), stub);
    expect(await get.json()).toEqual({ config: DEFAULT_CONFIG });

    const invalid = await handleAdmin(new Request(`${ORIGIN}/api/config`, {
      method: "PUT",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ ...DEFAULT_CONFIG, defaultGrantSeconds: 1 }),
    }), stub);
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toMatchObject({
      error: "invalid_request",
      message: "Configuration validation failed.",
      details: expect.any(Array),
    });

    const valid = await handleAdmin(new Request(`${ORIGIN}/api/config`, {
      method: "PUT",
      headers: {
        origin: ORIGIN,
        "content-type": "application/json",
        "cf-access-authenticated-user-email": " ADMIN@EXAMPLE.COM ",
      },
      body: JSON.stringify({ ...DEFAULT_CONFIG, defaultGrantSeconds: 7200 }),
    }), stub);
    expect(valid.status).toBe(200);
    expect(await valid.json()).toMatchObject({ ok: true, config: { version: 2, defaultGrantSeconds: 7200 } });

    const reset = await handleAdmin(mutation("/api/config/reset", {}), stub);
    expect(await reset.json()).toMatchObject({ ok: true, config: { version: 3, defaultGrantSeconds: 3600 } });
  });

  it("lists, reads, approves, and revokes requests and grants", async () => {
    const stub = store();
    const item = await pending(stub);

    const list = await handleAdmin(request("/api/requests?status=pending&host=example.com&limit=10"), stub);
    expect(await list.json()).toMatchObject({ entries: [{ id: item.id }], listComplete: true });

    const detail = await handleAdmin(request(`/api/requests/${item.id}`), stub);
    expect(await detail.json()).toMatchObject({ request: { id: item.id } });
    const missing = await handleAdmin(request("/api/requests/missing"), stub);
    expect(missing.status).toBe(404);

    const invalid = await handleAdmin(mutation(`/api/requests/${item.id}/approve`, { grantSeconds: "120" }), stub);
    expect(invalid.status).toBe(400);
    const approved = await handleAdmin(mutation(`/api/requests/${item.id}/approve`, { grantSeconds: 120 }), stub);
    const approvedBody = await approved.json<{ grant: { id: string } }>();
    expect(approved.status).toBe(200);
    expect(approvedBody).toMatchObject({ ok: true, status: "approved" });

    const grants = await handleAdmin(request("/api/grants"), stub);
    expect(await grants.json()).toMatchObject({ entries: [{ id: approvedBody.grant.id, status: "active" }] });
    const revoked = await handleAdmin(mutation("/api/grants/revoke", { id: approvedBody.grant.id }), stub);
    expect(await revoked.json()).toMatchObject({ ok: true, value: { status: "revoked" } });
  });

  it("denies requests and clears holds", async () => {
    const stub = store();
    const item = await pending(stub);
    const invalid = await handleAdmin(mutation(`/api/requests/${item.id}/deny`, {}), stub);
    expect(invalid.status).toBe(400);

    const denied = await handleAdmin(mutation(`/api/requests/${item.id}/deny`, { reason: "A valid policy denial reason." }), stub);
    const deniedBody = await denied.json<{ hold: { id: string } }>();
    expect(deniedBody).toMatchObject({ ok: true, status: "denied" });

    const holds = await handleAdmin(request("/api/holds"), stub);
    expect(await holds.json()).toMatchObject({ entries: [{ id: deniedBody.hold.id, status: "active" }] });
    const cleared = await handleAdmin(mutation("/api/holds/clear", { id: deniedBody.hold.id }), stub);
    expect(await cleared.json()).toMatchObject({ ok: true, value: { status: "cleared" } });
  });

  it("passes independent active-access cursors to the store", async () => {
    const grantInputs: ListInput[] = [];
    const holdInputs: ListInput[] = [];
    const stub = {
      listGrants: async (input: ListInput) => {
        grantInputs.push(input);
        return { entries: [], cursor: null, listComplete: true };
      },
      listHolds: async (input: ListInput) => {
        holdInputs.push(input);
        return { entries: [], cursor: null, listComplete: true };
      },
    } as unknown as DurableObjectStub<GateStore>;

    await handleAdmin(request("/api/grants?status=active&limit=25&cursor=grant-cursor"), stub);
    await handleAdmin(request("/api/holds?status=active&limit=50&cursor=hold-cursor"), stub);

    expect(grantInputs).toEqual([{ status: "active", cursor: "grant-cursor", limit: 25 }]);
    expect(holdInputs).toEqual([{ status: "active", cursor: "hold-cursor", limit: 50 }]);
  });

  it("renders safe history, active pagination, and decision-race behavior", async () => {
    const html = await (await handleAdmin(request("/"), store())).text();
    expect(html).toContain("statusFilter.value||'terminal'");
    expect(html).not.toContain("item.status!=='pending'");
    expect(html).toContain("loadState(grants,'grant',null,generation),loadState(holds,'hold',null,generation)");
    expect(html).toContain("Load more grants");
    expect(html).toContain("Load more holds");
    expect(html).toContain("generation!==loadGeneration");
    expect(html).toContain("current==='settings'&&settingsDirty");
    expect(html).toContain("form.isConnected&&settingsRevision===revision");
    expect(html).toContain("more.disabled=true;loadRequests");
    expect(html.match(/if\(e\.status===409\)/g)).toHaveLength(2);
  });

  it("maps malformed, oversized, range, and service failures to controlled errors", async () => {
    const stub = store();
    const invalidJson = await handleAdmin(new Request(`${ORIGIN}/api/config`, {
      method: "PUT",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: "{",
    }), stub);
    expect(invalidJson.status).toBe(400);
    expect(await invalidJson.json()).toMatchObject({ error: "invalid_request", message: "Invalid JSON body." });

    const oversized = await handleAdmin(new Request(`${ORIGIN}/api/config`, {
      method: "PUT",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ value: "x".repeat(70_000) }),
    }), stub);
    expect(oversized.status).toBe(413);
    expect(await oversized.json()).toMatchObject({ error: "payload_too_large" });

    const rangeStore = {
      listRequests: async () => { throw new RangeError("limit must be an integer between 1 and 100"); },
    } as unknown as DurableObjectStub<GateStore>;
    const range = await handleAdmin(request("/api/requests?limit=0"), rangeStore);
    expect(range.status).toBe(400);
    expect(await range.json()).toMatchObject({ error: "invalid_request" });

    const failing = { getConfig: async () => { throw new Error("database secret"); } } as unknown as DurableObjectStub<GateStore>;
    const unavailable = await handleAdmin(request("/api/config"), failing);
    expect(unavailable.status).toBe(503);
    expect(await unavailable.text()).not.toContain("database secret");
  });

  it("accepts a config reset with an empty body", async () => {
    const stub = store();
    const response = await handleAdmin(request("/api/config/reset", {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json" },
    }), stub);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ ok: true, config: { version: 2 } });
  });

  it("enforces same-origin WebSocket upgrades", async () => {
    const stub = store();
    expect((await handleAdmin(request("/ws", { method: "POST" }), stub)).status).toBe(405);
    expect((await handleAdmin(request("/ws"), stub)).status).toBe(403);
    expect((await handleAdmin(request("/ws", { headers: { origin: ORIGIN } }), stub)).status).toBe(403);

    const response = await handleAdmin(request("/ws", {
      headers: { origin: ORIGIN, upgrade: "websocket" },
    }), stub);
    expect(response.status).toBe(101);
    response.webSocket?.accept();
    response.webSocket?.close(1000, "done");
  });

  it("derives the admin origin from the request host, including local development", async () => {
    const stub = store();
    const page = await handleAdmin(new Request(`${LOCAL_ORIGIN}/`), stub);
    expect(page.headers.get("content-security-policy")).toContain("connect-src 'self' ws://localhost:8787;");
    await page.text();

    const reset = await handleAdmin(new Request(`${LOCAL_ORIGIN}/api/config/reset`, {
      method: "POST",
      headers: { origin: LOCAL_ORIGIN, "content-type": "application/json" },
      body: "{}",
    }), stub);
    expect(reset.status).toBe(200);

    const crossOrigin = await handleAdmin(new Request(`${LOCAL_ORIGIN}/api/config/reset`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: "{}",
    }), stub);
    expect(crossOrigin.status).toBe(403);

    const socket = await handleAdmin(new Request(`${LOCAL_ORIGIN}/ws`, {
      headers: { origin: LOCAL_ORIGIN, upgrade: "websocket" },
    }), stub);
    expect(socket.status).toBe(101);
    socket.webSocket?.accept();
    socket.webSocket?.close(1000, "done");
  });
});
