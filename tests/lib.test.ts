import { describe, expect, it, vi } from "vitest";
import { signToken, randomNonce, verifyToken } from "../src/lib/crypto.js";
import {
  InvalidJsonError,
  isRecord,
  json,
  PayloadTooLargeError,
  readJson,
} from "../src/lib/json.js";
import { log, logError } from "../src/lib/log.js";
import { bytesToStream } from "../src/lib/stream.js";
import type { BrowserTokenPayload, FormTokenPayload, StatusTokenPayload } from "../src/types.js";

const SECRET = "a sufficiently long test signing secret";
const NOW = 2_000_000_000;

function formPayload(overrides: Partial<FormTokenPayload> = {}): FormTokenPayload {
  return {
    type: "form",
    identityKind: "email",
    identity: "user@example.com",
    host: "example.com",
    policyKind: "generic",
    configVersion: 1,
    requestedUrl: "https://example.com/private",
    iat: NOW,
    exp: NOW + 600,
    nonce: randomNonce(),
    ...overrides,
  };
}

describe("browser tokens", () => {
  it("round-trips valid form and status tokens", async () => {
    const form = formPayload();
    expect(await verifyToken(SECRET, await signToken(SECRET, form), NOW)).toEqual(form);

    const status: StatusTokenPayload = {
      type: "status",
      identityKind: "email",
      identity: "user@example.com",
      host: "example.com",
      requestId: "request-id",
      iat: NOW,
      exp: NOW + 3600,
    };
    expect(await verifyToken(SECRET, await signToken(SECRET, status), NOW)).toEqual(status);
  });

  it("rejects absent, malformed, tampered, and wrongly signed tokens", async () => {
    const token = await signToken(SECRET, formPayload());
    expect(await verifyToken("", token, NOW)).toBeNull();
    expect(await verifyToken(SECRET, null, NOW)).toBeNull();
    expect(await verifyToken(SECRET, "bad", NOW)).toBeNull();
    expect(await verifyToken(SECRET, ".signature", NOW)).toBeNull();
    expect(await verifyToken(SECRET, `${token}x`, NOW)).toBeNull();
    expect(await verifyToken("another secret", token, NOW)).toBeNull();
    expect(await verifyToken(SECRET, "%%%.%%%", NOW)).toBeNull();
  });

  it.each([
    { identityKind: "ip" },
    { identity: "" },
    { identity: "x".repeat(255) },
    { host: "" },
    { iat: NOW + 1 },
    { exp: NOW },
    { type: "other" },
    { policyKind: "" },
    { configVersion: -1 },
    { requestedUrl: "" },
    { nonce: "" },
    { nonce: "not-a-16-byte-nonce" },
    { exp: NOW + 599 },
    { exp: NOW + 601 },
  ])("rejects an invalid form payload: %o", async (override) => {
    const payload = { ...formPayload(), ...override } as BrowserTokenPayload;
    expect(await verifyToken(SECRET, await signToken(SECRET, payload), NOW)).toBeNull();
  });

  it("creates URL-safe random nonces", () => {
    const first = randomNonce();
    const second = randomNonce();
    expect(first).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(second).not.toBe(first);
  });
});

describe("JSON and stream helpers", () => {
  it("sets controlled JSON headers", async () => {
    const response = json({ ok: true }, 201, { "x-test": "yes", "content-type": "text/plain" });
    expect(response.status).toBe(201);
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-test")).toBe("yes");
    expect(await response.json()).toEqual({ ok: true });
  });

  it("reads valid JSON and enforces declared and actual limits", async () => {
    expect(await readJson(new Request("https://example.com", { method: "POST", body: "{\"ok\":true}" }), 20)).toEqual({ ok: true });
    await expect(
      readJson(new Request("https://example.com", { headers: { "content-length": "21" } }), 20),
    ).rejects.toBeInstanceOf(PayloadTooLargeError);
    await expect(
      readJson(new Request("https://example.com", { method: "POST", body: "123456" }), 5),
    ).rejects.toBeInstanceOf(PayloadTooLargeError);
    await expect(
      readJson(new Request("https://example.com", { method: "POST", body: "{" }), 10),
    ).rejects.toBeInstanceOf(InvalidJsonError);
  });

  it("stops reading an oversized stream without a Content-Length header", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("{\"value\":\""));
        controller.enqueue(new Uint8Array(100));
      },
      cancel() {
        cancelled = true;
      },
    });
    const request = new Request("https://example.com", { method: "POST", body });
    await expect(readJson(request, 20)).rejects.toBeInstanceOf(PayloadTooLargeError);
    expect(cancelled).toBe(true);
  });

  it("recognizes records", () => {
    expect(isRecord({})).toBe(true);
    expect(isRecord([])).toBe(false);
    expect(isRecord(null)).toBe(false);
    expect(isRecord("record")).toBe(false);
  });

  it("streams bytes without changing them", async () => {
    const bytes = new TextEncoder().encode("streamed response");
    expect(await new Response(bytesToStream(bytes)).text()).toBe("streamed response");
  });
});

describe("structured logging", () => {
  it("emits structured informational and safe error records", () => {
    const info = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    log("event", { count: 1 });
    logError("failed", new TypeError("sensitive message"), { request_id: "id" });
    logError("unknown", "sensitive value");

    expect(info.mock.calls[0]?.[0]).toMatchObject({ event: "event", count: 1 });
    expect(error.mock.calls[0]?.[0]).toMatchObject({
      event: "pj_error",
      reason: "failed",
      error_name: "TypeError",
      request_id: "id",
    });
    expect(error.mock.calls[1]?.[0]).toMatchObject({ error_name: "UnknownError" });
    expect(error.mock.calls[0]?.[0]).not.toHaveProperty("message");
    info.mockRestore();
    error.mockRestore();
  });
});
