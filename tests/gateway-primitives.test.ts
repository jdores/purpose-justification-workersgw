import { describe, expect, it } from "vitest";
import {
  IdentityUnavailableError,
  normalizeEmail,
  normalizeName,
  resolveIdentity,
  resolveTarget,
} from "../src/gateway/identity.js";
import { isAuthEndpoint, isTopLevelDocument } from "../src/gateway/navigation.js";
import { emergencySyntheticResponse, syntheticResponse, tagPassThrough } from "../src/gateway/origin.js";
import { WORKER_NAME } from "../src/types.js";
import { gatewayContext } from "./helpers.js";

describe("navigation classification", () => {
  it.each([
    "/oauth",
    "/auth/callback",
    "/LOGIN",
    "/logout",
    "/callback",
    "/.well-known/openid-configuration",
    "/saml",
    "/sso/start",
    "/token",
    "/favicon.ico",
    "/robots.txt",
  ])("bypasses auth path %s", (path) => {
    expect(isAuthEndpoint(`https://example.com${path}`)).toBe(true);
  });

  it("does not overmatch or accept invalid URLs", () => {
    expect(isAuthEndpoint("https://example.com/oauthlike")).toBe(true);
    expect(isAuthEndpoint("https://example.com/api/login")).toBe(false);
    expect(isAuthEndpoint("not a URL")).toBe(false);
  });

  it.each([
    [{ "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" }, true],
    [{ "sec-fetch-mode": "Navigate", "sec-fetch-dest": "Document" }, true],
    [{ "sec-fetch-mode": "navigate", "sec-fetch-dest": "iframe" }, false],
    [{ "sec-fetch-mode": "cors", "sec-fetch-dest": "document" }, false],
    [{ "sec-fetch-mode": "navigate" }, false],
    [{ "sec-fetch-dest": "document" }, false],
    [{ accept: "text/html,application/xhtml+xml" }, true],
    [{ accept: "application/json" }, false],
    [{}, false],
  ])("classifies document headers %o as %s", (values, expected) => {
    expect(isTopLevelDocument(new Headers(values))).toBe(expected);
  });
});

describe("request target", () => {
  it("normalizes host and URL without query data", () => {
    expect(resolveTarget(new Request("https://WWW.Example.com/private?q=secret#fragment"), {})).toEqual({
      host: "example.com",
      requestedUrl: "https://www.example.com/private",
    });
  });

  it("canonicalizes a trailing DNS root dot into the same authorization scope", () => {
    expect(resolveTarget(new Request("https://www.example.com./private"), {})).toMatchObject({
      host: "example.com",
    });
  });

  it("uses the context host when a non-standard request URL cannot be parsed", () => {
    const request = { url: "not a URL" } as Request;
    expect(resolveTarget(request, { host: "fallback.example" })).toEqual({
      host: "fallback.example",
      requestedUrl: "https://fallback.example/",
    });
    expect(() => resolveTarget(request, {} as never)).toThrow("invalid host");
    expect(() => resolveTarget(request, { host: "good.example@evil.example" })).toThrow("invalid host");
  });

  it("rejects an unusable host", () => {
    const request = { url: "https:///" } as Request;
    expect(() => resolveTarget(request, { host: "" })).toThrow("invalid host");
  });

  it("truncates very long paths", () => {
    const result = resolveTarget(new Request(`https://example.com/${"a".repeat(3000)}?secret=yes`), {});
    expect(result.requestedUrl.length).toBe(2048);
    expect(result.requestedUrl.endsWith("...")).toBe(true);
    expect(result.requestedUrl).not.toContain("secret");
  });
});

describe("Gateway identity", () => {
  it("normalizes the Gateway user email and display name", async () => {
    expect(await resolveIdentity(gatewayContext({ email: "  User@Example.COM ", name: "  Example\u0007 User  " }))).toEqual({
      state: "identified",
      identityKind: "email",
      identity: "user@example.com",
      name: "Example User",
    });
    expect(await resolveIdentity(gatewayContext({ email: "user@example.com" }))).toMatchObject({ name: null });
    expect(await resolveIdentity(gatewayContext({ email: "user@example.com", name: " \u0000 " }))).toMatchObject({ name: null });
    const long = await resolveIdentity(gatewayContext({ email: "user@example.com", name: "n".repeat(300) }));
    expect(long.state === "identified" ? long.name?.length : 0).toBe(200);
  });

  it.each([
    [null],
    [{}],
    [{ name: "No Email" }],
    [{ email: "" }],
    [{ email: "not-an-email" }],
    [{ email: "two words@example.com" }],
    [{ email: `${"x".repeat(250)}@example.com` }],
  ])("treats %o as anonymous", async (identity) => {
    expect(await resolveIdentity(gatewayContext(identity))).toEqual({ state: "anonymous" });
  });

  it("distinguishes an identity lookup failure from an anonymous session", async () => {
    const failure = new Error("lookup failed");
    const error = await resolveIdentity(gatewayContext(failure)).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(IdentityUnavailableError);
    expect((error as Error).cause).toBe(failure);
  });

  it("normalizes email and name values defensively", () => {
    expect(normalizeEmail(42)).toBeNull();
    expect(normalizeName(42)).toBeNull();
  });
});

describe("origin response controls", () => {
  it("tags pass-through responses while preserving status and body", async () => {
    const result = tagPassThrough(
      new Response("origin", {
        status: 202,
        statusText: "Accepted",
        headers: {
          "set-cookie": "origin=yes",
          "x-gw-auth-skip": "true",
          "x-gw-worker-name": "spoofed",
          "x-gw-pj-error": "true",
          "x-gw-pj-denied": "true",
          "x-gw-pj-form": "true",
          "x-gw-pj-pending": "true",
          "x-gw-pj-rate-limited": "true",
          "x-gw-pj-request-id": "spoofed",
          "x-gw-pj-status": "true",
          "x-gw-pj-submit": "true",
          "x-gw-pj-subresource": "true",
        },
      }),
      "invocation",
      "x-gw-pj-granted",
      { "x-gw-pj-grant-until": "tomorrow" },
    );
    expect(result.status).toBe(202);
    expect(result.statusText).toBe("Accepted");
    expect(result.headers.get("x-gw-worker-name")).toBe(WORKER_NAME);
    expect(result.headers.get("x-gw-pj-request-id")).toBe("invocation");
    expect(result.headers.get("x-gw-pj-granted")).toBe("true");
    expect(result.headers.get("x-gw-pj-denied")).toBeNull();
    expect(result.headers.get("x-gw-auth-skip")).toBeNull();
    expect(
      [
        "x-gw-auth-skip",
        "x-gw-pj-subresource",
        "x-gw-pj-granted",
        "x-gw-pj-form",
        "x-gw-pj-pending",
        "x-gw-pj-denied",
        "x-gw-pj-submit",
        "x-gw-pj-status",
        "x-gw-pj-rate-limited",
        "x-gw-pj-error",
      ].filter((name) => result.headers.has(name)),
    ).toEqual(["x-gw-pj-granted"]);
    expect(result.headers.get("x-gw-pj-grant-until")).toBe("tomorrow");
    expect(await result.text()).toBe("origin");
  });

  it("preserves a pass-through WebSocket upgrade", () => {
    const pair = new WebSocketPair();
    const upstream = new Response(null, { status: 101, webSocket: pair[0] });
    const result = tagPassThrough(upstream, "invocation", "x-gw-pj-subresource");
    expect(result.status).toBe(101);
    expect(result.webSocket).toBe(pair[0]);
    result.webSocket?.accept();
    pair[1].accept();
    result.webSocket?.close(1000, "done");
    pair[1].close(1000, "done");
  });

  it("builds controlled synthetic responses without origin headers", async () => {
    const response = syntheticResponse({
      body: "<h1>controlled</h1>",
      status: 403,
      invocationId: "invocation",
      decisionHeader: "x-gw-pj-denied",
      contentType: "html",
      nonce: "nonce",
      extraHeaders: { "retry-after": "10" },
    });
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.get("content-security-policy")).toContain("'nonce-nonce'");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("retry-after")).toBe("10");
    expect(response.headers.get("x-gw-pj-denied")).toBe("true");
    expect(await response.text()).toBe("<h1>controlled</h1>");

    const jsonResponse = syntheticResponse({
      body: "{}",
      status: 200,
      invocationId: "json",
      decisionHeader: "x-gw-pj-status",
      contentType: "json",
    });
    expect(jsonResponse.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(jsonResponse.headers.get("content-security-policy")).toBeNull();
  });

  it("omits synthetic bodies when requested for HEAD responses", async () => {
    const response = syntheticResponse({
      body: "<h1>hidden</h1>",
      status: 200,
      invocationId: "head",
      decisionHeader: "x-gw-pj-form",
      contentType: "html",
      omitBody: true,
    });
    expect(response.body).toBeNull();
    const emergency = emergencySyntheticResponse({
      body: "{}",
      status: 503,
      invocationId: "head",
      decisionHeader: "x-gw-pj-error",
      contentType: "json",
      omitBody: true,
    });
    expect(emergency.body).toBeNull();
    expect(emergency.headers.get("x-gw-pj-error")).toBe("true");
  });
});
