import { describe, expect, it, vi } from "vitest";
import { handleGateway } from "../src/gateway/handler.js";
import { randomNonce, signToken } from "../src/lib/crypto.js";
import { DEFAULT_CONFIG } from "../src/store/config.js";
import type { GateStore } from "../src/store/gate-store.js";
import type {
  EvaluateResult,
  FormTokenPayload,
  GrantView,
  HoldView,
  RequestView,
  StatusResult,
  SubmitInput,
  SubmitResult,
} from "../src/types.js";
import { ACTION_HEADER, TOKEN_HEADER } from "../src/types.js";
import { ACTOR, gatewayContext, store, submission, USER_EMAIL, USER_NAME } from "./helpers.js";

const SECRET = "a sufficiently long middleware test secret";
const CONTEXT = gatewayContext();
const URL = "https://example.com/private?secret=query";

function navigation(url = URL, init: RequestInit = {}): Request {
  const headers = new Headers(init.headers);
  headers.set("sec-fetch-mode", "navigate");
  headers.set("sec-fetch-dest", "document");
  return new Request(url, { ...init, headers });
}

function future(seconds = 3600): string {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

function requestView(overrides: Partial<RequestView> = {}): RequestView {
  return {
    id: "request-id",
    status: "pending",
    identityKind: "email",
    identity: USER_EMAIL,
    identityName: USER_NAME,
    host: "example.com",
    requestedUrl: "https://example.com/private",
    justification: "This is a sufficiently detailed business justification.",
    policyKind: "generic",
    createdAt: new Date().toISOString(),
    expiresAt: future(),
    decidedAt: null,
    decidedBy: null,
    decidedBySource: null,
    decisionReason: null,
    grantSeconds: null,
    userAgent: "test-agent",
    configVersion: 1,
    grant: null,
    hold: null,
    ...overrides,
  };
}

function grantView(overrides: Partial<GrantView> = {}): GrantView {
  return {
    id: "grant-id",
    requestId: "request-id",
    identityKind: "email",
    identity: USER_EMAIL,
    host: "example.com",
    status: "active",
    grantedAt: new Date().toISOString(),
    expiresAt: future(),
    grantedBy: "admin@example.com",
    grantedBySource: "access-header",
    revokedAt: null,
    revokedBy: null,
    revokedBySource: null,
    ...overrides,
  };
}

function holdView(overrides: Partial<HoldView> = {}): HoldView {
  return {
    id: "hold-id",
    requestId: "request-id",
    identityKind: "email",
    identity: USER_EMAIL,
    host: "example.com",
    status: "active",
    reason: "This destination is not approved.",
    deniedAt: new Date().toISOString(),
    expiresAt: future(),
    deniedBy: "admin@example.com",
    deniedBySource: "access-header",
    clearedAt: null,
    clearedBy: null,
    clearedBySource: null,
    ...overrides,
  };
}

function fakeStore(methods: Record<string, unknown>): DurableObjectStub<GateStore> {
  return methods as unknown as DurableObjectStub<GateStore>;
}

function deps(storeStub: DurableObjectStub<GateStore>, signingSecret?: string) {
  return {
    store: storeStub,
    signingSecret: arguments.length === 1 ? SECRET : signingSecret,
    waitUntil: (promise: Promise<unknown>) => void promise,
  };
}

function expectNoOriginCall(next: ReturnType<typeof originNext>): void {
  expect(next).not.toHaveBeenCalled();
}

function originNext() {
  return vi.fn(async (_request: Request) => new Response("origin response", {
    status: 202,
    headers: { "set-cookie": "origin=secret", location: "https://redirect.example" },
  }));
}

async function formToken(overrides: Partial<FormTokenPayload> = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signToken(SECRET, {
    type: "form",
    identityKind: "email",
    identity: USER_EMAIL,
    host: "example.com",
    policyKind: "generic",
    configVersion: 1,
    requestedUrl: "https://example.com/private",
    iat: now,
    exp: now + 600,
    nonce: randomNonce(),
    ...overrides,
  });
}

async function statusToken(overrides: Record<string, unknown> = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signToken(SECRET, {
    type: "status",
    identityKind: "email",
    identity: USER_EMAIL,
    host: "example.com",
    requestId: "request-id",
    iat: now,
    exp: now + 3600,
    ...overrides,
  } as never);
}

function statusRequest(token: string, method = "GET"): Request {
  return new Request(URL, { method, headers: { [ACTION_HEADER]: "status", [TOKEN_HEADER]: token } });
}

function submitRequest(token: string, body: unknown = {
  justification: "This access is required to resolve a customer support incident.",
}): Request {
  return new Request(URL, {
    method: "POST",
    headers: {
      [ACTION_HEADER]: "submit",
      [TOKEN_HEADER]: token,
      "content-type": "application/json",
      "user-agent": "test-browser",
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

describe("gateway routing invariants", () => {
  it("passes authentication endpoints and subresources through exactly once without an identity lookup", async () => {
    for (const request of [
      new Request("https://example.com/oauth/callback"),
      new Request("https://example.com/api", { headers: { accept: "application/json" } }),
    ]) {
      const next = originNext();
      const identity = vi.fn(async () => ({ email: USER_EMAIL }));
      const response = await handleGateway(request, gatewayContext(null, { identity }), next, deps(fakeStore({}), undefined));
      expect(next).toHaveBeenCalledOnce();
      expect(next.mock.calls[0]?.[0]).toBe(request);
      expect(identity).not.toHaveBeenCalled();
      expect(response.headers.get(request.url.includes("oauth") ? "x-gw-auth-skip" : "x-gw-pj-subresource")).toBe("true");
      expect(await response.text()).toBe("origin response");
    }
  });

  it("passes an active grant through with the original mutation request", async () => {
    const grant = grantView();
    const evaluate = vi.fn(async () => ({
      state: "granted",
      grant,
      config: DEFAULT_CONFIG,
      policy: DEFAULT_CONFIG.policies.generic!,
    } satisfies EvaluateResult));
    const request = navigation(URL, { method: "POST", body: "original mutation body" });
    const next = originNext();
    const response = await handleGateway(request, CONTEXT, next, deps(fakeStore({ evaluate })));
    expect(evaluate).toHaveBeenCalledWith(expect.objectContaining({ identityKind: "email", identity: USER_EMAIL, host: "example.com" }));
    expect(next).toHaveBeenCalledOnce();
    expect(next.mock.calls[0]?.[0]).toBe(request);
    expect(await next.mock.calls[0]?.[0].text()).toBe("original mutation body");
    expect(response.headers.get("x-gw-pj-granted")).toBe("true");
    expect(response.headers.get("x-gw-pj-grant-until")).toBe(grant.expiresAt);
  });

  it("renders none, pending, and denied states without contacting the origin", async () => {
    const pending = requestView();
    const hold = holdView({ reason: "Denied because <script>alert(1)</script> is unsafe." });
    const evaluations: EvaluateResult[] = [
      { state: "none", config: DEFAULT_CONFIG, policy: DEFAULT_CONFIG.policies.generic! },
      { state: "pending", request: pending, config: DEFAULT_CONFIG, policy: DEFAULT_CONFIG.policies.generic! },
      { state: "denied", hold, config: DEFAULT_CONFIG, policy: DEFAULT_CONFIG.policies.generic! },
    ];
    const expectedHeaders = ["x-gw-pj-form", "x-gw-pj-pending", "x-gw-pj-denied"];

    for (const [index, evaluation] of evaluations.entries()) {
      const next = originNext();
      const storeStub = fakeStore({ evaluate: vi.fn(async () => evaluation) });
      const request = navigation(URL, {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "sensitive original body",
      });
      const response = await handleGateway(request, CONTEXT, next, deps(storeStub));
      expectNoOriginCall(next);
      expect(response.status).toBe(200);
      expect(response.headers.get(expectedHeaders[index]!)).toBe("true");
      expect(response.headers.get("set-cookie")).toBeNull();
      expect(response.headers.get("location")).toBeNull();
      const html = await response.text();
      expect(html).not.toContain("sensitive original body");
      if (evaluation.state === "denied") expect(html).toContain("&lt;script&gt;");
    }
  });

  it("returns headers without a body for HEAD navigations", async () => {
    const next = originNext();
    const storeStub = fakeStore({ evaluate: vi.fn(async () => ({
      state: "none",
      config: DEFAULT_CONFIG,
      policy: DEFAULT_CONFIG.policies.generic!,
    } satisfies EvaluateResult)) });
    const response = await handleGateway(navigation(URL, { method: "HEAD" }), CONTEXT, next, deps(storeStub));
    expectNoOriginCall(next);
    expect(response.headers.get("x-gw-pj-form")).toBe("true");
    expect(response.body).toBeNull();
  });

  it("blocks anonymous navigations with a sign-in page", async () => {
    for (const identity of [null, {}, { email: "not-an-email" }]) {
      const next = originNext();
      const evaluate = vi.fn();
      const response = await handleGateway(navigation(), gatewayContext(identity), next, deps(fakeStore({ evaluate })));
      expectNoOriginCall(next);
      expect(evaluate).not.toHaveBeenCalled();
      expect(response.status).toBe(403);
      expect(response.headers.get("x-gw-pj-identity-required")).toBe("true");
      expect(response.headers.get("content-security-policy")).toContain("script-src 'nonce-");
      expect(await response.text()).toContain("Sign-in required");
    }
  });

  it("rejects anonymous protocol actions with JSON", async () => {
    for (const request of [submitRequest(await formToken()), statusRequest(await statusToken())]) {
      const next = originNext();
      const response = await handleGateway(request, gatewayContext(null), next, deps(fakeStore({})));
      expectNoOriginCall(next);
      expect(response.status).toBe(403);
      expect(response.headers.get("x-gw-pj-identity-required")).toBe("true");
      expect(await response.json()).toEqual({
        error: "identity_required",
        message: "A signed-in Zero Trust session is required.",
      });
    }
  });

  it("fails closed when the Gateway identity lookup fails", async () => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const next = originNext();
      const evaluate = vi.fn();
      const response = await handleGateway(
        navigation(),
        gatewayContext(new Error("identity backend details")),
        next,
        deps(fakeStore({ evaluate })),
      );
      expectNoOriginCall(next);
      expect(evaluate).not.toHaveBeenCalled();
      expect(response.status).toBe(503);
      expect(response.headers.get("x-gw-pj-error")).toBe("true");
      expect(await response.text()).not.toContain("identity backend details");
      expect(errorLog).toHaveBeenCalledWith(expect.objectContaining({ reason: "identity_unavailable" }));

      const protocol = await handleGateway(
        statusRequest(await statusToken()),
        gatewayContext(new Error("identity backend details")),
        next,
        deps(fakeStore({})),
      );
      expect(protocol.status).toBe(503);
      expect(await protocol.json()).toEqual({
        error: "service_unavailable",
        message: "State service is temporarily unavailable.",
      });
      expectNoOriginCall(next);
    } finally {
      errorLog.mockRestore();
    }
  });

  it.each([
    [
      { url: "https:///", method: "GET", headers: new Headers() } as unknown as Request,
      gatewayContext(undefined, { host: "" }),
      SECRET,
      "middleware_failed",
    ],
    [navigation(), CONTEXT, undefined, "missing_signing_secret"],
  ])("fails closed on an invalid host or missing secret", async (request, context, secret, reason) => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const next = originNext();
      const response = await handleGateway(request, context, next, deps(fakeStore({ evaluate: vi.fn() }), secret));
      expectNoOriginCall(next);
      expect(response.status).toBe(503);
      expect(response.headers.get("x-gw-pj-error")).toBe("true");
      expect(response.headers.get("retry-after")).toBe("10");
      expect(errorLog).toHaveBeenCalledWith(expect.objectContaining({ reason }));
    } finally {
      errorLog.mockRestore();
    }
  });

  it("fails closed when state evaluation throws", async () => {
    const next = originNext();
    const storeStub = fakeStore({ evaluate: vi.fn(async () => { throw new Error("database details"); }) });
    const response = await handleGateway(navigation(), CONTEXT, next, deps(storeStub));
    expectNoOriginCall(next);
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("database details");
  });

  it("returns an emergency response if normal fail-closed rendering fails", async () => {
    const next = originNext();
    const storeStub = fakeStore({ evaluate: vi.fn(async () => { throw new Error("database details"); }) });
    const random = vi.spyOn(crypto, "getRandomValues").mockImplementationOnce(() => {
      throw new Error("entropy unavailable");
    });
    try {
      const response = await handleGateway(navigation(), CONTEXT, next, deps(storeStub));
      expectNoOriginCall(next);
      expect(response.status).toBe(503);
      expect(response.headers.get("x-gw-pj-error")).toBe("true");
      expect(response.headers.get("retry-after")).toBe("10");
      const html = await response.text();
      expect(html).toContain("Service unavailable");
      expect(html).not.toContain("database details");
    } finally {
      random.mockRestore();
    }
  });

  it("cancels a retained upstream body when a failure occurs after next() returned", async () => {
    let cancelled = false;
    const body = new ReadableStream({ cancel() { cancelled = true; } });
    const next = vi.fn(async (_request: Request) => ({ body, headers: 5 }) as unknown as Response);
    const waits: Promise<unknown>[] = [];
    const response = await handleGateway(new Request("https://example.com/oauth"), CONTEXT, next, {
      store: fakeStore({}),
      signingSecret: SECRET,
      waitUntil: (promise) => void waits.push(promise),
    });
    await Promise.all(waits);
    expect(next).toHaveBeenCalledOnce();
    expect(cancelled).toBe(true);
    expect(response.status).toBe(503);

    const tolerant = await handleGateway(new Request("https://example.com/oauth"), CONTEXT, vi.fn(async () => ({
      body: new ReadableStream(),
      headers: 5,
    }) as unknown as Response), {
      store: fakeStore({}),
      signingSecret: SECRET,
      waitUntil: () => { throw new Error("execution context unavailable"); },
    });
    expect(tolerant.status).toBe(503);
  });

  it("propagates an upstream failure without calling next twice", async () => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const upstreamError = new Error("upstream failed");
    const next = vi.fn(async (_request: Request): Promise<Response> => { throw upstreamError; });
    try {
      await expect(handleGateway(new Request("https://example.com/oauth"), CONTEXT, next, deps(fakeStore({})))).rejects.toBe(upstreamError);
      expect(next).toHaveBeenCalledOnce();
      expect(errorLog).toHaveBeenCalledWith(expect.objectContaining({ reason: "next_failed" }));
    } finally {
      errorLog.mockRestore();
    }
  });

  it("rejects unknown protocol actions without contacting the origin", async () => {
    const request = new Request(URL, { method: "POST", headers: { [ACTION_HEADER]: "unknown" }, body: "private" });
    const next = originNext();
    const response = await handleGateway(request, CONTEXT, next, deps(fakeStore({})));
    expect(response.status).toBe(400);
    expect(response.headers.get("x-gw-pj-error")).toBe("true");
    expect(response.headers.get("x-gw-pj-submit")).toBeNull();
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
    expectNoOriginCall(next);
  });
});

describe("submission protocol", () => {
  it.each([
    [new Request(URL, { headers: { [ACTION_HEADER]: "submit" } }), 400, "invalid_request"],
    [new Request(URL, { method: "POST", headers: { [ACTION_HEADER]: "submit", "content-type": "text/plain" }, body: "x" }), 400, "invalid_request"],
    [new Request(URL, { method: "POST", headers: { [ACTION_HEADER]: "submit", "content-type": "application/jsonp" }, body: "{}" }), 400, "invalid_request"],
  ])("validates method and content type", async (request, status, code) => {
    const next = originNext();
    const response = await handleGateway(request, CONTEXT, next, deps(fakeStore({})));
    expect(response.status).toBe(status);
    expect(await response.json()).toMatchObject({ error: code });
    expectNoOriginCall(next);
  });

  it("allows parameters on the application/json media type", async () => {
    const submit = vi.fn(async () => ({ state: "invalid" } satisfies SubmitResult));
    const request = submitRequest(await formToken());
    request.headers.set("content-type", "Application/JSON; charset=utf-8");
    const response = await handleGateway(request, CONTEXT, originNext(), deps(fakeStore({ submit })));
    expect(response.status).toBe(400);
    expect(submit).toHaveBeenCalledOnce();
  });

  it("fails closed without a signing secret", async () => {
    const next = originNext();
    const response = await handleGateway(submitRequest("token"), CONTEXT, next, deps(fakeStore({}), undefined));
    expect(response.status).toBe(503);
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(response.headers.get("x-gw-pj-error")).toBe("true");
    expect(response.headers.get("x-gw-pj-submit")).toBeNull();
    expect(await response.json()).toEqual({
      error: "service_unavailable",
      message: "State service is temporarily unavailable.",
    });
    expectNoOriginCall(next);
  });

  it("returns controlled JSON when the submission state service fails", async () => {
    const next = originNext();
    const submit = vi.fn(async () => { throw new Error("internal state details"); });
    const response = await handleGateway(
      submitRequest(await formToken()),
      CONTEXT,
      next,
      deps(fakeStore({ submit })),
    );
    expect(response.status).toBe(503);
    expect(response.headers.get("x-gw-pj-error")).toBe("true");
    expect(response.headers.get("x-gw-pj-submit")).toBeNull();
    expect(await response.json()).toEqual({
      error: "service_unavailable",
      message: "State service is temporarily unavailable.",
    });
    expectNoOriginCall(next);
  });

  it.each([
    ["invalid", { justification: "This justification would otherwise be valid." }, "invalid_state"],
    [null, { justification: "This justification would otherwise be valid." }, "invalid_state"],
  ])("rejects invalid token state", async (token, body, code) => {
    const request = submitRequest(token ?? "", body);
    if (token === null) request.headers.delete(TOKEN_HEADER);
    const next = originNext();
    const response = await handleGateway(request, CONTEXT, next, deps(fakeStore({})));
    expect(await response.json()).toMatchObject({ error: code });
    expectNoOriginCall(next);
  });

  it("rejects tokens bound to another scope or token type", async () => {
    for (const token of [
      await formToken({ identity: "other@example.com" }),
      await formToken({ host: "other.example.com" }),
      await formToken({ requestedUrl: "https://example.com/another" }),
      await signToken(SECRET, {
        type: "status",
        identityKind: "email",
        identity: USER_EMAIL,
        host: "example.com",
        requestId: "request-id",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 600,
      }),
    ]) {
      const next = originNext();
      const response = await handleGateway(submitRequest(token), CONTEXT, next, deps(fakeStore({})));
      expect(await response.json()).toMatchObject({ error: "invalid_state" });
      expectNoOriginCall(next);
    }
  });

  it.each([
    ["{", 400, "invalid_request"],
    [JSON.stringify({ nope: true }), 400, "invalid_request"],
    [JSON.stringify({ justification: "short" }), 400, "invalid_request"],
    [JSON.stringify({ justification: "x".repeat(1001) }), 400, "invalid_request"],
  ])("validates submission JSON", async (body, status, code) => {
    const next = originNext();
    const response = await handleGateway(submitRequest(await formToken(), body), CONTEXT, next, deps(fakeStore({})));
    expect(response.status).toBe(status);
    expect(await response.json()).toMatchObject({ error: code });
    expectNoOriginCall(next);
  });

  it("rejects submission bodies over 4096 bytes", async () => {
    const request = submitRequest(await formToken(), { justification: "x".repeat(5000) });
    const next = originNext();
    const response = await handleGateway(request, CONTEXT, next, deps(fakeStore({})));
    expect(response.status).toBe(413);
    expect(await response.json()).toMatchObject({ error: "payload_too_large" });
    expectNoOriginCall(next);
  });

  it.each([
    [{ state: "created", request: requestView() } satisfies SubmitResult, 200, "x-gw-pj-submit", { ok: true }],
    [{ state: "existing", request: requestView() } satisfies SubmitResult, 200, "x-gw-pj-submit", { ok: true }],
    [{ state: "rate_limited", retryAfterSeconds: 42 } satisfies SubmitResult, 429, "x-gw-pj-rate-limited", { error: "rate_limited" }],
    [{ state: "config_changed" } satisfies SubmitResult, 409, "x-gw-pj-submit", { error: "config_changed" }],
    [{ state: "granted", grant: grantView() } satisfies SubmitResult, 409, "x-gw-pj-submit", { error: "already_granted" }],
    [{ state: "denied", hold: holdView() } satisfies SubmitResult, 409, "x-gw-pj-submit", { error: "denied" }],
    [{ state: "invalid" } satisfies SubmitResult, 400, "x-gw-pj-submit", { error: "invalid_state" }],
  ])("maps store submission result %#", async (result, status, header, body) => {
    const submit = vi.fn(async (_input: SubmitInput) => result);
    const next = originNext();
    const response = await handleGateway(submitRequest(await formToken()), CONTEXT, next, deps(fakeStore({ submit })));
    expect(response.status).toBe(status);
    expect(response.headers.get(header)).toBe("true");
    expect(await response.json()).toMatchObject(body);
    expectNoOriginCall(next);
    expect(submit).toHaveBeenCalledOnce();
    expect(submit.mock.calls[0]?.[0]).toMatchObject({
      identityKind: "email",
      identity: USER_EMAIL,
      identityName: USER_NAME,
      host: "example.com",
      justification: "This access is required to resolve a customer support incident.",
    });
    if (result.state === "rate_limited") expect(response.headers.get("retry-after")).toBe("42");
  });
});

describe("status protocol", () => {
  it("validates status method, secret, and token scope", async () => {
    const valid = await statusToken();
    const cases: Array<[Request, string | undefined, number]> = [
      [statusRequest(valid, "POST"), SECRET, 400],
      [statusRequest(valid), undefined, 503],
      [statusRequest("invalid"), SECRET, 400],
      [statusRequest(await statusToken({ identity: "other@example.com" })), SECRET, 400],
      [statusRequest(await statusToken({ host: "other.example.com" })), SECRET, 400],
      [statusRequest(await formToken()), SECRET, 400],
    ];
    for (const [request, secret, expected] of cases) {
      const next = originNext();
      const response = await handleGateway(request, CONTEXT, next, deps(fakeStore({}), secret));
      expect(response.status).toBe(expected);
      expect(response.headers.get(expected === 503 ? "x-gw-pj-error" : "x-gw-pj-status")).toBe("true");
      expect(response.headers.get("x-gw-pj-submit")).toBeNull();
      expectNoOriginCall(next);
    }
  });

  it("logs status protocol rejections with the status event", async () => {
    const consoleLog = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      await handleGateway(statusRequest(await statusToken(), "POST"), CONTEXT, originNext(), deps(fakeStore({})));
      expect(consoleLog).toHaveBeenCalledWith(expect.objectContaining({ event: "pj_status_rejected" }));
      expect(consoleLog).not.toHaveBeenCalledWith(expect.objectContaining({ event: "pj_submit_rejected" }));
    } finally {
      consoleLog.mockRestore();
    }
  });

  it("returns controlled JSON when the status state service fails", async () => {
    const next = originNext();
    const status = vi.fn(async () => { throw new Error("internal state details"); });
    const response = await handleGateway(
      statusRequest(await statusToken()),
      CONTEXT,
      next,
      deps(fakeStore({ status })),
    );
    expect(response.status).toBe(503);
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(response.headers.get("x-gw-pj-error")).toBe("true");
    expect(response.headers.get("x-gw-pj-status")).toBeNull();
    expect(response.headers.get("x-gw-pj-submit")).toBeNull();
    expect(await response.json()).toEqual({
      error: "service_unavailable",
      message: "State service is temporarily unavailable.",
    });
    expectNoOriginCall(next);
  });

  it.each([
    [{ state: "pending", request: requestView() } satisfies StatusResult, { status: "pending", requestId: "request-id" }],
    [{ state: "approved", requestId: "request-id", grant: grantView() } satisfies StatusResult, { status: "approved", requestId: "request-id" }],
    [{ state: "denied", requestId: "request-id", hold: holdView() } satisfies StatusResult, { status: "denied", requestId: "request-id" }],
    [{ state: "expired", requestId: "request-id" } satisfies StatusResult, { status: "expired", requestId: "request-id" }],
  ])("maps status result %#", async (result, expected) => {
    const next = originNext();
    const status = vi.fn(async () => result);
    const response = await handleGateway(statusRequest(await statusToken()), CONTEXT, next, deps(fakeStore({ status })));
    expect(response.status).toBe(200);
    expect(response.headers.get("x-gw-pj-status")).toBe("true");
    expect(await response.json()).toMatchObject(expected);
    expect(status).toHaveBeenCalledWith(expect.objectContaining({ requestId: "request-id", identity: USER_EMAIL }));
    expectNoOriginCall(next);
  });

  it("rejects a status token for a missing request", async () => {
    const next = originNext();
    const response = await handleGateway(
      statusRequest(await statusToken()),
      CONTEXT,
      next,
      deps(fakeStore({ status: vi.fn(async () => ({ state: "invalid" } satisfies StatusResult)) })),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_state" });
    expectNoOriginCall(next);
  });
});

describe("gateway and GateStore integration", () => {
  it("completes form, submission, approval, polling, pass-through, and denial", async () => {
    const stub = store();
    const next = originNext();
    const form = await handleGateway(navigation(), CONTEXT, next, deps(stub));
    const html = await form.text();
    const tokenMatch = html.match(/formToken=("[^"]+")/);
    if (!tokenMatch?.[1]) throw new Error("Form token not found");
    const token = JSON.parse(tokenMatch[1]) as string;

    const submitted = await handleGateway(submitRequest(token), CONTEXT, next, deps(stub));
    const submissionBody = await submitted.json<{
      request: { id: string };
      statusToken: string;
    }>();
    expect(submissionBody.request.id).toBeTruthy();
    expectNoOriginCall(next);
    expect(await stub.getRequest(submissionBody.request.id)).toMatchObject({
      identityKind: "email",
      identity: USER_EMAIL,
      identityName: USER_NAME,
    });

    const otherUser = await handleGateway(navigation(), gatewayContext({ email: "other@example.com" }), next, deps(stub));
    expect(otherUser.headers.get("x-gw-pj-form")).toBe("true");
    const stolen = await handleGateway(statusRequest(submissionBody.statusToken), gatewayContext({ email: "other@example.com" }), next, deps(stub));
    expect(await stolen.json()).toMatchObject({ error: "invalid_state" });

    const pending = await handleGateway(navigation(), CONTEXT, next, deps(stub));
    expect(pending.headers.get("x-gw-pj-pending")).toBe("true");
    expect(await pending.text()).toContain("Awaiting administrator decision");

    const approved = await stub.approve(submissionBody.request.id, 120, ACTOR);
    expect(approved.ok).toBe(true);
    const polled = await handleGateway(statusRequest(submissionBody.statusToken), CONTEXT, next, deps(stub));
    expect(await polled.json()).toMatchObject({ status: "approved" });
    expectNoOriginCall(next);

    const grantedRequest = navigation(URL, { method: "POST", body: "original approved request" });
    const granted = await handleGateway(grantedRequest, CONTEXT, next, deps(stub));
    expect(granted.headers.get("x-gw-pj-granted")).toBe("true");
    expect(next).toHaveBeenCalledOnce();
    expect(next.mock.calls[0]?.[0]).toBe(grantedRequest);

    if (!approved.ok) return;
    await stub.revokeGrant(approved.value.grant.id, ACTOR);
    const denialRequest = await stub.submit(submission({
      submissionNonce: randomNonce(),
      requestedUrl: "https://example.com/private",
    }));
    if (denialRequest.state !== "created") throw new Error("Expected another request");
    await stub.deny(denialRequest.request.id, "This destination is outside approved policy.", ACTOR);
    const denied = await handleGateway(navigation(), CONTEXT, next, deps(stub));
    expect(denied.headers.get("x-gw-pj-denied")).toBe("true");
    expect(await denied.text()).toContain("outside approved policy");
    expect(next).toHaveBeenCalledOnce();
  });
});
