import type { GateStore } from "../store/gate-store.js";
import { InvalidJsonError, isRecord, PayloadTooLargeError, readJson } from "../lib/json.js";
import { json } from "../lib/json.js";
import { log, logError } from "../lib/log.js";
import type { Actor, ListInput, StoreResult } from "../types.js";
import { WORKER_NAME } from "../types.js";
import { renderAdmin } from "./ui.js";

export async function handleAdmin(request: Request, store: DurableObjectStub<GateStore>): Promise<Response> {
  const url = new URL(request.url);
  const invocationId = crypto.randomUUID();
  const started = Date.now();
  let outcome = "complete";
  try {
    if (url.pathname === "/" && request.method === "GET") return adminPage(url);
    if (url.pathname === "/health" && request.method === "GET") {
      return json({ ok: true, worker: WORKER_NAME });
    }
    if (url.pathname === "/ws") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      if (!sameOrigin(request, url) || request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
        return json({ error: "invalid_origin", message: "A same-origin admin request is required." }, 403);
      }
      return store.fetch(request);
    }

    if (url.pathname === "/api/config") {
      if (request.method === "GET") return json({ config: await store.getConfig() });
      if (request.method === "PUT") {
        const guard = mutationGuard(request, url);
        if (guard) return guard;
        const body = await readJson(request, 65_536);
        const result = await store.putConfig(body as never, actor(request));
        return storeResponse(result, (config) => ({ ok: true, config }));
      }
      return methodNotAllowed("GET, PUT");
    }

    if (url.pathname === "/api/config/reset") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      const guard = mutationGuard(request, url);
      if (guard) return guard;
      const result = await store.resetConfig(actor(request));
      return storeResponse(result, (config) => ({ ok: true, config }));
    }

    if (url.pathname === "/api/requests") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return json(await store.listRequests(listInput(url)));
    }

    const requestRoute = url.pathname.match(/^\/api\/requests\/([^/]+)(?:\/(approve|deny))?$/);
    if (requestRoute) {
      const id = decodeURIComponent(requestRoute[1] ?? "");
      const action = requestRoute[2];
      if (!action) {
        if (request.method !== "GET") return methodNotAllowed("GET");
        const item = await store.getRequest(id);
        return item
          ? json({ request: item })
          : json({ error: "not_found", message: "Request not found." }, 404);
      }
      if (request.method !== "POST") return methodNotAllowed("POST");
      const guard = mutationGuard(request, url);
      if (guard) return guard;
      const body = await readJson(request, 2048);
      if (!isRecord(body)) return invalid("Request body must be an object.");
      if (action === "approve") {
        const grantSeconds = body.grantSeconds;
        if (grantSeconds !== undefined && typeof grantSeconds !== "number") {
          return invalid("grantSeconds must be a number.");
        }
        const result = await store.approve(id, grantSeconds, actor(request));
        return storeResponse(result, (value) => ({ ok: true, ...value }));
      }
      if (typeof body.reason !== "string") return invalid("reason must be a string.");
      const result = await store.deny(id, body.reason, actor(request));
      return storeResponse(result, (value) => ({ ok: true, ...value }));
    }

    if (url.pathname === "/api/grants") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return json(await store.listGrants(listInput(url, "active")));
    }
    if (url.pathname === "/api/holds") {
      if (request.method !== "GET") return methodNotAllowed("GET");
      return json(await store.listHolds(listInput(url, "active")));
    }
    if (url.pathname === "/api/grants/revoke" || url.pathname === "/api/holds/clear") {
      if (request.method !== "POST") return methodNotAllowed("POST");
      const guard = mutationGuard(request, url);
      if (guard) return guard;
      const body = await readJson(request, 2048);
      if (!isRecord(body) || typeof body.id !== "string") return invalid("id must be a string.");
      if (url.pathname === "/api/grants/revoke") {
        const result = await store.revokeGrant(body.id, actor(request));
        return storeResponse(result, (value) => ({ ok: true, value }));
      }
      const result = await store.clearHold(body.id, actor(request));
      return storeResponse(result, (value) => ({ ok: true, value }));
    }

    if (knownPath(url.pathname)) return methodNotAllowed("GET");
    return json({ error: "not_found", message: "Route not found." }, 404);
  } catch (error) {
    outcome = "error";
    if (error instanceof PayloadTooLargeError) {
      return json({ error: "payload_too_large", message: "Request body is too large." }, 413);
    }
    if (error instanceof InvalidJsonError) return invalid("Invalid JSON body.");
    if (error instanceof RangeError) return invalid(error.message);
    logError("admin_request_failed", error, {
      invocation_id: invocationId,
      path: url.pathname,
      duration_ms: Date.now() - started,
      outcome,
    });
    return json({ error: "service_unavailable", message: "State service is temporarily unavailable." }, 503);
  } finally {
    log("pj_admin_request", {
      invocation_id: invocationId,
      path: url.pathname,
      method: request.method,
      duration_ms: Date.now() - started,
      outcome,
    });
  }
}

function adminPage(url: URL): Response {
  const page = renderAdmin();
  const socketOrigin = `${url.protocol === "https:" ? "wss:" : "ws:"}//${url.host}`;
  const headers = new Headers({
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "content-security-policy": `default-src 'none'; script-src 'nonce-${page.nonce}'; style-src 'nonce-${page.nonce}'; connect-src 'self' ${socketOrigin}; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'`,
  });
  return new Response(page.html, { headers });
}

// The only HTTP route is the Access-protected custom domain (workers.dev and previews are disabled),
// so the request's own origin is the admin origin on every deployment, including `wrangler dev`.
function sameOrigin(request: Request, url: URL): boolean {
  return request.headers.get("origin") === url.origin;
}

function mutationGuard(request: Request, url: URL): Response | null {
  if (!sameOrigin(request, url)) {
    return json({ error: "invalid_origin", message: "A same-origin admin request is required." }, 403);
  }
  const mediaType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") {
    return invalid("Content-Type must be application/json.");
  }
  return null;
}

function actor(request: Request): Actor {
  const value = request.headers.get("cf-access-authenticated-user-email")?.trim().toLowerCase();
  if (value && value.length <= 254) return { value, source: "access-header" };
  return { value: "unknown", source: "unknown" };
}

function listInput(url: URL, defaultStatus?: string): ListInput {
  const status = url.searchParams.get("status") ?? defaultStatus;
  const host = url.searchParams.get("host") ?? undefined;
  const cursor = url.searchParams.get("cursor") ?? undefined;
  const rawLimit = url.searchParams.get("limit");
  const limit = rawLimit === null ? undefined : Number(rawLimit);
  return {
    ...(status ? { status } : {}),
    ...(host ? { host } : {}),
    ...(cursor ? { cursor } : {}),
    ...(limit !== undefined ? { limit } : {}),
  };
}

function storeResponse<T>(result: StoreResult<T>, success: (value: T) => unknown): Response {
  if (result.ok) return json(success(result.value));
  const status =
    result.code === "not_found"
      ? 404
      : result.code === "validation_failed"
        ? 400
        : 409;
  return json(
    {
      error: result.code === "validation_failed" ? "invalid_request" : result.code,
      message: result.message,
      ...(result.details ? { details: result.details } : {}),
    },
    status,
  );
}

function invalid(message: string): Response {
  return json({ error: "invalid_request", message }, 400);
}

function methodNotAllowed(allow: string): Response {
  return json(
    { error: "method_not_allowed", message: "Method not allowed." },
    405,
    { allow },
  );
}

function knownPath(path: string): boolean {
  return ["/", "/health", "/ws", "/api/config", "/api/config/reset", "/api/requests", "/api/grants", "/api/holds", "/api/grants/revoke", "/api/holds/clear"].includes(path);
}
