import type { GateStore } from "../store/gate-store.js";
import { signToken, verifyToken, randomNonce } from "../lib/crypto.js";
import { InvalidJsonError, isRecord, PayloadTooLargeError, readJson } from "../lib/json.js";
import { log, logError } from "../lib/log.js";
import {
  renderDenied,
  renderForm,
  renderIdentityRequired,
  renderPending,
  renderUnavailable,
} from "../pages/render.js";
import type {
  FormTokenPayload,
  GatewayContext,
  IdentityKind,
  NextFn,
  StatusTokenPayload,
} from "../types.js";
import {
  ACTION_HEADER,
  FORM_TOKEN_TTL_SECONDS,
  TOKEN_HEADER,
} from "../types.js";
import { IdentityUnavailableError, resolveIdentity, resolveTarget, type RequestScope } from "./identity.js";
import { isAuthEndpoint, isTopLevelDocument } from "./navigation.js";
import { emergencySyntheticResponse, syntheticResponse, tagPassThrough } from "./origin.js";

interface GatewayDeps {
  store: DurableObjectStub<GateStore>;
  signingSecret: string | undefined;
  waitUntil: (promise: Promise<unknown>) => void;
}

interface Invocation {
  id: string;
  started: number;
  omitBody: boolean;
}

type ProtocolAction = "submit" | "status";

const SERVICE_UNAVAILABLE = { error: "service_unavailable", message: "State service is temporarily unavailable." };

/**
 * Gateway Forward middleware. `next()` is called at most once, and only on pass-through paths
 * (authentication bypass, non-navigation traffic, and active grants). Every synthetic response is
 * produced without contacting the destination origin.
 */
export async function handleGateway(
  request: Request,
  context: GatewayContext,
  next: NextFn,
  deps: GatewayDeps,
): Promise<Response> {
  const invocation: Invocation = {
    id: crypto.randomUUID(),
    started: Date.now(),
    omitBody: request.method === "HEAD",
  };
  let nextFailed = false;
  let upstream: Response | null = null;
  const passThrough = async (
    decisionHeader: string,
    event: string,
    fields: Record<string, unknown>,
    extra?: Record<string, string>,
  ): Promise<Response> => {
    try {
      upstream = await next(request);
    } catch (error) {
      nextFailed = true;
      throw error;
    }
    log(event, { ...eventFields(invocation), ...fields });
    return tagPassThrough(upstream, invocation.id, decisionHeader, extra);
  };
  const rawAction = request.headers.get(ACTION_HEADER);
  const action: ProtocolAction | null = rawAction === "submit" || rawAction === "status" ? rawAction : null;

  try {
    const target = resolveTarget(request, context);

    if (isAuthEndpoint(request.url)) {
      return await passThrough("x-gw-auth-skip", "pj_auth_skip", { host: target.host });
    }
    if (rawAction && !action) {
      return protocolError(invocation, null, 400, "invalid_request", "Invalid protocol action.");
    }
    if (!action && !isTopLevelDocument(request.headers)) {
      return await passThrough("x-gw-pj-subresource", "pj_subresource_skip", { host: target.host });
    }

    if (!deps.signingSecret) throw new MissingSecretError();
    const identity = await resolveIdentity(context);
    if (identity.state === "anonymous") return identityRequired(invocation, target.host, action);
    const scope: RequestScope = {
      identityKind: identity.identityKind,
      identity: identity.identity,
      host: target.host,
      requestedUrl: target.requestedUrl,
    };

    if (action === "submit") {
      return await handleSubmit(request, scope, identity.name, deps.signingSecret, deps, invocation);
    }
    if (action === "status") {
      return await handleStatus(request, scope, deps.signingSecret, deps, invocation);
    }

    const evaluation = await deps.store.evaluate(scope);
    if (evaluation.state === "granted") {
      return await passThrough(
        "x-gw-pj-granted",
        "pj_grant_pass",
        { host: scope.host, grant_id: evaluation.grant.id },
        { "x-gw-pj-grant-until": evaluation.grant.expiresAt },
      );
    }

    if (evaluation.state === "denied") {
      const page = renderDenied({ host: scope.host, policy: evaluation.policy, hold: evaluation.hold });
      log("pj_denied_render", {
        ...eventFields(invocation),
        host: scope.host,
        request_id: evaluation.hold.requestId,
      });
      return htmlResponse(invocation, page, 200, "x-gw-pj-denied", { "x-gw-pj-hold-until": evaluation.hold.expiresAt });
    }

    if (evaluation.state === "pending") {
      const statusToken = await createStatusToken(deps.signingSecret, evaluation.request);
      const page = renderPending({
        host: scope.host,
        requestedUrl: scope.requestedUrl,
        policy: evaluation.policy,
        request: evaluation.request,
        statusToken,
      });
      log("pj_pending_render", {
        ...eventFields(invocation),
        host: scope.host,
        request_id: evaluation.request.id,
      });
      return htmlResponse(invocation, page, 200, "x-gw-pj-pending");
    }

    const now = Math.floor(Date.now() / 1000);
    const formPayload: FormTokenPayload = {
      type: "form",
      identityKind: scope.identityKind,
      identity: scope.identity,
      host: scope.host,
      policyKind: evaluation.policy.kind,
      configVersion: evaluation.config.version,
      requestedUrl: scope.requestedUrl,
      iat: now,
      exp: now + FORM_TOKEN_TTL_SECONDS,
      nonce: randomNonce(),
    };
    const formToken = await signToken(deps.signingSecret, formPayload);
    const page = renderForm({
      host: scope.host,
      requestedUrl: scope.requestedUrl,
      policy: evaluation.policy,
      formToken,
    });
    log("pj_form_render", { ...eventFields(invocation), host: scope.host });
    return htmlResponse(invocation, page, 200, "x-gw-pj-form");
  } catch (error) {
    if (nextFailed) {
      logError("next_failed", error, errorFields(invocation));
      throw error;
    }
    const reason = error instanceof MissingSecretError
      ? "missing_signing_secret"
      : error instanceof IdentityUnavailableError
        ? "identity_unavailable"
        : "middleware_failed";
    logError(reason, error, errorFields(invocation));
    const retained = upstream as Response | null;
    if (retained?.body) {
      try {
        deps.waitUntil(retained.body.cancel().catch(() => undefined));
      } catch {
        // The fail-closed response does not depend on cancelling the retained body.
      }
    }
    try {
      if (action) {
        log(`pj_${action}_rejected`, {
          ...eventFields(invocation, "service_unavailable"),
          reason: "service_unavailable",
        });
        return jsonResponse(invocation, 503, "x-gw-pj-error", SERVICE_UNAVAILABLE, { "retry-after": "10" });
      }
      return htmlResponse(invocation, renderUnavailable(), 503, "x-gw-pj-error", { "retry-after": "10" });
    } catch (fallbackError) {
      logError("fallback_response_failed", fallbackError, errorFields(invocation));
      return emergencySyntheticResponse({
        body: action
          ? JSON.stringify(SERVICE_UNAVAILABLE)
          : "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Service unavailable</title><h1>Service unavailable</h1><p>Access cannot be evaluated right now. Please try again.</p></html>",
        status: 503,
        invocationId: invocation.id,
        decisionHeader: "x-gw-pj-error",
        contentType: action ? "json" : "html",
        omitBody: invocation.omitBody,
        extraHeaders: { "retry-after": "10" },
      });
    }
  }
}

async function handleSubmit(
  request: Request,
  scope: RequestScope,
  identityName: string | null,
  signingSecret: string,
  deps: GatewayDeps,
  invocation: Invocation,
): Promise<Response> {
  if (request.method !== "POST" || !isJsonContentType(request.headers.get("content-type"))) {
    return protocolError(invocation, "submit", 400, "invalid_request", "Invalid request body.");
  }
  const payload = await verifyToken(signingSecret, request.headers.get(TOKEN_HEADER));
  if (
    !payload ||
    payload.type !== "form" ||
    payload.identityKind !== scope.identityKind ||
    payload.identity !== scope.identity ||
    payload.host !== scope.host ||
    payload.requestedUrl !== scope.requestedUrl
  ) {
    return protocolError(invocation, "submit", 400, "invalid_state", "Invalid or expired request state.");
  }

  let parsed: unknown;
  try {
    parsed = await readJson(request, 4096);
  } catch (error) {
    if (error instanceof PayloadTooLargeError) {
      return protocolError(invocation, "submit", 413, "payload_too_large", "Request body is too large.");
    }
    if (error instanceof InvalidJsonError) {
      return protocolError(invocation, "submit", 400, "invalid_request", "Invalid request body.");
    }
    throw error;
  }
  if (!isRecord(parsed) || typeof parsed.justification !== "string") {
    return protocolError(invocation, "submit", 400, "invalid_request", "Invalid request body.");
  }
  const justification = parsed.justification.trim();
  const length = [...justification].length;
  if (length < 20 || length > 1000) {
    return protocolError(invocation, "submit", 400, "invalid_request", "Justification must be 20-1000 characters.");
  }

  const result = await deps.store.submit({
    identityKind: scope.identityKind,
    identity: scope.identity,
    identityName,
    host: scope.host,
    submissionNonce: payload.nonce,
    requestedUrl: payload.requestedUrl,
    justification,
    policyKind: payload.policyKind,
    configVersion: payload.configVersion,
    userAgent: request.headers.get("user-agent") ?? "",
  });

  if (result.state === "created" || result.state === "existing") {
    const statusToken = await createStatusToken(signingSecret, result.request);
    log(result.state === "created" ? "pj_submit_created" : "pj_submit_existing", {
      ...eventFields(invocation, result.state),
      request_id: result.request.id,
      host: scope.host,
    });
    return jsonResponse(invocation, 200, "x-gw-pj-submit", {
      ok: true,
      request: {
        id: result.request.id,
        status: "pending",
        createdAt: result.request.createdAt,
        expiresAt: result.request.expiresAt,
      },
      statusToken,
      existing: result.state === "existing",
    });
  }
  if (result.state === "rate_limited") {
    log("pj_submit_rate_limited", {
      ...eventFields(invocation, "rate_limited"),
      host: scope.host,
      retry_after_seconds: result.retryAfterSeconds,
    });
    return jsonResponse(
      invocation,
      429,
      "x-gw-pj-rate-limited",
      { error: "rate_limited", message: "Too many access requests.", retryAfterSeconds: result.retryAfterSeconds },
      { "retry-after": String(result.retryAfterSeconds) },
    );
  }
  if (result.state === "config_changed") {
    return protocolError(invocation, "submit", 409, "config_changed", "Page configuration changed; reload and try again.");
  }
  if (result.state === "granted") {
    return jsonResponse(invocation, 409, "x-gw-pj-submit", {
      error: "already_granted",
      message: "Access is already approved; reload the page.",
      grantExpiresAt: result.grant.expiresAt,
    });
  }
  if (result.state === "denied") {
    return jsonResponse(invocation, 409, "x-gw-pj-submit", {
      error: "denied",
      message: "Access is currently denied.",
      reason: result.hold.reason,
      holdExpiresAt: result.hold.expiresAt,
    });
  }
  return protocolError(invocation, "submit", 400, "invalid_state", "Invalid or expired request state.");
}

async function handleStatus(
  request: Request,
  scope: RequestScope,
  signingSecret: string,
  deps: GatewayDeps,
  invocation: Invocation,
): Promise<Response> {
  if (request.method !== "GET") {
    return protocolError(invocation, "status", 400, "invalid_request", "Invalid status request.");
  }
  const payload = await verifyToken(signingSecret, request.headers.get(TOKEN_HEADER));
  if (
    !payload ||
    payload.type !== "status" ||
    payload.identityKind !== scope.identityKind ||
    payload.identity !== scope.identity ||
    payload.host !== scope.host
  ) {
    return protocolError(invocation, "status", 400, "invalid_state", "Invalid or expired request state.");
  }
  const result = await deps.store.status({
    identityKind: scope.identityKind,
    identity: scope.identity,
    host: scope.host,
    requestId: payload.requestId,
  });
  if (result.state === "invalid") {
    return protocolError(invocation, "status", 400, "invalid_state", "Invalid or expired request state.");
  }
  let body: Record<string, unknown>;
  if (result.state === "pending") {
    body = { status: "pending", requestId: result.request.id, expiresAt: result.request.expiresAt };
  } else if (result.state === "approved") {
    body = { status: "approved", requestId: result.requestId, grantExpiresAt: result.grant.expiresAt };
  } else if (result.state === "denied") {
    body = {
      status: "denied",
      requestId: result.requestId,
      reason: result.hold.reason,
      holdExpiresAt: result.hold.expiresAt,
    };
  } else {
    body = { status: "expired", requestId: result.requestId };
  }
  if (result.state !== "pending") {
    log("pj_status_result", {
      ...eventFields(invocation, result.state),
      host: scope.host,
      request_id: result.requestId,
    });
  }
  return jsonResponse(invocation, 200, "x-gw-pj-status", body);
}

function identityRequired(invocation: Invocation, host: string, action: ProtocolAction | null): Response {
  log("pj_identity_required", { ...eventFields(invocation, "identity_required"), host });
  if (action) {
    return jsonResponse(invocation, 403, "x-gw-pj-identity-required", {
      error: "identity_required",
      message: "A signed-in Zero Trust session is required.",
    });
  }
  return htmlResponse(invocation, renderIdentityRequired({ host }), 403, "x-gw-pj-identity-required");
}

function protocolError(
  invocation: Invocation,
  action: ProtocolAction | null,
  status: number,
  code: string,
  message: string,
): Response {
  log(action ? `pj_${action}_rejected` : "pj_protocol_rejected", {
    ...eventFields(invocation, code),
    reason: code,
  });
  return jsonResponse(invocation, status, action ? `x-gw-pj-${action}` : "x-gw-pj-error", { error: code, message });
}

function jsonResponse(
  invocation: Invocation,
  status: number,
  decisionHeader: string,
  body: unknown,
  extraHeaders?: Record<string, string>,
): Response {
  return syntheticResponse({
    body: JSON.stringify(body),
    status,
    invocationId: invocation.id,
    decisionHeader,
    contentType: "json",
    omitBody: invocation.omitBody,
    ...(extraHeaders ? { extraHeaders } : {}),
  });
}

function htmlResponse(
  invocation: Invocation,
  page: { html: string; nonce: string },
  status: number,
  decisionHeader: string,
  extraHeaders?: Record<string, string>,
): Response {
  return syntheticResponse({
    body: page.html,
    status,
    invocationId: invocation.id,
    decisionHeader,
    contentType: "html",
    omitBody: invocation.omitBody,
    nonce: page.nonce,
    ...(extraHeaders ? { extraHeaders } : {}),
  });
}

async function createStatusToken(
  secret: string,
  request: { id: string; identityKind: IdentityKind; identity: string; host: string; expiresAt: string },
): Promise<string> {
  const payload: StatusTokenPayload = {
    type: "status",
    requestId: request.id,
    identityKind: request.identityKind,
    identity: request.identity,
    host: request.host,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(new Date(request.expiresAt).getTime() / 1000),
  };
  return signToken(secret, payload);
}

function eventFields(invocation: Invocation, outcome = "complete"): Record<string, unknown> {
  return { invocation_id: invocation.id, duration_ms: Date.now() - invocation.started, outcome };
}

function errorFields(invocation: Invocation): Record<string, unknown> {
  return { ...eventFields(invocation, "error") };
}

function isJsonContentType(value: string | null): boolean {
  return value?.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

class MissingSecretError extends Error {}
