import { bytesToStream } from "../lib/stream.js";
import { WORKER_NAME } from "../types.js";

export function tagPassThrough(
  response: Response,
  invocationId: string,
  decisionHeader: string,
  extra?: Record<string, string>,
): Response {
  const headers = new Headers(response.headers);
  for (const name of [...headers.keys()]) {
    const normalized = name.toLowerCase();
    if (normalized === "x-gw-worker-name" || normalized === "x-gw-auth-skip" || normalized.startsWith("x-gw-pj-")) {
      headers.delete(name);
    }
  }
  headers.set("x-gw-worker-name", WORKER_NAME);
  headers.set("x-gw-pj-request-id", invocationId);
  headers.set(decisionHeader, "true");
  for (const [name, value] of Object.entries(extra ?? {})) headers.set(name, value);
  const init: ResponseInit = {
    status: response.status,
    statusText: response.statusText,
    headers,
  };
  if (response.webSocket) init.webSocket = response.webSocket;
  return new Response(response.body, init);
}

export function syntheticResponse(input: {
  body: string;
  status: number;
  invocationId: string;
  decisionHeader: string;
  contentType: "html" | "json";
  omitBody?: boolean;
  nonce?: string;
  extraHeaders?: Record<string, string>;
}): Response {
  const headers = syntheticHeaders(input);
  const body = input.omitBody ? null : bytesToStream(new TextEncoder().encode(input.body));
  return new Response(body, { status: input.status, headers });
}

export function emergencySyntheticResponse(input: {
  body: string;
  status: number;
  invocationId: string;
  decisionHeader: string;
  contentType: "html" | "json";
  omitBody?: boolean;
  extraHeaders?: Record<string, string>;
}): Response {
  return new Response(input.omitBody ? null : input.body, { status: input.status, headers: syntheticHeaders(input) });
}

function syntheticHeaders(input: {
  invocationId: string;
  decisionHeader: string;
  contentType: "html" | "json";
  nonce?: string;
  extraHeaders?: Record<string, string>;
}): Headers {
  const headers = new Headers(input.extraHeaders);
  headers.set("content-type", `${input.contentType === "html" ? "text/html" : "application/json"}; charset=utf-8`);
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-gw-worker-name", WORKER_NAME);
  headers.set("x-gw-pj-request-id", input.invocationId);
  headers.set(input.decisionHeader, "true");
  if (input.contentType === "html") {
    const nonce = input.nonce ?? "none";
    headers.set(
      "content-security-policy",
      `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'`,
    );
    headers.set("x-frame-options", "DENY");
    headers.set("referrer-policy", "no-referrer");
    headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  }
  return headers;
}
