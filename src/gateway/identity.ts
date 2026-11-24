import type { GatewayContext, IdentityKind } from "../types.js";
import { MAX_EMAIL_LENGTH, MAX_IDENTITY_NAME_LENGTH } from "../types.js";
import { canonicalizeHost } from "../lib/host.js";

const EMAIL = /^[^\s@]+@[^\s@]+$/;

export interface RequestTarget {
  host: string;
  requestedUrl: string;
}

export interface RequestScope extends RequestTarget {
  identityKind: IdentityKind;
  identity: string;
}

export type ResolvedIdentity =
  | { state: "identified"; identityKind: IdentityKind; identity: string; name: string | null }
  | { state: "anonymous" };

export class IdentityUnavailableError extends Error {
  constructor(options?: ErrorOptions) {
    super("identity unavailable", options);
    this.name = "IdentityUnavailableError";
  }
}

export function resolveTarget(request: Request, context: { readonly host?: string }): RequestTarget {
  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    if (!context.host || !canonicalizeHost(context.host)) throw new RangeError("invalid host");
    url = new URL(`https://${context.host}/`);
  }

  const host = canonicalizeHost(url.hostname);
  if (!host) throw new RangeError("invalid host");

  url.search = "";
  url.hash = "";
  let requestedUrl = `${url.origin}${url.pathname}`;
  if (requestedUrl.length > 2048) requestedUrl = `${url.origin}${url.pathname.slice(0, 2048 - url.origin.length - 3)}...`;
  return { host, requestedUrl };
}

export async function resolveIdentity(context: Pick<GatewayContext, "identity">): Promise<ResolvedIdentity> {
  let identity: Awaited<ReturnType<GatewayContext["identity"]>>;
  try {
    identity = await context.identity();
  } catch (error) {
    throw new IdentityUnavailableError({ cause: error });
  }
  const email = normalizeEmail(identity?.email);
  if (!email) return { state: "anonymous" };
  return { state: "identified", identityKind: "email", identity: email, name: normalizeName(identity?.name) };
}

export function normalizeEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  if (email.length < 3 || email.length > MAX_EMAIL_LENGTH || !EMAIL.test(email)) return null;
  return email;
}

export function normalizeName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const name = value.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  if (!name) return null;
  return [...name].slice(0, MAX_IDENTITY_NAME_LENGTH).join("");
}
