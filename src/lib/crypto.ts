import type { BrowserTokenPayload } from "../types.js";
import { MAX_EMAIL_LENGTH } from "../types.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export async function signToken(secret: string, payload: BrowserTokenPayload): Promise<string> {
  const encoded = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const key = await importKey(secret, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, asArrayBuffer(encoder.encode(encoded)));
  return `${encoded}.${base64UrlEncode(new Uint8Array(signature))}`;
}

export async function verifyToken(
  secret: string,
  token: string | null,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<BrowserTokenPayload | null> {
  if (!secret || !token) return null;
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  try {
    const key = await importKey(secret, ["verify"]);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      asArrayBuffer(base64UrlDecode(parts[1])),
      asArrayBuffer(encoder.encode(parts[0])),
    );
    if (!valid) return null;
    const payload: unknown = JSON.parse(decoder.decode(base64UrlDecode(parts[0])));
    if (!validPayload(payload, nowSeconds)) return null;
    return payload;
  } catch {
    return null;
  }
}

export function randomNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function validPayload(value: unknown, now: number): value is BrowserTokenPayload {
  if (!isRecord(value) || value.identityKind !== "email") return false;
  if (!string(value.identity, 3, MAX_EMAIL_LENGTH) || !string(value.host, 1, 253)) return false;
  if (!integer(value.iat) || !integer(value.exp) || value.iat > now || value.exp <= now) return false;

  if (value.type === "form") return validForm(value);
  if (value.type === "status") return validStatus(value);
  return false;
}

function validForm(value: Record<string, unknown>): boolean {
  return (
    string(value.policyKind, 1, 64) &&
    integer(value.configVersion) &&
    string(value.requestedUrl, 1, 2048) &&
    typeof value.nonce === "string" &&
    /^[A-Za-z0-9_-]{22}$/.test(value.nonce) &&
    (value.exp as number) - (value.iat as number) === 600
  );
}

function validStatus(value: Record<string, unknown>): boolean {
  return string(value.requestId, 1, 64);
}

function importKey(secret: string, usages: ("sign" | "verify")[]): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    asArrayBuffer(encoder.encode(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    usages,
  );
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function string(value: unknown, min: number, max: number): value is string {
  return typeof value === "string" && value.length >= min && value.length <= max;
}

function integer(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}
