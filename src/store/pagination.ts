const VALID_LIMIT = 100;

export interface PageCursor {
  at: number;
  id: string;
  direction: "asc" | "desc";
}

export function normalizeLimit(value: number | undefined): number {
  if (value === undefined) return 50;
  if (!Number.isInteger(value) || value < 1 || value > VALID_LIMIT) {
    throw new RangeError("limit must be an integer between 1 and 100");
  }
  return value;
}

export function encodeCursor(cursor: PageCursor): string {
  return base64UrlEncode(JSON.stringify(cursor));
}

export function decodeCursor(value: string | undefined, direction: PageCursor["direction"]): PageCursor | null {
  if (!value) return null;
  try {
    const parsed: unknown = JSON.parse(base64UrlDecode(value));
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      !("at" in parsed) ||
      !("id" in parsed) ||
      !("direction" in parsed) ||
      !Number.isInteger(parsed.at) ||
      typeof parsed.id !== "string" ||
      parsed.id.length > 64 ||
      parsed.direction !== direction
    ) {
      throw new Error();
    }
    return parsed as PageCursor;
  } catch {
    throw new RangeError("cursor is invalid");
  }
}

function base64UrlEncode(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value: string): string {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return new TextDecoder().decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
}
