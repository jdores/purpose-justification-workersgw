export function canonicalizeHost(value: string): string | null {
  if (!value || value.length > 254 || /[\s@/\\?#]/u.test(value)) return null;
  try {
    const parsed = new URL(`https://${value}`).hostname.toLowerCase();
    const withoutRootDot = parsed.endsWith(".") ? parsed.slice(0, -1) : parsed;
    const normalized = withoutRootDot.startsWith("www.") ? withoutRootDot.slice(4) : withoutRootDot;
    return normalized && normalized.length <= 253 ? normalized : null;
  } catch {
    return null;
  }
}
