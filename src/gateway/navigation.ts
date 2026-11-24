const AUTH_PREFIXES = [
  "/oauth",
  "/auth",
  "/login",
  "/logout",
  "/callback",
  "/.well-known/",
  "/saml",
  "/sso",
  "/token",
  "/favicon.ico",
  "/robots.txt",
];

export function isAuthEndpoint(url: string): boolean {
  try {
    const path = new URL(url).pathname.toLowerCase();
    return AUTH_PREFIXES.some((prefix) => path.startsWith(prefix));
  } catch {
    return false;
  }
}

export function isTopLevelDocument(headers: Headers): boolean {
  const mode = headers.get("sec-fetch-mode")?.toLowerCase();
  const destination = headers.get("sec-fetch-dest")?.toLowerCase();
  if (mode === "navigate" && destination === "document") return true;
  if (mode !== undefined || destination !== undefined) return false;
  return headers.get("accept")?.toLowerCase().includes("text/html") ?? false;
}
