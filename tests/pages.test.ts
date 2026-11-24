import { describe, expect, it } from "vitest";
import {
  escapeHtml,
  renderDenied,
  renderForm,
  renderIdentityRequired,
  renderPending,
  renderUnavailable,
} from "../src/pages/render.js";
import { DEFAULT_CONFIG } from "../src/store/config.js";
import type { HoldView, RequestView } from "../src/types.js";

const ATTACK = `<script>alert("x")</script>'&`;
const policy = {
  ...DEFAULT_CONFIG.policies.generic!,
  formTitle: `Title ${ATTACK}`,
  formPrompt: `Prompt ${ATTACK}`,
  pendingTitle: `Pending ${ATTACK}`,
  pendingMessage: `Message ${ATTACK}`,
  blockTitle: `Blocked ${ATTACK}`,
  blockMessage: `Block message ${ATTACK}`,
  helpUrl: "https://support.example/?value=%22%3E",
};

const request: RequestView = {
  id: "request-id",
  status: "pending",
  identityKind: "email",
  identity: "user@example.com",
  identityName: "Example User",
  host: "example.com",
  requestedUrl: "https://example.com/private",
  justification: ATTACK,
  policyKind: "generic",
  createdAt: "2026-08-27T00:00:00.000Z",
  expiresAt: "2026-08-28T00:00:00.000Z",
  decidedAt: null,
  decidedBy: null,
  decidedBySource: null,
  decisionReason: null,
  grantSeconds: null,
  userAgent: "test",
  configVersion: 1,
  grant: null,
  hold: null,
};

const hold: HoldView = {
  id: "hold-id",
  requestId: "request-id",
  identityKind: "email",
  identity: "user@example.com",
  host: "example.com",
  status: "active",
  reason: ATTACK,
  deniedAt: "2026-08-27T00:00:00.000Z",
  expiresAt: "2026-08-28T00:00:00.000Z",
  deniedBy: "admin@example.com",
  deniedBySource: "access-header",
  clearedAt: null,
  clearedBy: null,
  clearedBySource: null,
};

describe("end-user page rendering", () => {
  it("escapes every HTML metacharacter", () => {
    expect(escapeHtml(`&<>"'`)).toBe("&amp;&lt;&gt;&quot;&#39;");
  });

  it("renders an escaped form with matching CSP nonce inputs", () => {
    const page = renderForm({
      host: ATTACK,
      requestedUrl: `https://example.com/${ATTACK}`,
      policy,
      formToken: `token</script><script>alert(1)</script>`,
    });
    expect(page.nonce).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(page.html).toContain("&lt;script&gt;");
    expect(page.html).toContain("token\\u003c/script>\\u003cscript>");
    expect(page.html).not.toContain("token</script>");
    expect(page.html).toContain(`style nonce="${page.nonce}"`);
    expect(page.html).toContain(`script nonce="${page.nonce}"`);
    expect(page.html).not.toContain("requested-duration");
    expect(page.html).toContain("['invalid_state','config_changed','already_granted','denied','identity_required']");
  });

  it("renders pending state without interpreting justification", () => {
    const page = renderPending({
      host: "example.com",
      requestedUrl: request.requestedUrl,
      policy,
      request,
      statusToken: "status-token",
    });
    expect(page.html).toContain("status-token");
    expect(page.html).toContain("\\u003cscript>alert");
    expect(page.html).not.toContain(ATTACK);
    expect(page.html).toContain("id=\"wait-view\"");
    expect(page.html).toContain("['invalid_state','identity_required'].includes(result.data.error)");
  });

  it("renders escaped denial and generic unavailable pages", () => {
    const denied = renderDenied({ host: ATTACK, policy, hold });
    expect(denied.html).toContain("&lt;script&gt;");
    expect(denied.html).not.toContain(ATTACK);
    expect(denied.html).toContain("Contact support");

    const unavailable = renderUnavailable();
    expect(unavailable.html).toContain("Access check unavailable");
    expect(unavailable.html).not.toContain("database");
    expect(unavailable.html).toContain(`nonce="${unavailable.nonce}"`);
  });

  it("does not surface the IP-based limitation in any user state", () => {
    const form = renderForm({
      host: "example.com",
      requestedUrl: request.requestedUrl,
      policy,
      formToken: "form-token",
    });
    const pending = renderPending({
      host: "example.com",
      requestedUrl: request.requestedUrl,
      policy,
      request,
      statusToken: "status-token",
    });
    const denied = renderDenied({ host: "example.com", policy, hold });
    const unavailable = renderUnavailable();
    const identity = renderIdentityRequired({ host: "example.com" });

    for (const html of [form.html, pending.html, denied.html, unavailable.html, identity.html]) {
      expect(html).not.toContain("Shared egress");
      expect(html).not.toContain("source IP");
      expect(html).not.toContain("bodyless GET");
    }
    expect(form.html).toContain("Administrators receive your Zero Trust email and name, this host and path");
  });

  it("renders an escaped sign-in required page", () => {
    const page = renderIdentityRequired({ host: ATTACK });
    expect(page.html).toContain("Sign-in required");
    expect(page.html).toContain("&lt;script&gt;");
    expect(page.html).not.toContain(ATTACK);
    expect(page.html).toContain(`script nonce="${page.nonce}"`);
  });
});
