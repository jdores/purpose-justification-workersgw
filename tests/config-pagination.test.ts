import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG, normalizeConfiguredHost, resolvePolicy, validateConfig } from "../src/store/config.js";
import { decodeCursor, encodeCursor, normalizeLimit } from "../src/store/pagination.js";
import type { ConfigInput, PolicyConfig } from "../src/types.js";

function config(overrides: Partial<ConfigInput> = {}): ConfigInput {
  return {
    defaultGrantSeconds: DEFAULT_CONFIG.defaultGrantSeconds,
    maxGrantSeconds: DEFAULT_CONFIG.maxGrantSeconds,
    denyHoldSeconds: DEFAULT_CONFIG.denyHoldSeconds,
    pendingExpirySeconds: DEFAULT_CONFIG.pendingExpirySeconds,
    retentionDays: DEFAULT_CONFIG.retentionDays,
    submissionLimitPerHour: DEFAULT_CONFIG.submissionLimitPerHour,
    defaultPolicyKind: DEFAULT_CONFIG.defaultPolicyKind,
    policies: DEFAULT_CONFIG.policies,
    hostPolicies: DEFAULT_CONFIG.hostPolicies,
    ...overrides,
  };
}

describe("configuration validation", () => {
  it("accepts the bundled configuration", () => {
    expect(validateConfig(config())).toEqual({ value: config(), errors: [] });
  });

  it("validates numeric bounds and relationships", () => {
    const result = validateConfig(config({
      defaultGrantSeconds: 61.5,
      maxGrantSeconds: 60,
      denyHoldSeconds: 0,
      pendingExpirySeconds: 299,
      retentionDays: 366,
      submissionLimitPerHour: 101,
    }));
    expect(result.errors).toEqual(expect.arrayContaining([
      expect.stringContaining("defaultGrantSeconds"),
      expect.stringContaining("denyHoldSeconds"),
      expect.stringContaining("pendingExpirySeconds"),
      expect.stringContaining("retentionDays"),
      expect.stringContaining("submissionLimitPerHour"),
      "defaultGrantSeconds must not exceed maxGrantSeconds",
    ]));
  });

  it("validates policy names, fields, URLs, and references", () => {
    const result = validateConfig(config({
      defaultPolicyKind: "missing",
      policies: {
        "Bad Kind": {
          kind: "different",
          formTitle: "",
          formPrompt: "x".repeat(1001),
          pendingTitle: "",
          pendingMessage: "",
          blockTitle: "",
          blockMessage: "",
          helpUrl: "file:///secret",
        },
      },
      hostPolicies: { "WWW.Example.com": "missing" },
    }));
    expect(result.value).toBeUndefined();
    expect(result.errors).toEqual(expect.arrayContaining([
      expect.stringContaining("must match"),
      expect.stringContaining("kind must equal"),
      expect.stringContaining("formTitle"),
      expect.stringContaining("formPrompt"),
      expect.stringContaining("helpUrl"),
      expect.stringContaining("defaultPolicyKind"),
      expect.stringContaining("normalized hostname"),
      expect.stringContaining("existing policy"),
    ]));
  });

  it("rejects malformed collections and policy values", () => {
    expect(validateConfig(null).errors).toEqual(["config must be an object"]);
    expect(validateConfig({ ...config(), policies: {} }).errors).toContain(
      "policies must contain between 1 and 50 entries",
    );
    expect(validateConfig({ ...config(), policies: { generic: null } }).errors).toContain(
      "policies.generic must be an object",
    );
    expect(validateConfig({ ...config(), hostPolicies: [] }).errors).toContain("hostPolicies must be an object");
    expect(validateConfig({ ...config(), hostPolicies: Object.fromEntries(
      Array.from({ length: 501 }, (_, index) => [`h${index}.example.com`, "generic"]),
    ) }).errors).toContain("hostPolicies must contain no more than 500 entries");
  });

  it("does not accept inherited policy references", () => {
    const policies = Object.create({ constructor: DEFAULT_CONFIG.policies.generic }) as Record<string, unknown>;
    policies.generic = DEFAULT_CONFIG.policies.generic;
    expect(validateConfig({ ...config(), defaultPolicyKind: "constructor", policies }).errors).toContain(
      "defaultPolicyKind must reference an existing policy",
    );
    expect(validateConfig({ ...config(), policies, hostPolicies: { "example.com": "toString" } }).errors).toContain(
      'hostPolicies["example.com"] must reference an existing policy',
    );
  });

  it.each([
    ["intranet", "intranet"],
    ["example.com", "example.com"],
    ["sub.example.com", "sub.example.com"],
    ["WWW.example.com", null],
    ["www.example.com", null],
    ["*.example.com", null],
    ["example.com/path", null],
    ["", null],
    ["x".repeat(254), null],
    ["bad host", null],
  ])("normalizes configured host %s", (value, expected) => {
    expect(normalizeConfiguredHost(value)).toBe(expected);
  });
});

describe("policy resolution", () => {
  const work = { ...DEFAULT_CONFIG.policies.generic!, kind: "work", formTitle: "Work" };
  const exact = { ...DEFAULT_CONFIG.policies.generic!, kind: "exact", formTitle: "Exact" };
  const configured: PolicyConfig = {
    ...DEFAULT_CONFIG,
    policies: { generic: DEFAULT_CONFIG.policies.generic!, work, exact },
    hostPolicies: { "intranet": "exact", "example.com": "work", "deep.example.com": "exact" },
  };

  it("resolves exact, parent, and default policies", () => {
    expect(resolvePolicy(configured, "intranet").kind).toBe("exact");
    expect(resolvePolicy(configured, "deep.example.com").kind).toBe("exact");
    expect(resolvePolicy(configured, "child.deep.example.com").kind).toBe("exact");
    expect(resolvePolicy(configured, "another.example.com").kind).toBe("work");
    expect(resolvePolicy(configured, "example.org").kind).toBe("generic");
  });

  it("falls back to bundled generic when the default reference is corrupt", () => {
    expect(resolvePolicy({ ...configured, defaultPolicyKind: "missing" }, "example.org").kind).toBe("generic");
  });
});

describe("pagination primitives", () => {
  it("normalizes limits", () => {
    expect(normalizeLimit(undefined)).toBe(50);
    expect(normalizeLimit(1)).toBe(1);
    expect(normalizeLimit(100)).toBe(100);
    for (const invalid of [0, 101, 1.5, Number.NaN]) expect(() => normalizeLimit(invalid)).toThrow(RangeError);
  });

  it("round-trips directional cursors", () => {
    const cursor = { at: 123, id: "request-id", direction: "asc" as const };
    const encoded = encodeCursor(cursor);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeCursor(encoded, "asc")).toEqual(cursor);
    expect(decodeCursor(undefined, "asc")).toBeNull();
  });

  it.each([
    "garbage",
    btoa("{}"),
    btoa(JSON.stringify({ at: 1, id: "request-id", direction: "desc" })),
    btoa(JSON.stringify({ at: 1.5, id: "request-id", direction: "asc" })),
    btoa(JSON.stringify({ at: 1, id: "x".repeat(65), direction: "asc" })),
    btoa("null"),
  ])("rejects invalid cursor %s", (cursor) => {
    expect(() => decodeCursor(cursor, "asc")).toThrow("cursor is invalid");
  });
});
