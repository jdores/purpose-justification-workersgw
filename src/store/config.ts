import type { ConfigInput, Policy, PolicyConfig } from "../types.js";
import { canonicalizeHost } from "../lib/host.js";

const POLICY_KIND = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export const DEFAULT_CONFIG: PolicyConfig = {
  version: 1,
  updatedAt: "1970-01-01T00:00:00.000Z",
  defaultGrantSeconds: 3600,
  maxGrantSeconds: 2_592_000,
  denyHoldSeconds: 3600,
  pendingExpirySeconds: 86_400,
  retentionDays: 30,
  submissionLimitPerHour: 20,
  defaultPolicyKind: "generic",
  policies: {
    generic: {
      kind: "generic",
      formTitle: "Tell us why you need access",
      formPrompt:
        "Explain the business purpose for accessing this site. Your request will be reviewed by an administrator.",
      pendingTitle: "Request awaiting review",
      pendingMessage:
        "Your justification was submitted. Keep this page open or return later to check the decision.",
      blockTitle: "Access request denied",
      blockMessage: "An administrator denied access to this site.",
    },
  },
  hostPolicies: {},
};

export function validateConfig(input: unknown): { value?: ConfigInput; errors: string[] } {
  const errors: string[] = [];
  if (!isRecord(input)) return { errors: ["config must be an object"] };

  integer(input.defaultGrantSeconds, 60, 2_592_000, "defaultGrantSeconds", errors);
  integer(input.maxGrantSeconds, 60, 2_592_000, "maxGrantSeconds", errors);
  integer(input.denyHoldSeconds, 60, 2_592_000, "denyHoldSeconds", errors);
  integer(input.pendingExpirySeconds, 300, 604_800, "pendingExpirySeconds", errors);
  integer(input.retentionDays, 1, 365, "retentionDays", errors);
  integer(input.submissionLimitPerHour, 1, 100, "submissionLimitPerHour", errors);

  if (
    typeof input.defaultGrantSeconds === "number" &&
    typeof input.maxGrantSeconds === "number" &&
    input.defaultGrantSeconds > input.maxGrantSeconds
  ) {
    errors.push("defaultGrantSeconds must not exceed maxGrantSeconds");
  }

  const policies = input.policies;
  if (!isRecord(policies) || Object.keys(policies).length < 1 || Object.keys(policies).length > 50) {
    errors.push("policies must contain between 1 and 50 entries");
  } else {
    for (const [key, value] of Object.entries(policies)) validatePolicy(key, value, errors);
  }

  if (
    typeof input.defaultPolicyKind !== "string" ||
    !isRecord(policies) ||
    !Object.hasOwn(policies, input.defaultPolicyKind)
  ) {
    errors.push("defaultPolicyKind must reference an existing policy");
  }

  const hostPolicies = input.hostPolicies;
  if (!isRecord(hostPolicies)) {
    errors.push("hostPolicies must be an object");
  } else if (Object.keys(hostPolicies).length > 500) {
    errors.push("hostPolicies must contain no more than 500 entries");
  } else {
    for (const [host, kind] of Object.entries(hostPolicies)) {
      if (normalizeConfiguredHost(host) !== host) {
        errors.push(`hostPolicies key "${host}" must be a normalized hostname`);
      }
      if (typeof kind !== "string" || !isRecord(policies) || !Object.hasOwn(policies, kind)) {
        errors.push(`hostPolicies["${host}"] must reference an existing policy`);
      }
    }
  }

  if (errors.length) return { errors };

  const value: ConfigInput = {
    defaultGrantSeconds: input.defaultGrantSeconds as number,
    maxGrantSeconds: input.maxGrantSeconds as number,
    denyHoldSeconds: input.denyHoldSeconds as number,
    pendingExpirySeconds: input.pendingExpirySeconds as number,
    retentionDays: input.retentionDays as number,
    submissionLimitPerHour: input.submissionLimitPerHour as number,
    defaultPolicyKind: input.defaultPolicyKind as string,
    policies: policies as Record<string, Policy>,
    hostPolicies: hostPolicies as Record<string, string>,
  };
  return { value, errors };
}

export function resolvePolicy(config: PolicyConfig, host: string): Policy {
  let candidate = host;
  while (candidate) {
    const kind = config.hostPolicies[candidate];
    if (kind && Object.hasOwn(config.policies, kind)) return config.policies[kind]!;
    if (!candidate.includes(".")) break;
    const firstDot = candidate.indexOf(".");
    const parent = candidate.slice(firstDot + 1);
    if (!parent.includes(".")) break;
    candidate = parent;
  }
  return Object.hasOwn(config.policies, config.defaultPolicyKind)
    ? config.policies[config.defaultPolicyKind]!
    : DEFAULT_CONFIG.policies.generic!;
}

export function normalizeConfiguredHost(value: string): string | null {
  if (!value || value.length > 253 || value.includes("*") || value.includes("/")) return null;
  const normalized = canonicalizeHost(value);
  return normalized === value ? normalized : null;
}

function validatePolicy(key: string, value: unknown, errors: string[]): void {
  if (!POLICY_KIND.test(key)) {
    errors.push(`policies key "${key}" must match [a-z0-9][a-z0-9_-]{0,63}`);
  }
  if (!isRecord(value)) {
    errors.push(`policies.${key} must be an object`);
    return;
  }
  if (value.kind !== key) errors.push(`policies.${key}.kind must equal "${key}"`);
  stringRange(value.formTitle, 1, 200, `policies.${key}.formTitle`, errors);
  stringRange(value.formPrompt, 1, 1000, `policies.${key}.formPrompt`, errors);
  stringRange(value.pendingTitle, 1, 200, `policies.${key}.pendingTitle`, errors);
  stringRange(value.pendingMessage, 1, 1000, `policies.${key}.pendingMessage`, errors);
  stringRange(value.blockTitle, 1, 200, `policies.${key}.blockTitle`, errors);
  stringRange(value.blockMessage, 1, 1000, `policies.${key}.blockMessage`, errors);
  if (value.helpUrl !== undefined) {
    if (typeof value.helpUrl !== "string" || !isHttpUrl(value.helpUrl)) {
      errors.push(`policies.${key}.helpUrl must be an absolute http(s) URL`);
    }
  }
}

function integer(value: unknown, min: number, max: number, name: string, errors: string[]): void {
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) {
    errors.push(`${name} must be an integer between ${min} and ${max}`);
  }
}

function stringRange(value: unknown, min: number, max: number, name: string, errors: string[]): void {
  if (typeof value !== "string" || [...value].length < min || [...value].length > max) {
    errors.push(`${name} must be ${min}-${max} characters`);
  }
}

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
