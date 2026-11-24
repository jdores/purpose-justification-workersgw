import { env } from "cloudflare:workers";
import { randomNonce } from "../src/lib/crypto.js";
import type { Actor, EvaluateInput, GatewayContext, GatewayIdentity, SubmitInput } from "../src/types.js";

export const ACTOR: Actor = { value: "admin@example.com", source: "access-header" };
export const USER_EMAIL = "user@example.com";
export const USER_NAME = "Example User";

export function scope(identity = USER_EMAIL, host = "example.com"): EvaluateInput {
  return { identityKind: "email", identity, host };
}

export function submission(overrides: Partial<SubmitInput> = {}): SubmitInput {
  return {
    ...scope(),
    identityName: USER_NAME,
    submissionNonce: randomNonce(),
    requestedUrl: "https://example.com/private",
    justification: "This access is required for a customer support investigation.",
    policyKind: "generic",
    configVersion: 1,
    userAgent: "test-agent",
    ...overrides,
  };
}

export function store(name = crypto.randomUUID()) {
  return env.GATE_STORE.getByName(name);
}

/** Builds a Gateway Forward context. Pass an Error to simulate an identity lookup failure. */
export function gatewayContext(
  identity: GatewayIdentity | null | Error = { email: USER_EMAIL, name: USER_NAME },
  overrides: Partial<GatewayContext> = {},
): GatewayContext {
  return {
    srcIp: "192.0.2.10",
    srcPort: 50000,
    networkProtocol: "tcp",
    host: "example.com",
    uri: "https://example.com/",
    accountId: "0".repeat(32),
    policyId: "00000000-0000-4000-8000-000000000000",
    identity: async () => {
      if (identity instanceof Error) throw identity;
      return identity;
    },
    devicePosture: async () => ({ checks: { passed: [] } }),
    ...overrides,
  };
}
