export const WORKER_NAME = "purpose-justification-workersgw";
export const STORE_INSTANCE = "global";
export const ACTION_HEADER = "x-gw-pj-action";
export const TOKEN_HEADER = "x-gw-pj-token";
export const FORM_TOKEN_TTL_SECONDS = 600;

export const MAX_EMAIL_LENGTH = 254;
export const MAX_IDENTITY_NAME_LENGTH = 200;

export type IdentityKind = "email";
export type RequestStatus = "pending" | "approved" | "denied" | "expired";
export type GrantStatus = "active" | "expired" | "revoked";
export type HoldStatus = "active" | "expired" | "cleared";

export type {
  GatewayIdentity,
  GatewayMiddlewareContext as GatewayContext,
  GatewayMiddlewareNext as NextFn,
} from "@cloudflare/zt-types";

export interface Policy {
  kind: string;
  formTitle: string;
  formPrompt: string;
  pendingTitle: string;
  pendingMessage: string;
  blockTitle: string;
  blockMessage: string;
  helpUrl?: string;
}

export interface PolicyConfig {
  version: number;
  updatedAt: string;
  defaultGrantSeconds: number;
  maxGrantSeconds: number;
  denyHoldSeconds: number;
  pendingExpirySeconds: number;
  retentionDays: number;
  submissionLimitPerHour: number;
  defaultPolicyKind: string;
  policies: Record<string, Policy>;
  hostPolicies: Record<string, string>;
}

export type ConfigInput = Omit<PolicyConfig, "version" | "updatedAt"> &
  Partial<Pick<PolicyConfig, "version" | "updatedAt">>;

export interface Actor {
  value: string;
  source: "access-header" | "unknown";
}

export interface RequestView {
  id: string;
  status: RequestStatus;
  identityKind: IdentityKind;
  identity: string;
  identityName: string | null;
  host: string;
  requestedUrl: string;
  justification: string;
  policyKind: string;
  createdAt: string;
  expiresAt: string;
  decidedAt: string | null;
  decidedBy: string | null;
  decidedBySource: Actor["source"] | null;
  decisionReason: string | null;
  grantSeconds: number | null;
  userAgent: string | null;
  configVersion: number;
  grant: GrantView | null;
  hold: HoldView | null;
}

export interface GrantView {
  id: string;
  requestId: string;
  identityKind: IdentityKind;
  identity: string;
  host: string;
  status: GrantStatus;
  grantedAt: string;
  expiresAt: string;
  grantedBy: string;
  grantedBySource: Actor["source"];
  revokedAt: string | null;
  revokedBy: string | null;
  revokedBySource: Actor["source"] | null;
}

export interface HoldView {
  id: string;
  requestId: string;
  identityKind: IdentityKind;
  identity: string;
  host: string;
  status: HoldStatus;
  reason: string;
  deniedAt: string;
  expiresAt: string;
  deniedBy: string;
  deniedBySource: Actor["source"];
  clearedAt: string | null;
  clearedBy: string | null;
  clearedBySource: Actor["source"] | null;
}

export interface EvaluateInput {
  identityKind: IdentityKind;
  identity: string;
  host: string;
}

export type EvaluateResult =
  | { state: "granted"; grant: GrantView; config: PolicyConfig; policy: Policy }
  | { state: "denied"; hold: HoldView; config: PolicyConfig; policy: Policy }
  | { state: "pending"; request: RequestView; config: PolicyConfig; policy: Policy }
  | { state: "none"; config: PolicyConfig; policy: Policy };

export interface SubmitInput extends EvaluateInput {
  identityName: string | null;
  submissionNonce: string;
  requestedUrl: string;
  justification: string;
  policyKind: string;
  configVersion: number;
  userAgent: string;
}

export type SubmitResult =
  | { state: "created" | "existing"; request: RequestView }
  | { state: "granted"; grant: GrantView }
  | { state: "denied"; hold: HoldView }
  | { state: "rate_limited"; retryAfterSeconds: number }
  | { state: "config_changed" }
  | { state: "invalid" };

export interface StatusInput extends EvaluateInput {
  requestId: string;
}

export type StatusResult =
  | { state: "pending"; request: RequestView }
  | { state: "approved"; requestId: string; grant: GrantView }
  | { state: "denied"; requestId: string; hold: HoldView }
  | { state: "expired"; requestId: string }
  | { state: "invalid" };

export interface ListInput {
  status?: string;
  host?: string;
  cursor?: string;
  limit?: number;
}

export interface ListResult<T> {
  entries: T[];
  cursor: string | null;
  listComplete: boolean;
}

export type StoreResult<T> =
  | { ok: true; value: T }
  | {
      ok: false;
      code:
        | "not_found"
        | "already_decided"
        | "request_expired"
        | "not_active"
        | "validation_failed";
      message: string;
      details?: string[];
    };

export interface FormTokenPayload {
  type: "form";
  identityKind: IdentityKind;
  identity: string;
  host: string;
  policyKind: string;
  configVersion: number;
  requestedUrl: string;
  iat: number;
  exp: number;
  nonce: string;
}

export interface StatusTokenPayload {
  type: "status";
  requestId: string;
  identityKind: IdentityKind;
  identity: string;
  host: string;
  iat: number;
  exp: number;
}

export type BrowserTokenPayload = FormTokenPayload | StatusTokenPayload;
