import { WORKER_NAME } from "../types.js";

export function log(event: string, fields: Record<string, unknown> = {}): void {
  console.log({
    event,
    worker: WORKER_NAME,
    ...fields,
  });
}

export function logError(reason: string, error: unknown, fields: Record<string, unknown> = {}): void {
  console.error({
    event: "pj_error",
    worker: WORKER_NAME,
    reason,
    error_name: error instanceof Error ? error.name : "UnknownError",
    ...fields,
  });
}
