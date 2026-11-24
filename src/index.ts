import { WorkerEntrypoint } from "cloudflare:workers";
import { handleAdmin } from "./admin/router.js";
import { handleGateway } from "./gateway/handler.js";
import { GateStore as GateStoreClass } from "./store/gate-store.js";
import type { GatewayContext, NextFn } from "./types.js";
import { STORE_INSTANCE } from "./types.js";

type RuntimeEnv = Env & { STATE_SIGNING_SECRET?: string };

export class GatewayMiddleware extends WorkerEntrypoint<RuntimeEnv> {
  async handle(request: Request, context: GatewayContext, next: NextFn): Promise<Response> {
    const store = this.env.GATE_STORE.getByName(STORE_INSTANCE) as DurableObjectStub<GateStoreClass>;
    return handleGateway(request, context, next, {
      store,
      signingSecret: this.env.STATE_SIGNING_SECRET,
      waitUntil: (promise) => this.ctx.waitUntil(promise),
    });
  }
}

export class GateStore extends GateStoreClass {}

export default class AdminWorker extends WorkerEntrypoint<RuntimeEnv> {
  override async fetch(request: Request): Promise<Response> {
    const store = this.env.GATE_STORE.getByName(STORE_INSTANCE) as DurableObjectStub<GateStoreClass>;
    return handleAdmin(request, store);
  }
}
