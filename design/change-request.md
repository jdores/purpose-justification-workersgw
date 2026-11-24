# Change Requests

> **Instructions for the LLM:** When processing this file, implement each outstanding change request in order. For each one:
> 1. Ask clarifying questions if anything is ambiguous — do not assume.
> 2. Check `design/references/` for any supporting context (images, logs, screenshots) mentioned in the request.
> 3. Check `design/assets/` for any app files (images, fonts, static files) that need to be integrated into the project. Always keep the originals in `design/assets/`.
> 4. Implement the code changes in `src/`.
> 5. Update `design/prd.md` to reflect the change.
> 6. Move the completed request from **Outstanding** to **Finalized** below, assigning it the next sequential `CR-NNN` number (based on the highest existing number in **Finalized**; start at `CR-001` if none exist).
> 7. Update `README.md` to reflect the current state of the project.
>
> **Numbering:** Change requests in **Outstanding** are unnumbered. Numbers are assigned only when a request is moved to **Finalized**. This prevents misnumbering when multiple requests are added concurrently.

---

## Outstanding

<!-- Add change requests here using the format below (do NOT include a CR number):

### Short title
**Priority:** P0 / P1 / P2
**Description:** What needs to change and why.
**References:** (optional) List any files in design/references/ that provide context.
**Assets:** (optional) List any files in design/assets/ to integrate into the project.
**Acceptance criteria:**
- [ ] Criterion 1
- [ ] Criterion 2

-->

---

## Finalized

<!-- Completed change requests are moved here by the LLM after implementation. -->

### CR-001 - Implement the PRD

**Completed:** 2026-08-28

Implemented the approved purpose-justification Gateway Worker, including the Gateway middleware, SQLite-backed `GateStore`, signed user workflow, Access-protected admin surface, live updates, expiry and retention, observability, deployment configuration, tests, hardening, and operator documentation. Automated release checks pass. The Worker, migration, custom domain, and signing secret are deployed, and unauthenticated admin routes redirect to Access; remaining Gateway activation steps are explicitly documented for operators.

### CR-002 - Remove IP-based limitation copy from the Worker UI

**Completed:** 2026-09-18

Removed the user-facing references to the IP-based (shared-egress) limitation from the deployed Worker. Deleted the "Shared egress IPs share request, grant, and denial state." warning from the end-user form, wait, denied, and service-unavailable pages (`src/pages/render.ts`) and the "IP-based identity" banner plus its per-request-card repetition in the admin console (`src/admin/ui.ts`), and removed the now-unused `.notice` CSS. Reworded the end-user form privacy note to omit "your source IP" while keeping the host, path, justification, timestamp, user-agent, and bodyless-GET disclosures. The admin console still shows the source IP as the request identity. Updated the affected tests (`tests/pages.test.ts`, `tests/admin.test.ts`) to assert the copy is absent, and kept the limitation documented in `README.md` and `design/prd.md` per request. Re-verified with `npm run typecheck` (passed) and `npm run coverage` (154 tests passed across 7 files; 96.69% statements, 95.56% branches). Deployed to `<your-custom-domain>` on 2026-09-18 (Wrangler updated to 4.135.0 per repo policy; Version ID `7f3e9e1f-ea7e-4718-ad6f-1d71f3f64a82`).

### CR-003 - Switch to Gateway user identity and the Forward action

**Completed:** 2026-11-19

Adopted the public-beta Gateway **Forward** contract (2026-10-15). Identity now comes from `await context.identity()`: requests, grants, denial holds, rate limits, and signed tokens are keyed on the lowercased user email (`identity_kind = 'email'`), and the Gateway display name is stored as `identity_name` for the admin console. Sessions without an identified email get a new `403` sign-in required page (or `403 identity_required` JSON for submit/status), and identity lookup failures fail closed with `503` (`identity_unavailable`); there is no source-IP fallback. Gateway context types now come from `@cloudflare/zt-types` (camelCase fields, replacing the stale `src_ip` shape). `next()` is now called at most once and only on pass-through paths (auth bypass, non-navigation, active grant); every synthetic response — form, wait, denial, sign-in, submit/status JSON, protocol errors, and fail-closed `503` — is returned without contacting the origin, which removes the sanitized origin GET and the ~66 origin requests per 15-minute wait. `HEAD` synthetic responses omit the body. A one-time, transactional GateStore schema v2 migration (`schema_meta`) purges all IP-keyed requests, grants, and holds, adds `requests.identity_name`, and logs `pj_schema_migrated` with purge counts. Docs were renamed from "Custom" to "Forward", gained the Workers-subdomain prerequisite, and dropped the shared-IP and origin-poll-cost limitations. Wrangler was updated to 4.165.0 and `worker-configuration.d.ts` regenerated. Verified with `npm run typecheck` (passed), `npm run coverage` (169 tests across 7 files; 96.96% statements, 95.37% branches), `wrangler types --check` (current), and `npm run dry-run` (115.54 KiB, 27.36 KiB gzip). Deployed to `<your-custom-domain>` on 2026-11-19 (Version ID `85aff386-6ccc-47d4-a214-42cda34b42f0`); unauthenticated `/health` and `/api/config` return the Cloudflare Access redirect. The Gateway policy must be recreated or confirmed with the `Forward` action, and test users must be signed in to the device client.

### CR-004 - Derive the admin origin from the request and refresh the README

**Completed:** 2026-11-24

Removed the hardcoded admin origin (the deployment's real custom domain) from `src/admin/router.ts`. Admin mutations and the `/ws` upgrade now require an `Origin` equal to the request URL's own origin, and the console CSP `connect-src` is built from the current host (`wss:` for HTTPS, `ws:` otherwise), so the console works on any admin hostname and fully under `wrangler dev`. Tests now use a generic hostname, add local-origin and cross-origin (scheme, port, host, `null`) cases, and assert no personal hostname appears in the console. Applied all README review findings: added the requested disclaimer at the top, a "How it works" section, Wrangler login/whoami, Worker ID lookup via the List Workers API, identity-selector policy scoping, a troubleshooting table of `x-gw-*` headers, a license section, and a stable Testing section; removed the personal hostname, CR jargon, and stale-prone verification numbers; and marked the Gateway logging behavior for Worker-generated denial pages as undocumented and unverified. Updated Wrangler to 4.168.0 and regenerated `worker-configuration.d.ts`. Verified with `npm run typecheck`, `npm run coverage` (170 tests; 96.96% statements, 95.37% branches), `wrangler types --check`, `npm run dry-run` (115.51 KiB, 27.35 KiB gzip), and a local `wrangler dev` origin check. Deployed on 2026-11-24 (Version ID `93a8cc86-b663-4c8b-8001-6f2daa93b763`); unauthenticated `/health` and `/api/config` return the Cloudflare Access redirect.
