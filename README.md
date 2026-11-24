> **Disclaimer**
>
> THIS SOFTWARE IS PROVIDED BY CLOUDFLARE "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
> INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
> A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CLOUDFLARE BE LIABLE FOR ANY DIRECT,
> INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES  (INCLUDING, BUT NOT
> LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
> BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
> STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
> USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Purpose Justification Gateway Worker

`purpose-justification-workersgw` is a proof of concept for the Cloudflare Gateway **Forward** action (public beta), which runs a Worker on HTTP traffic that Gateway permits. It intercepts selected top-level browser navigations, asks the signed-in Zero Trust user why they need the site, and lets that user through to the site only after an administrator approves a time-limited grant.

The same Worker serves an admin console on a custom hostname that you protect with Cloudflare Access.

## How it works

1. A signed-in user on a Gateway-enrolled device opens a site matched by your Forward policy.
2. Instead of the site, they see a form asking for a business justification (20–1,000 characters).
3. After submitting, they see a waiting page that checks for a decision automatically.
4. An administrator reviews the request in the admin console and approves it for a chosen duration or denies it with a reason.
5. **Approved:** the waiting page reloads and the user reaches the site until the grant expires.
   **Denied:** the user sees the reason and cannot ask again until the denial hold expires.
6. If the user is not signed in to the Cloudflare device client, they see a **Sign-in required** page instead of the form.

Access is granted per user (email) and per host. A grant for `example.com` also covers `www.example.com`, but not `app.example.com`.

## Architecture

- `GatewayMiddleware` is the named Gateway Forward entrypoint. It identifies the user with `await context.identity()` and calls Gateway's `next()` at most once — only for authentication paths, non-navigation traffic, and approved access. Gateway types come from `@cloudflare/zt-types`.
- `GateStore` is one SQLite-backed Durable Object named `global`. It owns configuration, requests, grants, denial holds, expiry, retention, and admin WebSockets.
- The default HTTP entrypoint serves the admin UI, JSON API, health route, and WebSocket proxy.
- Signed browser state uses HMAC-SHA256 with the `STATE_SIGNING_SECRET` Worker secret.
- Form, waiting, denial, sign-in, status-check, and error responses are produced by the Worker without contacting the destination site, using controlled security headers. The user's justification is never forwarded.

## Requirements

- Node.js 22 or newer (`.nvmrc` specifies 22)
- A Cloudflare account with Workers (including a configured Workers subdomain), Durable Objects, Access, and Gateway with the Forward action (public beta on all Zero Trust plans)
- Gateway-enrolled devices with a signed-in user, traffic forwarding, and TLS decryption configured
- A custom hostname on a zone in the account for the Access-protected admin console

## Local Development

```bash
nvm use
npm ci
```

Add a random signing secret to the ignored `.dev.vars` file:

```text
STATE_SIGNING_SECRET=<random-secret>
```

Start the local admin console and Durable Object:

```bash
npm run dev
```

The console at `http://localhost:8787` is fully usable locally, including approve, deny, settings, and live updates; the admin origin is derived from the request host. Gateway middleware behavior cannot be exercised with a normal browser request to `wrangler dev`; it is covered by the workerd test suite.

## Commands

| Command | Purpose |
|---|---|
| `npm run dev` | Start local Wrangler development |
| `npm test` | Run the workerd test suite |
| `npm run coverage` | Run tests with enforced coverage thresholds |
| `npm run typecheck` | Run strict TypeScript checks |
| `npm run cf-typegen` | Regenerate `worker-configuration.d.ts` |
| `npm run dry-run` | Build and validate a deployment without uploading it |
| `npm run deploy` | Deploy the Worker and Durable Object migration |

## Deployment

`wrangler.toml` in the repository contains placeholders. Before deploying, set:

- `account_id` to your Cloudflare account ID (replacing `<your-account-id>`). Find it with `npx wrangler whoami`, or in the Cloudflare dashboard under **Account home** → your account → **Copy account ID**.
- `routes[0].pattern` to your admin hostname (replacing `<your-custom-domain>`), for example `approvals.example.com`. It must be a hostname on a zone in the same account; Wrangler creates the DNS record and certificate for the custom domain on deploy. No other file needs the hostname.

Complete these steps in order:

1. Log in to Wrangler with an account that can deploy Workers, and confirm it shows the intended account:

```bash
npx wrangler login
npx wrangler whoami
```

2. Confirm the account has the Gateway Forward action and a configured Workers subdomain. The Worker itself keeps `workers_dev = false`.
3. Create a Cloudflare Access self-hosted application covering the entire admin hostname, including `/health`, `/api/*`, and `/ws`. Allow only the intended administrator group.
4. Generate and upload the signing secret:

```bash
openssl rand -base64 32 | npx wrangler secret put STATE_SIGNING_SECRET
```

5. Deploy the Worker:

```bash
npm run deploy
```

6. Verify an unauthenticated request to `https://<your-custom-domain>/api/config` redirects to Access instead of returning configuration JSON.
7. Create a Gateway HTTP policy with action **Forward** that selects the `purpose-justification-workersgw` Worker (Cloudflare One → **Traffic controls** → **Firewall policies** → **HTTP**). If you use the API, set `action: "forward"` and `rule_settings.forward.worker_id` to the Worker's 32-character ID, which you can get from the [List Workers](https://developers.cloudflare.com/api/resources/workers/subresources/beta/subresources/workers/methods/list/) API.
8. Scope the policy:
   - Match only the intended destinations.
   - Explicitly exclude the admin hostname so administrators cannot be locked out of the console.
   - Add an identity selector (for example a user group) so only signed-in users reach the Worker; anonymous traffic would otherwise only ever see the sign-in page.
9. Place the rule above any earlier Forward rule that could match first. HTTP Block policies still take precedence over Forward.
10. Confirm TLS decryption, the Cloudflare certificate, device enrollment with user sign-in, and traffic forwarding are active.
11. Confirm `workers.dev` and preview URLs do not expose the default entrypoint.
12. Verify Workers Observability receives structured `pj_*` events.

## Operations

The admin console provides:

- **Pending:** oldest-first review queue with approve and deny actions.
- **History:** filtered request audit history.
- **Active access:** active grants and denial holds with revoke and clear controls.
- **Settings:** durations, retention, request limits, copy profiles, and host mappings.

Approver identity comes from `cf-access-authenticated-user-email` when present. It is best-effort attribution only because this Worker relies on Access as the authentication boundary and does not verify Access JWTs itself.

`GET /health` proves only that the HTTP Worker is reachable. It intentionally does not query `GateStore`. Use admin API behavior and `pj_error` logs to diagnose state-service failures.

Configuration and state are stored in Durable Object SQLite. Alarms perform expiry and retention cleanup, while every authorization read also lazily expires stale records so a delayed alarm cannot extend access.

## Troubleshooting

Every response produced or passed through by the Worker carries `x-gw-worker-name: purpose-justification-workersgw`, a Worker-generated `x-gw-pj-request-id`, and one decision header. Inspect them in the browser's developer tools on a gated page:

| Header | Meaning |
|---|---|
| *(no `x-gw-worker-name`)* | The Worker did not run. Check the Forward policy match, rule order, TLS decryption, and Do Not Inspect policies. |
| `x-gw-auth-skip` | Authentication path; passed through without gating. |
| `x-gw-pj-subresource` | Not a top-level navigation; passed through. |
| `x-gw-pj-granted` | Active grant; `x-gw-pj-grant-until` shows its expiry. |
| `x-gw-pj-form` / `x-gw-pj-pending` / `x-gw-pj-denied` | Form, waiting page, or denial page was shown. |
| `x-gw-pj-identity-required` | Gateway returned no identified user; the device client is not signed in. |
| `x-gw-pj-error` | Fail-closed `503`. Check `pj_error` events in Workers Observability for the `reason` (for example `missing_signing_secret` or `identity_unavailable`). |

If the admin console returns `403 invalid_origin` for every change, make sure you are using the console on the same hostname it was loaded from; requests from other origins are rejected by design.

## Data and Security

- Identity is the lowercased email from the Gateway-provided `context.identity()`; the display name is stored for the admin console only. Request headers and source IPs are never used as identity.
- Sessions without an identified email receive a `403` sign-in required page; identity lookup failures fail closed with `503`.
- Persisted URLs contain only origin and path. Query strings and fragments are removed.
- Stored request data includes user email and display name, normalized host, sanitized URL, justification, timestamp, user agent, and decision history. Logs never contain the user email or name.
- Tokens, signing secrets, CSP nonces, destination cookies, request bodies, and origin responses are not persisted or logged.
- Admin changes and WebSocket upgrades require an `Origin` header equal to the console's own origin.
- Configuration, identity, state, signing, SQL, and rendering failures fail closed.
- The storage schema is versioned. Upgrading from the earlier source-IP version purges all IP-keyed requests, grants, and denial holds once and logs the counts as `pj_schema_migrated`.

## Known Limitations

- Users must be signed in to the Cloudflare device client; anonymous Gateway sessions cannot request access.
- Only top-level browser document navigations are gated. APIs, native applications, `curl`, subresources, and other non-navigation traffic pass through.
- Authentication-related path prefixes intentionally bypass gating.
- A single global Durable Object provides a coherent queue but is a deliberate POC latency and throughput bottleneck.
- How Gateway logs record Worker-generated denial pages is not documented for the Forward action and has not been verified. Treat Worker logs and admin state as the source of truth for what the user was shown.
- The Worker-generated request ID cannot be reliably correlated with Gateway request logs.
- The admin console is public if Access is absent or misconfigured; the application cannot detect that condition reliably.
- Parent host mapping does not bundle a Public Suffix List. Do not configure broad suffixes such as `co.uk`.
- JavaScript is required for user submission because ordinary browser forms cannot set the signed protocol headers.
- The Gateway Forward action is in public beta and its contract may change.

## Testing

The workerd test suite (`npm run coverage`) covers the Gateway middleware paths — including assertions that no synthetic response calls `next()` — identity and sign-in handling, the GateStore state machine, alarms, schema migration, WebSockets, the admin API, tokens, and page escaping. Coverage thresholds of 90% statements and branches are enforced for `src/gateway`, `src/store`, and `src/lib`. Detailed verification results for each change are recorded in `design/prd.md`.

See `design/prd.md` for the complete protocol, API, state machine, and acceptance requirements.

## License

Released under the [MIT License](LICENSE).
