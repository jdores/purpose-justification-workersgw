import { randomNonce } from "../lib/crypto.js";
import type { HoldView, Policy, RequestView } from "../types.js";
import { ACTION_HEADER, TOKEN_HEADER } from "../types.js";
import { PAGE_STYLES } from "./styles.js";

export interface RenderedPage {
  html: string;
  nonce: string;
}

export function renderForm(input: {
  host: string;
  requestedUrl: string;
  policy: Policy;
  formToken: string;
}): RenderedPage {
  return renderInteractive({ ...input, request: null, statusToken: null });
}

export function renderPending(input: {
  host: string;
  requestedUrl: string;
  policy: Policy;
  request: RequestView;
  statusToken: string;
}): RenderedPage {
  return renderInteractive({ ...input, formToken: null });
}

function renderInteractive(input: {
  host: string;
  requestedUrl: string;
  policy: Policy;
  formToken: string | null;
  request: RequestView | null;
  statusToken: string | null;
}): RenderedPage {
  const nonce = randomNonce();
  const initial = input.request
    ? {
        statusToken: input.statusToken,
        justification: input.request.justification,
        createdAt: input.request.createdAt,
        expiresAt: input.request.expiresAt,
      }
    : null;
  const help = input.policy.helpUrl
    ? `<a class="button secondary" href="${escapeHtml(input.policy.helpUrl)}">Contact support</a>`
    : "";
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(input.policy.formTitle)}</title><style nonce="${nonce}">${PAGE_STYLES}</style></head><body><main>
  <section class="card" aria-labelledby="form-title" id="form-view"${input.request ? " hidden" : ""}>
    ${corners()}<p class="eyebrow">Access request</p><p class="host">${escapeHtml(input.host)}<br>${escapeHtml(input.requestedUrl)}</p>
    <h1 id="form-title">${escapeHtml(input.policy.formTitle)}</h1><p>${escapeHtml(input.policy.formPrompt)}</p>
    <form id="request-form"><label for="justification">Purpose justification</label><textarea id="justification" name="justification" minlength="20" maxlength="1000" required aria-describedby="count privacy"></textarea><div class="meta"><span>20 character minimum</span><span id="count">0 / 1000</span></div><div id="error" class="error" role="alert" aria-live="polite"></div><div class="actions"><button id="submit" type="submit">Submit justification</button>${help}</div></form>
    <p class="note" id="privacy">Administrators receive your Zero Trust email and name, this host and path, your justification, timestamp, and browser user agent.</p><noscript><p class="error visible">JavaScript is required to submit this request.</p></noscript>
  </section>
  <section class="card" aria-labelledby="wait-title" id="wait-view"${input.request ? "" : " hidden"}>
    ${corners()}<p class="eyebrow">Request submitted</p><p class="host">${escapeHtml(input.host)}</p><h1 id="wait-title">${escapeHtml(input.policy.pendingTitle)}</h1><div class="status"><span class="pulse" aria-hidden="true"></span><span id="status-label">Awaiting administrator decision</span></div><p>${escapeHtml(input.policy.pendingMessage)}</p><div class="reason"><strong>Your justification</strong><p id="submitted-text"></p></div><p id="wait-meta" class="note"></p><div id="wait-error" class="error" role="alert" aria-live="polite"></div><div class="actions"><button type="button" class="secondary" id="check" hidden>Check again</button></div>
  </section>
  <section class="card" aria-labelledby="denied-title" id="denied-view" hidden>${corners()}<p class="eyebrow">Request denied</p><p class="host">${escapeHtml(input.host)}</p><h1 id="denied-title">${escapeHtml(input.policy.blockTitle)}</h1><p>${escapeHtml(input.policy.blockMessage)}</p><div class="reason"><strong>Administrator reason</strong><p id="denied-reason"></p></div><p id="hold-expiry" class="note"></p>${help}</section>
  </main><script nonce="${nonce}">(function(){
  var actionHeader=${scriptJson(ACTION_HEADER)},tokenHeader=${scriptJson(TOKEN_HEADER)},formToken=${scriptJson(input.formToken)},initial=${scriptJson(initial)};
  var form=document.getElementById('request-form'),formView=document.getElementById('form-view'),waitView=document.getElementById('wait-view'),deniedView=document.getElementById('denied-view'),text=document.getElementById('justification'),count=document.getElementById('count'),error=document.getElementById('error'),submit=document.getElementById('submit'),check=document.getElementById('check'),waitError=document.getElementById('wait-error');
  var statusToken=initial&&initial.statusToken,start=Date.now(),timer=null,stopped=false;
  function showError(el,msg){el.textContent=msg;el.classList.add('visible')}
  function showWait(data){formView.hidden=true;waitView.hidden=false;document.getElementById('submitted-text').textContent=data.justification;document.getElementById('wait-meta').textContent='Submitted '+new Date(data.createdAt).toLocaleString()+'; expires '+new Date(data.expiresAt).toLocaleString();statusToken=data.statusToken;start=Date.now();stopped=false;schedule()}
  function interval(){var elapsed=Date.now()-start;if(elapsed<60000)return 5000;if(elapsed<300000)return 10000;if(elapsed<900000)return 20000;return 0}
  function schedule(delay){if(timer)clearTimeout(timer);if(document.hidden)return;var next=delay===undefined?interval():delay;if(!next){stopped=true;check.hidden=false;document.getElementById('status-label').textContent='Still awaiting a decision';return}timer=setTimeout(poll,next)}
  function poll(){if(!statusToken||document.hidden)return;check.disabled=true;fetch(location.href,{method:'GET',headers:(function(){var h={};h[actionHeader]='status';h[tokenHeader]=statusToken;return h})(),credentials:'same-origin'}).then(function(r){return r.json().then(function(data){return {ok:r.ok,data:data}})}).then(function(result){if(!result.ok){if(['invalid_state','identity_required'].includes(result.data.error)){location.reload();return}throw new Error(result.data.message||'Status check failed.')}var data=result.data;waitError.classList.remove('visible');if(data.status==='approved'){document.getElementById('status-label').textContent='Approved. Continuing...';setTimeout(function(){location.reload()},350);return}if(data.status==='denied'){waitView.hidden=true;deniedView.hidden=false;document.getElementById('denied-reason').textContent=data.reason;document.getElementById('hold-expiry').textContent='You may request access again after '+new Date(data.holdExpiresAt).toLocaleString();return}if(data.status==='expired'){document.getElementById('status-label').textContent='Request expired';check.textContent='Start a new request';check.hidden=false;check.onclick=function(){location.reload()};return}schedule()}).catch(function(e){showError(waitError,e.message||'Unable to check status.');schedule(20000)}).finally(function(){check.disabled=false})}
  if(text)text.addEventListener('input',function(){count.textContent=Array.from(text.value).length+' / 1000'});
  if(form)form.addEventListener('submit',function(event){event.preventDefault();var justification=text.value.trim(),length=Array.from(justification).length;if(length<20||length>1000){showError(error,'Justification must be 20-1000 characters.');return}submit.disabled=true;submit.textContent='Submitting...';error.classList.remove('visible');fetch(location.href,{method:'POST',headers:(function(){var h={'content-type':'application/json'};h[actionHeader]='submit';h[tokenHeader]=formToken;return h})(),body:JSON.stringify({justification:justification}),credentials:'same-origin'}).then(function(r){return r.json().then(function(data){return {ok:r.ok,data:data}})}).then(function(result){if(!result.ok){if(['invalid_state','config_changed','already_granted','denied','identity_required'].includes(result.data.error)){location.reload();return}throw new Error(result.data.message||'Submission failed.')}if(result.data.existing){location.reload();return}showWait({statusToken:result.data.statusToken,justification:justification,createdAt:result.data.request.createdAt,expiresAt:result.data.request.expiresAt})}).catch(function(e){showError(error,e.message||'Submission failed.');submit.disabled=false;submit.textContent='Submit justification'})});
  check.addEventListener('click',function(){if(stopped)poll()});document.addEventListener('visibilitychange',function(){if(!document.hidden&&statusToken){poll()}});if(initial){showWait(initial)}
  })();</script></body></html>`;
  return { html, nonce };
}

export function renderDenied(input: { host: string; policy: Policy; hold: HoldView }): RenderedPage {
  const nonce = randomNonce();
  const help = input.policy.helpUrl
    ? `<a class="button secondary" href="${escapeHtml(input.policy.helpUrl)}">Contact support</a>`
    : "";
  return {
    nonce,
    html: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(input.policy.blockTitle)}</title><style nonce="${nonce}">${PAGE_STYLES}</style></head><body><main><section class="card" aria-labelledby="title">${corners()}<p class="eyebrow">Request denied</p><p class="host">${escapeHtml(input.host)}</p><h1 id="title">${escapeHtml(input.policy.blockTitle)}</h1><p>${escapeHtml(input.policy.blockMessage)}</p><div class="reason"><strong>Administrator reason</strong><p>${escapeHtml(input.hold.reason)}</p></div><p class="note">You may request access again after ${escapeHtml(new Date(input.hold.expiresAt).toLocaleString("en-US", { timeZone: "UTC", timeZoneName: "short" }))}.</p><div class="actions">${help}<button type="button" id="check-again">Check again</button></div></section></main><script nonce="${nonce}">document.getElementById('check-again').addEventListener('click',function(){location.reload()});</script></body></html>`,
  };
}

export function renderIdentityRequired(input: { host: string }): RenderedPage {
  const nonce = randomNonce();
  return {
    nonce,
    html: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign-in required</title><style nonce="${nonce}">${PAGE_STYLES}</style></head><body><main><section class="card" aria-labelledby="title">${corners()}<p class="eyebrow">Identity required</p><p class="host">${escapeHtml(input.host)}</p><h1 id="title">Sign-in required</h1><p>Access to this site requires a signed-in Cloudflare Zero Trust session so an administrator can review your request. Sign in to your organization's Cloudflare device client, then try again.</p><div class="actions"><button type="button" id="retry">Try again</button></div></section></main><script nonce="${nonce}">document.getElementById('retry').addEventListener('click',function(){location.reload()});</script></body></html>`,
  };
}

export function renderUnavailable(): RenderedPage {
  const nonce = randomNonce();
  return {
    nonce,
    html: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access check unavailable</title><style nonce="${nonce}">${PAGE_STYLES}</style></head><body><main><section class="card">${corners()}<p class="eyebrow">Temporary issue</p><h1>Access check unavailable</h1><p>We could not verify whether this destination is approved, so access remains closed. Please retry shortly.</p><div class="actions"><button type="button" id="retry">Retry</button></div></section></main><script nonce="${nonce}">document.getElementById('retry').addEventListener('click',function(){location.reload()});</script></body></html>`,
  };
}

function corners(): string {
  return '<i class="corner tl" aria-hidden="true"></i><i class="corner tr" aria-hidden="true"></i><i class="corner bl" aria-hidden="true"></i><i class="corner br" aria-hidden="true"></i>';
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function scriptJson(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}
