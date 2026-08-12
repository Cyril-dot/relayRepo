/**
 * RushPay relay.
 *
 * A single-file HTTP forwarder. Deploy it somewhere whose outbound IP
 * Cloudflare does not challenge, point RUSHPAY_BASE_URL at it, and AkwaPay
 * reaches RushPay through it with no adapter changes at all.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * WHY THIS EXISTS
 * ─────────────────────────────────────────────────────────────────────────
 *
 * RushPay's API sits behind Cloudflare with a browser challenge enabled on
 * /api/v1/*. Server-to-server calls from Render get HTTP 403 and an HTML
 * body titled "Just a moment..." — a JavaScript challenge no backend can
 * solve. The identical request with the identical key succeeds from a
 * residential connection, which is how we know it is IP reputation and not
 * authentication.
 *
 * That is a misconfiguration on RushPay's side: an API path should never sit
 * behind a browser challenge, because no legitimate integration can pass one.
 * Their support is unavailable until next month, so this is the stopgap.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * THIS IS TEMPORARY, AND IT IS NOT FREE
 * ─────────────────────────────────────────────────────────────────────────
 *
 * Be honest about what you are adding:
 *
 *   - A NEW SINGLE POINT OF FAILURE on the path of every RushPay charge. If
 *     this process is down, RushPay is down for you. The saving grace is
 *     that AkwaPay fails over to another gateway, so deposits still work.
 *   - EXTRA LATENCY, one more network hop per call.
 *   - YOUR API KEY IN FLIGHT through one more machine. Deploy it somewhere
 *     you control. Never use a public/shared proxy for this — a third party
 *     would see every X-API-Key you send.
 *   - NO GUARANTEE. If Cloudflare also challenges the relay's IP, this
 *     changes nothing. Test before relying on it.
 *
 * Delete it the moment RushPay excludes /api/v1/* from the challenge. Leave
 * a calendar reminder; stopgaps that outlive their reason are how systems rot.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * DEPLOY
 * ─────────────────────────────────────────────────────────────────────────
 *
 *   1. Put this file in its own repo/service (Railway, Fly, a VPS — anywhere
 *      whose IPs Cloudflare treats better than your current host's).
 *   2. Set RELAY_TOKEN to a long random string:
 *        node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
 *   3. Start it:  node relay.js
 *   4. Verify:    curl https://your-relay/health
 *   5. On the AkwaPay API service set:
 *        RUSHPAY_BASE_URL=https://your-relay/api/v1
 *        RUSHPAY_RELAY_TOKEN=<the same token>
 *
 * The boot banner will then read "VIA RELAY https://your-relay/api/v1", so
 * nobody has to go digging through env vars to discover this exists.
 */

import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';

const PORT = Number(process.env.PORT ?? 8080);
const UPSTREAM = (process.env.RUSHPAY_UPSTREAM ?? 'https://core.rushpay.cash').replace(/\/+$/, '');
const RELAY_TOKEN = process.env.RELAY_TOKEN ?? '';

/**
 * Browser-shaped headers.
 *
 * Cloudflare's Browser Integrity Check scores the request partly on whether
 * it looks like it came from a browser. This is the difference between the
 * relay working and the relay being a pointless extra hop.
 *
 * If Cloudflare is running a full Managed Challenge rather than BIC, no
 * header set will pass and only the IP reputation of this host matters.
 */
const BROWSER_HEADERS = {
  'user-agent':
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  accept: 'application/json, text/plain, */*',
  'accept-language': 'en-GB,en;q=0.9',
  'sec-fetch-site': 'same-origin',
  'sec-fetch-mode': 'cors',
  'sec-fetch-dest': 'empty',
};

/** Copy only the named headers through, preserving their values exactly. */
function forward(headers, names) {
  const out = {};
  for (const n of names) {
    const v = headers[n];
    if (v !== undefined) out[n] = String(v);
  }
  return out;
}

function safeEqual(a, b) {
  const ab = Buffer.from(a ?? '');
  const bb = Buffer.from(b ?? '');
  // Length check first: timingSafeEqual throws on a mismatch, and the length
  // of a token is not the secret.
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

  if (url.pathname === '/health') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
    return;
  }

  // Only forward the RushPay API surface. An open forwarder is an open proxy,
  // and an open proxy on the public internet is found and abused within hours.
  if (!url.pathname.startsWith('/api/v1/')) {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
    return;
  }

  // Shared-secret gate. Without it, anyone who finds this host can bounce
  // traffic through it — and, worse, watch for X-API-Key headers.
  if (!RELAY_TOKEN || !safeEqual(req.headers['x-relay-token'], RELAY_TOKEN)) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'unauthorized' }));
    return;
  }

  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 256 * 1024) {
      res.writeHead(413, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'payload_too_large' }));
      return;
    }
    chunks.push(c);
  }
  const body = Buffer.concat(chunks);

  const target = `${UPSTREAM}${url.pathname}${url.search}`;
  const started = Date.now();

  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers: {
        ...BROWSER_HEADERS,
        // Forward every auth header RushPay understands, UNTOUCHED. The relay
        // never reads them, never stores them, never logs them.
        //
        // An allowlist rather than a blanket copy, because forwarding the
        // caller's Host, Origin or Cookie headers to a different domain is
        // how a relay becomes a security problem.
        //
        // X-RushPay-Widget-Session is easy to forget and fails confusingly:
        // RushPay replies "X-RushPay-Widget-Session header required" even
        // though the caller sent it, because the relay quietly dropped it.
        // Anything RushPay authenticates with belongs in this list.
        ...forward(req.headers, [
          'x-api-key',
          'x-rushpay-widget-session',
          'authorization',
          'content-type',
          'idempotency-key',
        ]),
      },
      body: req.method === 'GET' || req.method === 'HEAD' ? undefined : body,
      signal: AbortSignal.timeout(20_000),
    });

    const text = await upstream.text();
    const ms = Date.now() - started;

    // Log enough to diagnose, never enough to leak. No key, no phone number,
    // no request body — those belong to the customer, not to this log.
    const challenged = upstream.status === 403 && /just a moment|cf-browser-verification/i.test(text);
    console.log(
      JSON.stringify({
        msg: challenged ? 'UPSTREAM CHALLENGED BY CLOUDFLARE' : 'relayed',
        path: url.pathname,
        status: upstream.status,
        ms,
        ...(challenged
          ? { hint: "this relay's IP is also being challenged — it is not helping, try another host" }
          : {}),
      }),
    );

    res.writeHead(upstream.status, {
      'content-type': upstream.headers.get('content-type') ?? 'application/json',
    });
    res.end(text);
  } catch (err) {
    // Return a shape the adapter can read rather than a bare socket error, so
    // a relay failure is distinguishable from a RushPay failure in the logs.
    console.error(JSON.stringify({ msg: 'relay error', path: url.pathname, error: String(err) }));
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ success: false, message: `relay could not reach RushPay: ${String(err)}` }));
  }
});

server.listen(PORT, () => {
  console.log(`rushpay relay listening on ${PORT} → ${UPSTREAM}`);
  if (!RELAY_TOKEN) {
    // Refuse quietly rather than loudly failing: with no token every request
    // is rejected anyway, but say why, once, at startup.
    console.error('RELAY_TOKEN is not set — every request will be rejected with 401. Set it.');
  }
});
