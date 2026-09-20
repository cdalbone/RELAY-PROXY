const { ProxyAgent, fetch } = require('undici');

const RELAY_TOKEN = process.env.RELAY_TOKEN || '';
const QUOTAGUARD_PROXY_URL = process.env.QUOTAGUARD_PROXY_URL || '';
const ALLOWED_TARGET_HOSTS = (process.env.ALLOWED_TARGET_HOSTS || '')
  .split(',')
  .map((h) => h.trim().toLowerCase())
  .filter(Boolean);

function isHostAllowed(hostname) {
  const h = hostname.toLowerCase();
  return ALLOWED_TARGET_HOSTS.some((allowed) => h === allowed || h.endsWith('.' + allowed));
}

export default async function handler(req, res) {
  try {
    if (!RELAY_TOKEN || req.headers['x-relay-token'] !== RELAY_TOKEN) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    const target = req.headers['x-relay-target'];
    if (!target) {
      return res.status(400).json({ error: 'missing x-relay-target' });
    }
    if (!QUOTAGUARD_PROXY_URL) {
      return res.status(500).json({ error: 'QUOTAGUARD_PROXY_URL not configured on relay' });
    }

    let targetUrl;
    try {
      targetUrl = new URL(target);
    } catch {
      return res.status(400).json({ error: 'invalid x-relay-target url' });
    }
    if (!['http:', 'https:'].includes(targetUrl.protocol)) {
      return res.status(400).json({ error: 'only http/https targets allowed' });
    }
    if (ALLOWED_TARGET_HOSTS.length === 0) {
      return res.status(403).json({ error: 'ALLOWED_TARGET_HOSTS not configured on relay' });
    }
    if (!isHostAllowed(targetUrl.hostname)) {
      return res.status(403).json({ error: 'target host not allowed: ' + targetUrl.hostname });
    }

    const forwardHeaders = {};
    const drop = ['x-relay-target', 'x-relay-token', 'host', 'content-length', 'connection', 'transfer-encoding', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-real-ip'];
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase();
      if (drop.includes(lk) || lk.startsWith('x-relay-')) continue;
      forwardHeaders[k] = v;
    }
    forwardHeaders['host'] = targetUrl.host;

    const resp = await fetch(target, {
      method: req.method,
      headers: forwardHeaders,
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : req.body,
      dispatcher: new ProxyAgent(QUOTAGUARD_PROXY_URL),
    });
    const buf = Buffer.from(await resp.arrayBuffer());
    res.status(resp.statusCode);
    const ct = resp.headers.get('content-type');
    if (ct) res.setHeader('content-type', ct);
    return res.send(buf);
  } catch (e) {
    console.error('[relay] error', e.message);
    return res.status(502).json({ error: e.message });
  }
}
