const express = require('express');
const { ProxyAgent, fetch } = require('undici');

const app = express();
app.use(express.raw({ limit: '10mb', type: '*/*' }));

const RELAY_TOKEN = process.env.RELAY_TOKEN || '';
const QUOTAGUARD_PROXY_URL = process.env.QUOTAGUARD_PROXY_URL || '';
const ALLOWED_TARGET_HOSTS = (process.env.ALLOWED_TARGET_HOSTS || '')
  .split(',')
  .map((h) => h.trim().toLowerCase())
  .filter(Boolean);

function isHostAllowed(hostname) {
  const h = hostname.toLowerCase();
  return ALLOWED_TARGET_HOSTS.some((a) => h === a || h.endsWith('.' + a));
}

app.all('/api/relay', async (req, res) => {
  try {
    // 1. Valida o token de acesso
    if (!RELAY_TOKEN || req.headers['x-relay-token'] !== RELAY_TOKEN) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    // 2. Pega o destino
    const target = req.headers['x-relay-target'];
    if (!target) {
      return res.status(400).json({ error: 'missing x-relay-target' });
    }

    // 3. Verifica se o QuotaGuard está configurado
    if (!QUOTAGUARD_PROXY_URL) {
      return res.status(500).json({ error: 'QUOTAGUARD_PROXY_URL not configured' });
    }

    // 4. Valida o destino (segurança anti-SSRF)
    let targetUrl;
    try {
      targetUrl = new URL(target);
    } catch {
      return res.status(400).json({ error: 'invalid target url' });
    }
    if (!['http:', 'https:'].includes(targetUrl.protocol)) {
      return res.status(400).json({ error: 'only http/https targets allowed' });
    }
    if (ALLOWED_TARGET_HOSTS.length === 0) {
      return res.status(403).json({ error: 'ALLOWED_TARGET_HOSTS not configured' });
    }
    if (!isHostAllowed(targetUrl.hostname)) {
      return res.status(403).json({ error: 'target host not allowed: ' + targetUrl.hostname });
    }

    // 5. Copia os headers, descartando os de relay e hop-by-hop
    const forwardHeaders = {};
    const drop = [
      'x-relay-target', 'x-relay-token', 'host', 'content-length',
      'connection', 'transfer-encoding', 'x-forwarded-for',
      'x-forwarded-host', 'x-forwarded-proto', 'x-real-ip',
    ];
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase();
      if (drop.includes(lk) || lk.startsWith('x-relay-')) continue;
      forwardHeaders[k] = v;
    }
    forwardHeaders['host'] = targetUrl.host;

    // 6. Faz a requisição pelo proxy QuotaGuard
    const resp = await fetch(target, {
      method: req.method,
      headers: forwardHeaders,
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : req.body,
      dispatcher: new ProxyAgent(QUOTAGUARD_PROXY_URL),
    });

    // 7. Retorna a resposta
    const buf = Buffer.from(await resp.arrayBuffer());
    res.status(resp.status);
    const ct = resp.headers.get('content-type');
    if (ct) res.setHeader('content-type', ct);
    return res.send(buf);
  } catch (e) {
    console.error('[relay] error', e.message, e.stack);
    return res.status(502).json({ error: e.message });
  }
});

module.exports = app;
