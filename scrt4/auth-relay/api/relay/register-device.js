// POST /api/relay/register-device — store push subscription
// DELETE /api/relay/register-device — remove push subscription
// Proxies to self-hosted GCP Redis relay.

const RELAY_BACKEND_URL = process.env.RELAY_BACKEND_URL;

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!RELAY_BACKEND_URL) {
    return res.status(503).json({ error: 'Relay backend not configured' });
  }

  try {
    const resp = await fetch(`${RELAY_BACKEND_URL}/api/relay/register-device`, {
      method: req.method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body || {}),
      signal: AbortSignal.timeout(10000),
    });
    const data = await resp.json();
    return res.status(resp.status).json(data);
  } catch (err) {
    return res.status(502).json({ error: 'Relay backend unavailable' });
  }
}
