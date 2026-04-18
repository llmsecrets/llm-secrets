// GET /api/relay/vapid-public-key — return VAPID public key
// Proxies to self-hosted GCP Redis relay.

const RELAY_BACKEND_URL = process.env.RELAY_BACKEND_URL;

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  if (!RELAY_BACKEND_URL) {
    return res.status(503).json({ error: 'Relay backend not configured' });
  }

  try {
    const resp = await fetch(`${RELAY_BACKEND_URL}/api/relay/vapid-public-key`, {
      signal: AbortSignal.timeout(10000),
    });
    const data = await resp.json();
    return res.status(resp.status).json(data);
  } catch (err) {
    return res.status(502).json({ error: 'Relay backend unavailable' });
  }
}
