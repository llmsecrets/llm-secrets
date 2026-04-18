// GET /api/relay/resolve/:code — resolve short code to session ID
// Proxies to self-hosted GCP Redis relay.

const RELAY_BACKEND_URL = process.env.RELAY_BACKEND_URL;

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  if (!RELAY_BACKEND_URL) {
    return res.status(503).json({ error: 'Relay backend not configured' });
  }

  const { code } = req.query;
  if (!code || code.length < 3 || code.length > 8) {
    return res.status(400).json({ error: 'Invalid code' });
  }

  try {
    const resp = await fetch(`${RELAY_BACKEND_URL}/api/relay/resolve/${code}`, {
      signal: AbortSignal.timeout(10000),
    });
    const data = await resp.json();
    return res.status(resp.status).json(data);
  } catch (err) {
    return res.status(502).json({ error: 'Relay backend unavailable' });
  }
}
