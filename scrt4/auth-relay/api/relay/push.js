// POST /api/relay/push — send push notification to registered devices
// Proxies to self-hosted GCP Redis relay.

const RELAY_BACKEND_URL = process.env.RELAY_BACKEND_URL;

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!RELAY_BACKEND_URL) {
    return res.status(503).json({ error: 'Relay backend not configured' });
  }

  const { session_id, auth_url } = req.body || {};
  if (!session_id || !auth_url) {
    return res.status(400).json({ error: 'Missing session_id or auth_url' });
  }

  try {
    const resp = await fetch(`${RELAY_BACKEND_URL}/api/relay/push`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id, auth_url }),
      signal: AbortSignal.timeout(10000),
    });
    const data = await resp.json();
    return res.status(resp.status).json(data);
  } catch (err) {
    return res.status(502).json({ error: 'Relay backend unavailable' });
  }
}
