// GET /s/:code — resolve short code and redirect to auth.html
// Server-side redirect: /s/k7x9 → 302 → /auth.html?s=SESSION_ID

const RELAY_BACKEND_URL = process.env.RELAY_BACKEND_URL;

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  if (!RELAY_BACKEND_URL) {
    return res.status(503).send('Relay backend not configured');
  }

  const { code } = req.query;
  if (!code || code.length < 3 || code.length > 8) {
    return res.status(400).send('Invalid code');
  }

  try {
    const resp = await fetch(`${RELAY_BACKEND_URL}/api/relay/resolve/${code}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!resp.ok) {
      return res.status(404).send('Link expired or invalid. Scan the QR code again.');
    }
    const data = await resp.json();
    const sessionId = data.session_id;
    if (!sessionId) {
      return res.status(404).send('Link expired or invalid. Scan the QR code again.');
    }
    const redirectUrl = `/auth.html?s=${sessionId}&_=${Date.now()}`;
    return res.redirect(302, redirectUrl);
  } catch (err) {
    return res.status(502).send('Relay backend unavailable. Try again.');
  }
}
