// Relay API: temporary encrypted blob storage
// POST /api/relay/:id — store encrypted payload (from phone)
// GET  /api/relay/:id — retrieve and delete (from daemon)
//
// Proxies to self-hosted GCP Redis relay. Blobs auto-expire after 2 minutes.
// The relay never sees plaintext — payload is encrypted end-to-end.

const RELAY_BACKEND_URL = process.env.RELAY_BACKEND_URL; // e.g. http://34.48.219.138:4100

export default async function handler(req, res) {
  const { id } = req.query;
  if (!id || id.length < 16) {
    return res.status(400).json({ error: "Invalid session ID" });
  }

  if (req.method === "OPTIONS") return res.status(200).end();

  if (!RELAY_BACKEND_URL) {
    return res.status(503).json({ error: "Relay backend not configured" });
  }

  try {
    const upstream = `${RELAY_BACKEND_URL}/api/relay/${id}`;
    const opts = { signal: AbortSignal.timeout(10000) };

    if (req.method === "POST") {
      const { payload } = req.body || {};
      if (!payload || typeof payload !== "string") {
        return res.status(400).json({ error: "Missing payload" });
      }
      if (payload.length > 10_000) {
        return res.status(400).json({ error: "Payload too large" });
      }
      const resp = await fetch(upstream, {
        ...opts,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload }),
      });
      const data = await resp.json();
      return res.status(resp.status).json(data);
    }

    if (req.method === "GET") {
      const resp = await fetch(upstream, opts);
      const data = await resp.json();
      return res.status(resp.status).json(data);
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(502).json({ error: "Relay backend unavailable" });
  }
}
