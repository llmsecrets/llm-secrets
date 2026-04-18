// scrt4 relay server — Redis-backed encrypted blob relay
// Replaces Vercel Edge Config with self-hosted Redis
//
// POST /api/relay/:id — store encrypted payload (from phone or CLI)
// GET  /api/relay/:id — retrieve and delete (from CLI or phone)
// POST /api/relay/shorten — generate short code for a session ID
// GET  /api/relay/resolve/:code — resolve short code to session ID
// POST /api/relay/register-device — register push subscription
// POST /api/relay/push — send push notification to registered devices
// GET  /api/relay/vapid-public-key — return VAPID public key
//
// The relay never sees plaintext — payloads are encrypted end-to-end.

const http = require('http');
const Redis = require('ioredis');
const webpush = require('web-push');

const PORT = process.env.RELAY_PORT || 4100;
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
const TTL_SECONDS = 300;

// VAPID keys for Web Push
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || 'BOhLfR1QO3imbDcJW23KFY1LcLIdLoYdmuruAbxLq7WVmR1CT-gzS0Oup6SC4m2onqIIBj3iOpDD8k1U1IHxst0';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';

if (VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails('mailto:admin@llmsecrets.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
  console.log('Web Push configured with VAPID keys');
} else {
  console.warn('VAPID_PRIVATE_KEY not set — push notifications disabled');
}

// Numeric-only 4-digit codes (0000–9999) for easy manual entry
function generateShortCode() {
  const num = require('crypto').randomInt(0, 10000);
  return String(num).padStart(4, '0');
}

const redis = new Redis(REDIS_URL, {
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => Math.min(times * 100, 3000),
});

redis.on('error', (err) => console.error('Redis error:', err.message));
redis.on('connect', () => console.log('Redis connected'));

// Parse JSON body
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

// CORS headers
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function json(res, status, data) {
  setCors(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

const server = http.createServer(async (req, res) => {
  setCors(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    return res.end();
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;

  try {
    // POST /api/relay/shorten — generate short code
    if (req.method === 'POST' && path === '/api/relay/shorten') {
      const body = await parseBody(req);
      const { session_id } = body;
      if (!session_id || session_id.length < 16) {
        return json(res, 400, { error: 'Invalid session_id' });
      }

      for (let attempt = 0; attempt < 10; attempt++) {
        const code = generateShortCode();
        const key = `short:${code}`;
        const set = await redis.set(key, session_id, 'EX', TTL_SECONDS, 'NX');
        if (set === 'OK') {
          return json(res, 200, { code });
        }
      }
      return json(res, 500, { error: 'Could not generate unique code' });
    }

    // GET /api/relay/resolve/:code — resolve short code
    const resolveMatch = path.match(/^\/api\/relay\/resolve\/([0-9]{4})$/);
    if (req.method === 'GET' && resolveMatch) {
      const code = resolveMatch[1];
      const sessionId = await redis.get(`short:${code}`);
      if (!sessionId) {
        return json(res, 404, { error: 'Code not found or expired' });
      }
      return json(res, 200, { session_id: sessionId });
    }

    // GET /api/relay/vapid-public-key — return VAPID public key
    if (req.method === 'GET' && path === '/api/relay/vapid-public-key') {
      return json(res, 200, { publicKey: VAPID_PUBLIC_KEY });
    }

    // POST /api/relay/register-device — store push subscription
    if (req.method === 'POST' && path === '/api/relay/register-device') {
      const body = await parseBody(req);
      const { subscription, device_name } = body;
      if (!subscription || !subscription.endpoint) {
        return json(res, 400, { error: 'Invalid subscription' });
      }

      const deviceId = require('crypto').randomUUID();
      const record = JSON.stringify({
        id: deviceId,
        subscription,
        device_name: device_name || 'Unknown device',
        registered_at: new Date().toISOString(),
      });
      await redis.hset('push:devices', deviceId, record);
      return json(res, 200, { ok: true, device_id: deviceId });
    }

    // DELETE /api/relay/register-device — remove push subscription
    if (req.method === 'DELETE' && path === '/api/relay/register-device') {
      const body = await parseBody(req);
      const { device_id } = body;
      if (!device_id) {
        return json(res, 400, { error: 'Missing device_id' });
      }
      await redis.hdel('push:devices', device_id);
      return json(res, 200, { ok: true });
    }

    // POST /api/relay/push — send push to all registered devices
    if (req.method === 'POST' && path === '/api/relay/push') {
      if (!VAPID_PRIVATE_KEY) {
        return json(res, 503, { error: 'Push notifications not configured' });
      }

      const body = await parseBody(req);
      const { session_id, auth_url } = body;
      if (!session_id || !auth_url) {
        return json(res, 400, { error: 'Missing session_id or auth_url' });
      }

      const devices = await redis.hgetall('push:devices');
      const deviceEntries = Object.entries(devices);
      if (deviceEntries.length === 0) {
        return json(res, 200, { sent: 0, message: 'No registered devices' });
      }

      const payload = JSON.stringify({
        title: 'scrt4 unlock',
        body: 'Tap to authenticate with passkey',
        url: auth_url,
        session_id,
        timestamp: Date.now(),
      });

      let sent = 0;
      let failed = 0;
      const stale = [];

      for (const [deviceId, recordStr] of deviceEntries) {
        try {
          const record = JSON.parse(recordStr);
          await webpush.sendNotification(record.subscription, payload);
          sent++;
        } catch (err) {
          failed++;
          if (err.statusCode === 410 || err.statusCode === 404) {
            stale.push(deviceId);
          }
          console.error(`Push failed for ${deviceId}:`, err.statusCode || err.message);
        }
      }

      if (stale.length > 0) {
        await redis.hdel('push:devices', ...stale);
      }

      return json(res, 200, { sent, failed, cleaned: stale.length });
    }

    // POST /api/relay/:id — store payload
    const relayMatch = path.match(/^\/api\/relay\/(.{16,})$/);
    if (req.method === 'POST' && relayMatch) {
      const id = relayMatch[1];
      const body = await parseBody(req);
      const { payload } = body;
      if (!payload || typeof payload !== 'string') {
        return json(res, 400, { error: 'Missing payload' });
      }
      if (payload.length > 10000) {
        return json(res, 400, { error: 'Payload too large' });
      }
      await redis.set(`relay:${id}`, payload, 'EX', TTL_SECONDS);
      return json(res, 200, { ok: true });
    }

    // GET /api/relay/:id — retrieve and delete
    if (req.method === 'GET' && relayMatch) {
      const id = relayMatch[1];
      let payload;
      try {
        payload = await redis.getdel(`relay:${id}`);
      } catch {
        payload = await redis.get(`relay:${id}`);
        if (payload) await redis.del(`relay:${id}`);
      }
      if (!payload) {
        return json(res, 404, { error: 'Not found' });
      }
      return json(res, 200, { payload });
    }

    // Health check
    if (req.method === 'GET' && path === '/health') {
      const ping = await redis.ping();
      const deviceCount = await redis.hlen('push:devices');
      return json(res, 200, { status: 'ok', redis: ping, registered_devices: deviceCount });
    }

    json(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error('Handler error:', err.message);
    json(res, 500, { error: 'Internal error' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Relay server listening on :${PORT}`);
});
