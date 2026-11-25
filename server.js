const crypto = require('crypto');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const { API_KEY, HMAC_SECRET, DATABASE_URL, DB_CA_FILE, PORT = 3000 } = process.env;
const DEBUG_ONLY = process.env.ENABLE_DEBUG_ROUTE === 'true';
const configured = !!(API_KEY && API_KEY.length >= 24 && DATABASE_URL);
if (!configured && !DEBUG_ONLY) {
  console.error('Set API_KEY (>=24 chars) and DATABASE_URL');
  process.exit(1);
}
if (!configured) console.warn('API_KEY/DATABASE_URL not set: running with debug route only; /api/sales disabled.');

// ---- DB: TLS-encrypted connection, parameterised queries only ----
const pool = configured ? new Pool({
  connectionString: DATABASE_URL,
  ssl: DB_CA_FILE ? { ca: fs.readFileSync(DB_CA_FILE, 'utf8'), rejectUnauthorized: true } : undefined,
  max: 5,
}) : null;

const safeEqual = (a, b) => {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
};

// ---- Auth middleware ----
function authenticate(req, res, next) {
  if (!configured) return res.status(503).json({ error: 'not configured' });
  const token = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!token || !safeEqual(token, API_KEY)) return res.status(401).json({ error: 'unauthorized' });

  if (HMAC_SECRET) {
    const ts = Number(req.get('x-timestamp'));
    const sig = req.get('x-signature') || '';
    if (!ts || Math.abs(Date.now() - ts) > 5 * 60 * 1000) // replay window: 5 min
      return res.status(401).json({ error: 'stale or missing timestamp' });
    const expected = crypto.createHmac('sha256', HMAC_SECRET).update(`${ts}.`).update(req.rawBody).digest('hex');
    if (!safeEqual(sig, expected)) return res.status(401).json({ error: 'bad signature' });
  }
  next();
}

// ---- Validation ----
const isTallyDate = (s) => /^\d{8}$/.test(s);
function validateVoucher(v) {
  if (!v || typeof v !== 'object') return 'voucher must be an object';
  if (!/^\d{1,20}$/.test(String(v.vchid))) return 'invalid vchid';
  if (typeof v.vchno !== 'string' || v.vchno.length > 100) return 'invalid vchno';
  if (!isTallyDate(String(v.vchdt))) return 'invalid vchdt';
  return null;
}
const toDate = (s) => `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}`;

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, limit: 60 }));
// ---- Debug route: NO auth, logs whatever it receives. Opt-in via ENABLE_DEBUG_ROUTE=true. ----
// Registered before express.json so malformed/non-JSON bodies are still captured.
if (process.env.ENABLE_DEBUG_ROUTE === 'true') {
  console.warn('WARNING: unauthenticated /debug/echo is ENABLED. Do not use in production.');
  app.all('/debug/echo', express.raw({ type: () => true, limit: '1mb' }), (req, res) => {
    const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
    let parsed;
    try { parsed = raw ? JSON.parse(raw) : undefined; } catch { /* not JSON */ }
    console.log('[debug/echo]', JSON.stringify({
      time: new Date().toISOString(),
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      headers: req.headers,
      body: parsed !== undefined ? parsed : raw,
    }, null, 2));
    res.json({ ok: true, received: { method: req.method, bytes: Buffer.byteLength(raw), json: parsed !== undefined } });
  });
}

app.use(express.json({
  limit: '5mb',
  verify: (req, _res, buf) => { req.rawBody = buf; }, // exact bytes for HMAC
}));

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/api/sales', authenticate, async (req, res) => {
  const vouchers = req.body && req.body.data;
  if (!Array.isArray(vouchers) || vouchers.length === 0 || vouchers.length > 500)
    return res.status(400).json({ error: 'data must be an array of 1-500 vouchers' });

  for (const [i, v] of vouchers.entries()) {
    const err = validateVoucher(v);
    if (err) return res.status(400).json({ error: `data[${i}]: ${err}` });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const v of vouchers) {
      await client.query(
        `INSERT INTO sales_vouchers (vchid, altid, vchno, vchdt, vchtype, partyname, total_amt, payload)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (vchid) DO UPDATE SET
           altid=EXCLUDED.altid, vchno=EXCLUDED.vchno, vchdt=EXCLUDED.vchdt, vchtype=EXCLUDED.vchtype,
           partyname=EXCLUDED.partyname, total_amt=EXCLUDED.total_amt, payload=EXCLUDED.payload,
           updated_at=now()`,
        [String(v.vchid), v.altid ?? null, v.vchno, toDate(String(v.vchdt)), v.vchtype ?? null,
         v.partyname ?? null, Number(v.nfield2) || null, JSON.stringify(v)]
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true, saved: vouchers.length });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('DB error:', e.message); // never return DB internals to the caller
    res.status(500).json({ error: 'internal error' });
  } finally {
    client.release();
  }
});

app.use((err, _req, res, _next) => {
  res.status(err.status || 400).json({ error: 'bad request' });
});

app.listen(PORT, () => console.log(`Listening on :${PORT}`));
