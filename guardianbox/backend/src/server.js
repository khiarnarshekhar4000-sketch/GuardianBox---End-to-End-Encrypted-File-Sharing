import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Transform } from 'node:stream';
import { openDb } from './db.js';
import { createStorage } from './storage.js';
import { startCleanupJob } from './cleanup.js';

const PORT = Number(process.env.PORT || 3001);
const MAX_BYTES = Number(process.env.MAX_FILE_MB || 100) * 1024 * 1024;
const MAX_TTL_MS = 7 * 24 * 3600 * 1000;
const B64URL = /^[A-Za-z0-9_-]+$/;

const db = openDb();
const storage = createStorage();
const app = express();

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(
  helmet({
    referrerPolicy: { policy: 'no-referrer' },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        connectSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
      },
    },
  }),
);
app.use('/api', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));
app.use('/api', (_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

class LimitStream extends Transform {
  constructor(max) {
    super();
    this.max = max;
    this.bytes = 0;
  }
  _transform(chunk, _enc, cb) {
    this.bytes += chunk.length;
    if (this.bytes > this.max) return cb(Object.assign(new Error('File too large'), { code: 'TOO_LARGE' }));
    cb(null, chunk);
  }
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---- Upload: raw ciphertext body, metadata in headers -----------------------
app.post('/api/files', async (req, res) => {
  const iv = req.get('x-iv');
  const salt = req.get('x-salt') || null;
  const ttlMs = Math.min(Number(req.get('x-expires-in-ms')), MAX_TTL_MS);
  const maxDl = req.get('x-max-downloads') ? Number(req.get('x-max-downloads')) : null;

  if (!iv || !B64URL.test(iv) || iv.length > 32) return res.status(400).json({ error: 'Invalid IV' });
  if (salt && (!B64URL.test(salt) || salt.length > 64)) return res.status(400).json({ error: 'Invalid salt' });
  if (!Number.isFinite(ttlMs) || ttlMs < 60_000) return res.status(400).json({ error: 'Invalid expiry' });
  if (maxDl !== null && (!Number.isInteger(maxDl) || maxDl < 1 || maxDl > 1000))
    return res.status(400).json({ error: 'Invalid download limit' });
  const declared = Number(req.get('content-length'));
  if (declared > MAX_BYTES) return res.status(413).json({ error: 'File too large' });

  const id = crypto.randomBytes(16).toString('base64url');
  const deleteToken = crypto.randomBytes(24).toString('base64url');
  const limiter = new LimitStream(MAX_BYTES);
  req.pipe(limiter);
  req.on('error', (e) => limiter.destroy(e));
  req.on('aborted', () => limiter.destroy(new Error('aborted')));

  try {
    await storage.put(id, limiter);
    const now = Date.now();
    db.insert({
      id,
      iv,
      salt,
      size: limiter.bytes,
      created_at: now,
      expires_at: now + ttlMs,
      max_downloads: maxDl,
      delete_token_hash: sha256(deleteToken),
    });
    res.status(201).json({ id, deleteToken, expiresAt: now + ttlMs });
  } catch (err) {
    await storage.remove(id).catch(() => {});
    if (err.code === 'TOO_LARGE') return res.status(413).json({ error: 'File too large' });
    console.error('[upload]', err.message);
    if (!res.headersSent) res.status(500).json({ error: 'Upload failed' });
  }
});

const alive = (row) =>
  row && row.expires_at > Date.now() && (row.max_downloads === null || row.downloads < row.max_downloads);

// ---- Metadata (public: IV, salt, size, limits) --------------------------------
app.get('/api/files/:id/meta', (req, res) => {
  const row = B64URL.test(req.params.id) ? db.get(req.params.id) : null;
  if (!alive(row)) return res.status(404).json({ error: 'File not found or expired' });
  res.json({
    iv: row.iv,
    salt: row.salt,
    size: row.size,
    expiresAt: row.expires_at,
    downloadsLeft: row.max_downloads === null ? null : row.max_downloads - row.downloads,
  });
});

// ---- Ciphertext download ------------------------------------------------------
app.get('/api/files/:id/blob', async (req, res) => {
  const id = req.params.id;
  if (!B64URL.test(id) || !db.claimDownload(id)) return res.status(404).json({ error: 'File not found or expired' });
  const row = db.get(id);
  try {
    const body = await storage.get(id);
    res.set({ 'Content-Type': 'application/octet-stream', 'Content-Length': String(row.size) });
    body.on('error', () => res.destroy());
    res.on('close', async () => {
      // Burn after reading: remove as soon as the last allowed download is sent.
      const r = db.get(id);
      if (r && r.max_downloads !== null && r.downloads >= r.max_downloads) {
        await storage.remove(id).catch(() => {});
        db.delete(id);
      }
    });
    body.pipe(res);
  } catch (err) {
    console.error('[download]', err.message);
    if (!res.headersSent) res.status(500).json({ error: 'Download failed' });
  }
});

// ---- Uploader-initiated deletion ----------------------------------------------
app.delete('/api/files/:id', async (req, res) => {
  const row = B64URL.test(req.params.id) ? db.get(req.params.id) : null;
  const token = req.get('x-delete-token') || '';
  if (!row) return res.status(404).json({ error: 'Not found' });
  const a = Buffer.from(sha256(token));
  const b = Buffer.from(row.delete_token_hash);
  if (!crypto.timingSafeEqual(a, b)) return res.status(403).json({ error: 'Forbidden' });
  await storage.remove(row.id);
  db.delete(row.id);
  res.status(204).end();
});

// ---- Serve the built frontend --------------------------------------------------
const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../frontend/dist');
if (fs.existsSync(dist)) {
  app.use(express.static(dist));
  app.get('*', (_req, res) => res.sendFile(path.join(dist, 'index.html')));
}

startCleanupJob(db, storage);
app.listen(PORT, () => console.log(`GuardianBox listening on :${PORT} (storage: ${storage.kind})`));
