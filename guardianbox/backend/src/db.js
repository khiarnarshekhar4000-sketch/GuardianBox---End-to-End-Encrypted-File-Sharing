import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Metadata only. Note what is NOT here: no key, no password, no filename,
 * no content type. The filename and MIME type live inside the encrypted payload.
 */
export function openDb(file = process.env.DB_FILE || './data/guardianbox.db') {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS files (
      id               TEXT PRIMARY KEY,
      iv               TEXT NOT NULL,          -- public AES-GCM nonce (base64url)
      salt             TEXT,                   -- public PBKDF2 salt, password mode only
      size             INTEGER NOT NULL,       -- ciphertext size in bytes
      created_at       INTEGER NOT NULL,       -- epoch ms
      expires_at       INTEGER NOT NULL,       -- epoch ms
      max_downloads    INTEGER,                -- NULL = unlimited
      downloads        INTEGER NOT NULL DEFAULT 0,
      delete_token_hash TEXT NOT NULL          -- sha256 of uploader's delete token
    );
    CREATE INDEX IF NOT EXISTS idx_files_expires ON files(expires_at);
  `);

  const q = {
    insert: db.prepare(`INSERT INTO files
      (id, iv, salt, size, created_at, expires_at, max_downloads, delete_token_hash)
      VALUES (@id, @iv, @salt, @size, @created_at, @expires_at, @max_downloads, @delete_token_hash)`),
    get: db.prepare('SELECT * FROM files WHERE id = ?'),
    del: db.prepare('DELETE FROM files WHERE id = ?'),
    // Atomic: a download is only "claimed" if the file is still alive. Prevents races
    // where two simultaneous requests both pass a burn-after-reading limit.
    claim: db.prepare(`UPDATE files SET downloads = downloads + 1
      WHERE id = ? AND expires_at > ? AND (max_downloads IS NULL OR downloads < max_downloads)`),
    dead: db.prepare(`SELECT id FROM files
      WHERE expires_at <= ? OR (max_downloads IS NOT NULL AND downloads >= max_downloads)`),
  };

  return {
    raw: db,
    insert: (row) => q.insert.run(row),
    get: (id) => q.get.get(id),
    delete: (id) => q.del.run(id),
    claimDownload: (id, now = Date.now()) => q.claim.run(id, now).changes === 1,
    findDeadIds: (now = Date.now()) => q.dead.all(now).map((r) => r.id),
  };
}
