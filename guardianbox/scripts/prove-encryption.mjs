/**
 * Proof of zero-knowledge storage.
 *   1. Start the server:  npm run start -w backend   (local-disk or S3 mode)
 *   2. Run:               node scripts/prove-encryption.mjs
 *
 * Encrypts a known plaintext with the SAME cryptoUtils the browser uses, uploads it,
 * then inspects what the server actually stored (blob + database) and shows that
 *   - the plaintext and filename are nowhere in storage or the DB,
 *   - the blob looks like random data (high entropy),
 *   - decryption fails without the key and succeeds with it.
 */
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { encryptFile, decryptFile } from '../frontend/src/cryptoUtils.js';

const BASE = process.env.BASE_URL || 'http://localhost:3001';
const BLOB_DIR = process.env.BLOB_DIR || './data/blobs';
const DB_FILE = process.env.DB_FILE || './data/guardianbox.db';

const SECRET = 'CONFIDENTIAL: payment of $4,200,000 routed via shell company Acme Holdings.\n'.repeat(50);
const file = new File([SECRET], 'whistleblower-evidence.txt', { type: 'text/plain' });

const entropy = (buf) => {
  const c = new Array(256).fill(0);
  for (const b of buf) c[b]++;
  return -c.reduce((s, n) => (n ? s + (n / buf.length) * Math.log2(n / buf.length) : s), 0);
};

console.log('1) Encrypting in "browser" (Node webcrypto)…');
const enc = await encryptFile(file);

console.log('2) Uploading ciphertext…');
const res = await fetch(`${BASE}/api/files`, {
  method: 'POST',
  headers: { 'content-type': 'application/octet-stream', 'x-iv': enc.iv, 'x-expires-in-ms': '3600000' },
  body: enc.ciphertext,
});
const { id } = await res.json();
console.log('   file id:', id);

console.log('\n3) What the SERVER stored:');
const stored = fs.readFileSync(path.join(BLOB_DIR, id));
console.log(`   blob size: ${stored.length} bytes (plaintext was ${SECRET.length})`);
console.log(`   Shannon entropy: ${entropy(stored).toFixed(3)} bits/byte (8.0 = perfectly random; English text ≈ 4.2)`);
console.log('   contains "CONFIDENTIAL"?      ', stored.includes('CONFIDENTIAL'));
console.log('   contains "Acme"?              ', stored.includes('Acme'));
console.log('   contains filename?            ', stored.includes('whistleblower'));
console.log('   first 48 bytes (hex):         ', stored.subarray(0, 48).toString('hex'));

const row = new Database(DB_FILE, { readonly: true }).prepare('SELECT * FROM files WHERE id=?').get(id);
console.log('\n   DB row:', JSON.stringify(row));
console.log('   DB contains key?              ', JSON.stringify(row).includes(enc.keyString));
console.log('   DB contains filename?         ', JSON.stringify(row).includes('whistleblower'));

console.log('\n4) Recipient flow:');
const meta = await (await fetch(`${BASE}/api/files/${id}/meta`)).json();
const blob = new Uint8Array(await (await fetch(`${BASE}/api/files/${id}/blob`)).arrayBuffer());
try {
  await decryptFile(blob, meta.iv, { keyString: 'A'.repeat(43) });
  console.log('   wrong key: DECRYPTED (BAD!)');
} catch (e) {
  console.log('   wrong key  →', e.name + ':', e.message);
}
const out = await decryptFile(blob, meta.iv, { keyString: enc.keyString });
console.log('   right key  → recovered', JSON.stringify(out.name), `(${out.bytes.length} bytes), identical: ${Buffer.from(out.bytes).toString() === SECRET}`);

await fetch(`${BASE}/api/files/${id}`, { method: 'DELETE', headers: { 'x-delete-token': 'x' } }).catch(() => {});
