import { describe, it, expect } from 'vitest';
import {
  generateKey, exportKey, importKey, encrypt, decrypt, encryptString, decryptString,
  deriveKeyFromPassword, generateSalt, encryptFile, decryptFile, packFile, unpackFile,
  toB64Url, fromB64Url, DecryptionError, IV_BYTES,
} from './cryptoUtils.js';

const bytes = (...n) => new Uint8Array(n);
// getRandomValues is capped at 65,536 bytes per call, so fill larger buffers in chunks.
const randomBytes = (n) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(i + 65536, n)));
  return out;
};

describe('encrypt / decrypt round trip', () => {
  it('returns the original bytes', async () => {
    const key = await generateKey();
    const data = randomBytes(100_000);
    const { ciphertext, iv } = await encrypt(data, key);
    expect(await decrypt(ciphertext, key, iv)).toEqual(data);
  });

  it('returns the original string (incl. unicode)', async () => {
    const key = await generateKey();
    const text = 'Source: Ravi → ministry memo 🔐 日本語';
    const { ciphertext, iv } = await encryptString(text, key);
    expect(await decryptString(ciphertext, key, iv)).toBe(text);
  });

  it('handles empty input', async () => {
    const key = await generateKey();
    const { ciphertext, iv } = await encrypt(new Uint8Array(0), key);
    expect((await decrypt(ciphertext, key, iv)).length).toBe(0);
  });

  it('ciphertext does not contain the plaintext', async () => {
    const key = await generateKey();
    const secret = 'TOP-SECRET-WHISTLEBLOWER-DOCUMENT';
    const { ciphertext } = await encrypt(secret, key);
    expect(Buffer.from(ciphertext).includes(Buffer.from(secret))).toBe(false);
  });
});

describe('IV handling', () => {
  it('uses a 96-bit IV and never repeats it', async () => {
    const key = await generateKey();
    const ivs = new Set();
    for (let i = 0; i < 200; i++) {
      const { iv } = await encrypt('x', key);
      expect(iv.length).toBe(IV_BYTES);
      ivs.add(toB64Url(iv));
    }
    expect(ivs.size).toBe(200);
  });

  it('same plaintext + same key gives different ciphertext', async () => {
    const key = await generateKey();
    const a = await encrypt('same', key);
    const b = await encrypt('same', key);
    expect(toB64Url(a.ciphertext)).not.toBe(toB64Url(b.ciphertext));
  });
});

describe('failure modes ("Wrong Password" handling)', () => {
  it('wrong key throws DecryptionError', async () => {
    const { ciphertext, iv } = await encrypt('hello', await generateKey());
    await expect(decrypt(ciphertext, await generateKey(), iv)).rejects.toBeInstanceOf(DecryptionError);
  });

  it('wrong IV throws DecryptionError', async () => {
    const key = await generateKey();
    const { ciphertext } = await encrypt('hello', key);
    await expect(decrypt(ciphertext, key, new Uint8Array(IV_BYTES))).rejects.toBeInstanceOf(DecryptionError);
  });

  it('tampered ciphertext is detected (GCM authentication)', async () => {
    const key = await generateKey();
    const { ciphertext, iv } = await encrypt('hello world', key);
    ciphertext[0] ^= 0x01;
    await expect(decrypt(ciphertext, key, iv)).rejects.toBeInstanceOf(DecryptionError);
  });

  it('truncated ciphertext is detected', async () => {
    const key = await generateKey();
    const { ciphertext, iv } = await encrypt('hello world', key);
    await expect(decrypt(ciphertext.slice(0, -3), key, iv)).rejects.toBeInstanceOf(DecryptionError);
  });
});

describe('key export / import (URL fragment)', () => {
  it('exports a 43-char base64url key that round-trips', async () => {
    const key = await generateKey();
    const str = await exportKey(key);
    expect(str).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const { ciphertext, iv } = await encrypt('via link', key);
    expect(await decryptString(ciphertext, await importKey(str), iv)).toBe('via link');
  });

  it('rejects malformed keys', async () => {
    await expect(importKey('tooshort')).rejects.toBeInstanceOf(DecryptionError);
  });

  it('base64url helpers round-trip all byte values', () => {
    const all = new Uint8Array(256).map((_, i) => i);
    expect(fromB64Url(toB64Url(all))).toEqual(all);
  });
});

describe('password mode', () => {
  it('same password+salt derives a working key; wrong password fails', async () => {
    const salt = generateSalt();
    const k1 = await deriveKeyFromPassword('correct horse', salt, 1000);
    const { ciphertext, iv } = await encrypt('pw protected', k1);
    const k2 = await deriveKeyFromPassword('correct horse', salt, 1000);
    expect(await decryptString(ciphertext, k2, iv)).toBe('pw protected');
    const bad = await deriveKeyFromPassword('wrong horse', salt, 1000);
    await expect(decrypt(ciphertext, bad, iv)).rejects.toBeInstanceOf(DecryptionError);
  });
});

describe('file packaging', () => {
  it('pack/unpack preserves name, type and bytes', () => {
    const packed = packFile('report.pdf', 'application/pdf', bytes(1, 2, 3, 4));
    expect(unpackFile(packed)).toMatchObject({ name: 'report.pdf', type: 'application/pdf', bytes: bytes(1, 2, 3, 4) });
  });

  it('encryptFile → decryptFile (link mode) restores the file and hides the filename', async () => {
    const file = new File([bytes(9, 8, 7, 6, 5)], 'leak.docx', { type: 'application/msword' });
    const enc = await encryptFile(file);
    expect(enc.keyString).toBeTruthy();
    expect(Buffer.from(enc.ciphertext).includes(Buffer.from('leak.docx'))).toBe(false);
    const out = await decryptFile(enc.ciphertext, enc.iv, { keyString: enc.keyString });
    expect(out).toMatchObject({ name: 'leak.docx', type: 'application/msword', bytes: bytes(9, 8, 7, 6, 5) });
  });

  it('encryptFile → decryptFile (password mode)', async () => {
    const file = new File([bytes(1, 1, 2, 3)], 'a.bin');
    const enc = await encryptFile(file, { password: 'hunter2' });
    expect(enc.keyString).toBeNull();
    const out = await decryptFile(enc.ciphertext, enc.iv, { password: 'hunter2', salt: enc.salt });
    expect(out.bytes).toEqual(bytes(1, 1, 2, 3));
    await expect(decryptFile(enc.ciphertext, enc.iv, { password: 'nope', salt: enc.salt })).rejects.toBeInstanceOf(DecryptionError);
  }, 20_000);
});
