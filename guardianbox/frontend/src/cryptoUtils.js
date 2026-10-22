/**
 * cryptoUtils.js: all client-side cryptography for GuardianBox.
 *
 * Primitive: AES-256-GCM (authenticated encryption) via the Web Crypto API.
 *  - A fresh random 96-bit IV is generated for EVERY encryption. Never reuse an IV with the same key.
 *  - GCM appends a 128-bit auth tag, so wrong keys and tampered data fail loudly on decrypt.
 *  - Two key modes:
 *      1. "link" mode: random 256-bit key, shared in the URL #fragment (never sent to the server).
 *      2. "password" mode: key derived with PBKDF2-SHA256 (600k iterations) from a password + public salt.
 *  - File name and MIME type are packed INSIDE the plaintext, so the server never learns them.
 */

const subtle = globalThis.crypto.subtle;
const getRandomValues = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export const IV_BYTES = 12;
export const SALT_BYTES = 16;
export const PBKDF2_ITERATIONS = 600_000;

export class DecryptionError extends Error {
  constructor(message = 'Decryption failed: wrong key/password, or the data was tampered with.') {
    super(message);
    this.name = 'DecryptionError';
  }
}

// ---------- encoding helpers ----------
export function toB64Url(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64Url(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const toBytes = (data) =>
  typeof data === 'string' ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);

// ---------- keys ----------
export function generateKey() {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

/** Export a key as base64url (43 chars for 256 bits): suitable for the URL fragment. */
export async function exportKey(key) {
  return toB64Url(new Uint8Array(await subtle.exportKey('raw', key)));
}

export function importKey(keyString) {
  let raw;
  try {
    raw = fromB64Url(keyString);
  } catch {
    throw new DecryptionError('The key in the link is malformed.');
  }
  if (raw.length !== 32) throw new DecryptionError('The key in the link is malformed.');
  return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export const generateSalt = () => getRandomValues(SALT_BYTES);

export async function deriveKeyFromPassword(password, salt, iterations = PBKDF2_ITERATIONS) {
  const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// ---------- core encrypt / decrypt ----------
/** @returns {{ciphertext: Uint8Array, iv: Uint8Array}} */
export async function encrypt(data, key) {
  const iv = getRandomValues(IV_BYTES);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, toBytes(data));
  return { ciphertext: new Uint8Array(ct), iv };
}

/** @returns {Promise<Uint8Array>} plaintext; throws DecryptionError on wrong key or tampering. */
export async function decrypt(ciphertext, key, iv) {
  try {
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, key, toBytes(ciphertext)));
  } catch {
    throw new DecryptionError();
  }
}

export async function encryptString(text, key) {
  return encrypt(text, key);
}

export async function decryptString(ciphertext, key, iv) {
  return new TextDecoder().decode(await decrypt(ciphertext, key, iv));
}

// ---------- file packaging: [4-byte header length][JSON header][file bytes] ----------
export function packFile(name, type, bytes) {
  const header = new TextEncoder().encode(JSON.stringify({ name, type, size: bytes.length }));
  const out = new Uint8Array(4 + header.length + bytes.length);
  new DataView(out.buffer).setUint32(0, header.length);
  out.set(header, 4);
  out.set(bytes, 4 + header.length);
  return out;
}

export function unpackFile(packed) {
  if (packed.length < 4) throw new DecryptionError('Corrupted payload.');
  const headerLen = new DataView(packed.buffer, packed.byteOffset, packed.byteLength).getUint32(0);
  if (headerLen > packed.length - 4) throw new DecryptionError('Corrupted payload.');
  const meta = JSON.parse(new TextDecoder().decode(packed.subarray(4, 4 + headerLen)));
  return { name: meta.name, type: meta.type, bytes: packed.subarray(4 + headerLen) };
}

// ---------- high-level helpers used by the UI ----------
/**
 * Encrypt a File in the browser.
 * @param {File} file
 * @param {{password?: string}} opts
 * @returns {{ciphertext, iv: string, salt: string|null, keyString: string|null}}
 *   keyString is the secret to put in the URL fragment (null in password mode).
 */
export async function encryptFile(file, { password } = {}) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const packed = packFile(file.name, file.type || 'application/octet-stream', bytes);

  let key;
  let keyString = null;
  let salt = null;
  if (password) {
    const saltBytes = generateSalt();
    key = await deriveKeyFromPassword(password, saltBytes);
    salt = toB64Url(saltBytes);
  } else {
    key = await generateKey();
    keyString = await exportKey(key);
  }
  const { ciphertext, iv } = await encrypt(packed, key);
  return { ciphertext, iv: toB64Url(iv), salt, keyString };
}

/**
 * Decrypt a downloaded blob.
 * @returns {{name: string, type: string, bytes: Uint8Array}}
 */
export async function decryptFile(ciphertext, ivString, { keyString, password, salt } = {}) {
  let key;
  if (salt) {
    if (!password) throw new DecryptionError('This file is password protected.');
    key = await deriveKeyFromPassword(password, fromB64Url(salt));
  } else {
    if (!keyString) throw new DecryptionError('The link is missing its decryption key (the part after #).');
    key = await importKey(keyString);
  }
  const packed = await decrypt(ciphertext, key, fromB64Url(ivString));
  return unpackFile(packed);
}
