import React, { useRef, useState } from 'react';
import { encryptFile, decryptFile, DecryptionError } from './cryptoUtils.js';
import { uploadBlob, fetchMeta, fetchBlob, deleteFile } from './api.js';

const HOUR = 3600_000;
const EXPIRY = [
  ['1 hour', HOUR],
  ['24 hours', 24 * HOUR],
  ['7 days', 7 * 24 * HOUR],
];
const fmtSize = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);

export default function App() {
  const match = window.location.pathname.match(/^\/file\/([A-Za-z0-9_-]+)$/);
  return (
    <main className="shell">
      <header>
        <div className="logo">🛡️ GuardianBox</div>
        <p className="tag">Zero-knowledge file sharing. Files are encrypted in your browser. The server never sees the key.</p>
      </header>
      {match ? <Download id={match[1]} /> : <Upload />}
      <footer>AES-256-GCM · Web Crypto API · the decryption key lives only in the link’s # fragment</footer>
    </main>
  );
}

function Upload() {
  const input = useRef();
  const [file, setFile] = useState(null);
  const [expiry, setExpiry] = useState(EXPIRY[1][1]);
  const [maxDl, setMaxDl] = useState('');
  const [password, setPassword] = useState('');
  const [phase, setPhase] = useState('idle'); // idle | encrypting | uploading | done
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [deleted, setDeleted] = useState(false);

  async function go() {
    setError('');
    try {
      setPhase('encrypting');
      const enc = await encryptFile(file, { password: password || undefined });
      setPhase('uploading');
      const res = await uploadBlob(
        enc.ciphertext,
        { iv: enc.iv, salt: enc.salt, expiresInMs: expiry, maxDownloads: maxDl ? Number(maxDl) : null },
        setProgress,
      );
      // Everything after '#' stays in the browser. It is never part of any HTTP request.
      const link = `${window.location.origin}/file/${res.id}${enc.keyString ? '#' + enc.keyString : ''}`;
      setResult({ link, id: res.id, token: res.deleteToken, expiresAt: res.expiresAt, passwordMode: !!password });
      setPhase('done');
    } catch (e) {
      setError(e.message);
      setPhase('idle');
    }
  }

  if (phase === 'done' && result) {
    return (
      <section className="card">
        <h2>✅ Encrypted &amp; uploaded</h2>
        <p className="muted">
          {result.passwordMode
            ? 'Share this link and tell the recipient the password through a different channel.'
            : 'Anyone with this full link (including the part after #) can decrypt the file. We cannot recover it for you.'}
        </p>
        <div className="linkbox">
          <code>{result.link}</code>
          <button onClick={() => navigator.clipboard.writeText(result.link)}>Copy</button>
        </div>
        <p className="muted">Expires {new Date(result.expiresAt).toLocaleString()}</p>
        <div className="row">
          <button
            className="danger"
            disabled={deleted}
            onClick={async () => {
              await deleteFile(result.id, result.token);
              setDeleted(true);
            }}
          >
            {deleted ? 'Deleted' : 'Delete now'}
          </button>
          <button className="ghost" onClick={() => { setPhase('idle'); setResult(null); setFile(null); setPassword(''); setDeleted(false); }}>
            Share another file
          </button>
        </div>
      </section>
    );
  }

  const busy = phase === 'encrypting' || phase === 'uploading';
  return (
    <section className="card">
      <div
        className="drop"
        onClick={() => input.current.click()}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => { e.preventDefault(); setFile(e.dataTransfer.files[0] || null); }}
      >
        <input ref={input} type="file" hidden onChange={(e) => setFile(e.target.files[0] || null)} />
        {file ? <><strong>{file.name}</strong><span className="muted">{fmtSize(file.size)}</span></> : <span>Drop a file here or click to choose (max 100 MB)</span>}
      </div>

      <div className="grid">
        <label>Expires after
          <select value={expiry} onChange={(e) => setExpiry(Number(e.target.value))}>
            {EXPIRY.map(([l, v]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label>Burn after
          <select value={maxDl} onChange={(e) => setMaxDl(e.target.value)}>
            <option value="">unlimited downloads</option>
            <option value="1">1 download</option>
            <option value="5">5 downloads</option>
            <option value="10">10 downloads</option>
          </select>
        </label>
      </div>
      <label>Optional password
        <input type="password" placeholder="Leave empty to use a random key in the link" value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>

      {error && <p className="error">{error}</p>}
      {busy && (
        <div className="bar"><div style={{ width: phase === 'encrypting' ? '15%' : `${15 + progress * 85}%` }} /></div>
      )}
      <button disabled={!file || busy} onClick={go}>
        {phase === 'encrypting' ? 'Encrypting in your browser…' : phase === 'uploading' ? 'Uploading ciphertext…' : 'Encrypt & upload'}
      </button>
    </section>
  );
}

function Download({ id }) {
  const keyString = window.location.hash.slice(1); // read locally; never sent to the server
  const [state, setState] = useState('ready'); // ready | working | done
  const [password, setPassword] = useState('');
  const [meta, setMeta] = useState(null);
  const [error, setError] = useState('');
  const [name, setName] = useState('');

  React.useEffect(() => {
    fetchMeta(id).then(setMeta).catch((e) => setError(e.message));
  }, [id]);

  async function go() {
    setError('');
    setState('working');
    try {
      const cipher = await fetchBlob(id);
      const out = await decryptFile(cipher, meta.iv, { keyString, password, salt: meta.salt });
      const url = URL.createObjectURL(new Blob([out.bytes], { type: out.type }));
      const a = document.createElement('a');
      a.href = url;
      a.download = out.name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      setName(out.name);
      setState('done');
    } catch (e) {
      setError(e instanceof DecryptionError ? e.message : e.message || 'Download failed');
      setState('ready');
    }
  }

  const needsPassword = meta?.salt;
  const missingKey = meta && !meta.salt && !keyString;
  return (
    <section className="card">
      <h2>Encrypted file</h2>
      {meta && (
        <p className="muted">
          {fmtSize(meta.size)} · expires {new Date(meta.expiresAt).toLocaleString()}
          {meta.downloadsLeft !== null && ` · ${meta.downloadsLeft} download(s) left`}
        </p>
      )}
      {missingKey && <p className="error">This link has no decryption key. Make sure you copied everything after the “#”.</p>}
      {needsPassword && (
        <label>Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
      )}
      {error && <p className="error">{error}</p>}
      {state === 'done' ? (
        <p>✅ Decrypted locally and saved as <strong>{name}</strong>.</p>
      ) : (
        <button disabled={!meta || state === 'working' || missingKey || (needsPassword && !password)} onClick={go}>
          {state === 'working' ? 'Downloading & decrypting…' : 'Download & decrypt'}
        </button>
      )}
      <p className="muted small">Note: if this file has a download limit, each attempt counts, even with a wrong key.</p>
    </section>
  );
}
