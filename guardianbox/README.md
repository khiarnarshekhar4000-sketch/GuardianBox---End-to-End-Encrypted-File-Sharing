# 🛡️ GuardianBox: zero-knowledge file sharing

Files are encrypted **in the browser** with AES-256-GCM before upload. The server (and S3) only ever
hold random-looking ciphertext. The decryption key lives in the URL **fragment** (`#…`), which browsers
never send in HTTP requests.

```
https://guardianbox.example/file/Zk3…  #  Qm9…43-char-key…
└──────── sent to server ──────────┘   └─ stays in the browser ─┘
```

## Architecture

```
Browser (React)                              Server (Express)                S3 / MinIO      SQLite
───────────────                              ────────────────                ──────────      ──────
pick file
generate 256-bit key  ──────────────────────────────────────────────────────────────────────────────
pack {name,type,bytes} → AES-GCM encrypt
POST ciphertext + IV + expiry ───────────────► stream body ────────────────► blobs/<id>      row: id, iv,
                                               (size-limited, no buffering)                   size, expiry,
link = /file/<id>#<key>                                                                       limits, hash(deleteToken)
                                                                                              (NO key, NO name)
recipient opens link
read key from location.hash
GET meta (iv) / GET blob  ◄──────────────────  atomic download claim ◄────── blob
AES-GCM decrypt → save file
```

| Phase | Where |
|---|---|
| Crypto engine | `frontend/src/cryptoUtils.js` |
| Upload API / storage | `backend/src/server.js`, `backend/src/storage.js` (S3, MinIO, or local disk) |
| Metadata DB | `backend/src/db.js` (SQLite) |
| Expiry + burn-after-reading | atomic `claimDownload` in `db.js`; hourly cron in `backend/src/cleanup.js` |
| UI | `frontend/src/App.jsx` |
| Tests | `frontend/src/cryptoUtils.test.js` |
| Proof | `scripts/prove-encryption.mjs` |

## Run it

```bash
npm install
cp .env.example .env            # optional; with no S3_BUCKET it stores blobs on local disk

# development (two terminals)
npm run dev:backend             # http://localhost:3001
npm run dev:frontend            # http://localhost:5173  (proxies /api)

# production-style (single process serves the built UI)
npm run build && npm start      # http://localhost:3001

npm test                        # unit tests
npm run prove                   # end-to-end zero-knowledge proof (server must be running)
```

### Using S3 or MinIO
Set `S3_BUCKET`, `AWS_REGION`, and AWS credentials. For MinIO also set `S3_ENDPOINT=http://localhost:9000`.
The bucket should be **private** (block public access). Optionally add an S3 lifecycle rule that expires
`blobs/` objects after 8 days as a safety net behind the cron job.

### Deploying
A `Dockerfile` is included. It works on Render, Railway, Fly.io, or any VPS. Set the env vars above, mount a
persistent volume at `/app/data` (for SQLite), and **serve over HTTPS only** (the Web Crypto API requires a
secure context).

## Proof that S3 holds only ciphertext

1. Upload any file through the UI.
2. Look at the object in the S3 console (`blobs/<id>`), download it, and run `xxd blob | head`: random bytes,
   no file signature (no `%PDF`, no `PK`), no filename.
3. Or run `npm run prove`, which encrypts a known plaintext, uploads it, then reports: the blob's Shannon entropy
   (~8 bits/byte), that none of the plaintext/filename strings occur in the blob or DB row, and that decryption
   fails with a wrong key and succeeds with the right one.

## Security audit

### What the server learns
Ciphertext size (≈ file size + 16 bytes), upload time, expiry, download count, IP addresses and the public IV/salt.
It does **not** learn the content, filename, MIME type, or key.

### Attack vectors and mitigations

| # | Threat | Analysis / mitigation |
|---|---|---|
| 1 | **User loses the link** | The key exists only in the link (or in the password). There is no recovery by design; the server cannot help. Users must save the full link. UI warns about this. |
| 2 | **Link shared over an insecure channel** | Whoever has the full link can decrypt. Recommend sending it via Signal etc., or use **password mode** and send the password over a different channel. |
| 3 | **Database breach** | Attackers get IDs, IVs, sizes, timestamps and a SHA-256 of delete tokens. No keys, passwords or filenames. Useless without the links. |
| 4 | **S3 bucket breach / malicious cloud admin** | Only AES-256-GCM ciphertext. Offline brute force of a random 256-bit key is infeasible. |
| 5 | **Malicious or compromised server serving modified JavaScript** | **The fundamental limit of browser-based E2EE.** A hostile server could ship JS that exfiltrates the key. Mitigations: strict CSP (no inline/3rd-party scripts), no external dependencies at runtime, Subresource Integrity, open-source code, and (future) a browser extension / signed-bundle / reproducible build so users can verify the code. |
| 6 | **Key leaks via Referer / logs / analytics** | Fragments are not sent in requests or `Referer`; additionally `Referrer-Policy: no-referrer` is set. No analytics/3rd-party scripts. Caveat: browser history, synced history, and link-preview bots in chat apps that execute JS can see the full URL. |
| 7 | **Weak passwords (password mode)** | PBKDF2-SHA256, 600k iterations, random 128-bit salt slows offline guessing but cannot save a weak password. Anyone who obtains the blob (e.g. DB+S3 breach) can attack it offline. Prefer link mode (256-bit random key) or long passphrases. |
| 8 | **IV reuse** | A fresh random 96-bit IV per encryption, and a fresh random key per upload in link mode, so (key, IV) pairs never repeat. |
| 9 | **Ciphertext tampering** | GCM auth tag makes any modification fail decryption (tested). A server could *delete* or *replace the whole blob*, which is detected as a decryption failure, not silent corruption. |
| 10 | **Metadata leakage / traffic analysis** | Size and timing are visible. Filename and type are encrypted inside the payload. Padding could hide exact size (future work). |
| 11 | **Brute-forcing file IDs** | IDs are 128-bit random; per-IP rate limiting on `/api`. Even with an ID, an attacker needs the key. But an attacker *can* burn a download-limited file by fetching the blob, so a "burn after 1" file could be consumed by someone with only the ID. (Mitigation: IDs are unguessable; future: require a proof-of-key token.) |
| 12 | **Burn-after-reading races** | Downloads are claimed with a single atomic SQL `UPDATE … WHERE downloads < max`, so concurrent requests can't both succeed. File is deleted when the response closes, and the cron sweeps leftovers. |
| 13 | **Abuse (illegal content hosting)** | The operator can't scan content, by design. Mitigations: size limits, rate limiting, ≤7-day TTL, delete tokens, and a takedown-by-ID process. Needs a policy decision before public launch. |
| 14 | **Large files / DoS** | Body is streamed to S3 (multipart) with a hard byte cap; rate limits. Current client-side crypto is single-shot, so browser memory limits practical size (~100 MB cap). Future: chunked STREAM-style AES-GCM. |
| 15 | **Client-side compromise (malware, malicious extensions, XSS)** | Out of scope for E2EE; CSP reduces XSS risk. React escapes output; no `dangerouslySetInnerHTML`. |
| 16 | **Downgrade to HTTP** | Web Crypto requires a secure context and the key would be exposed in transit if the page were tampered. Deploy HTTPS-only with HSTS. |

### Known limitations / roadmap
- Chunked (streaming) encryption for multi-GB files.
- Size padding; optional uploader-side "proof of key" to protect download-limited files from ID-only burning.
- Verifiable/signed frontend builds.
- Postgres instead of SQLite for multi-instance deployments.
