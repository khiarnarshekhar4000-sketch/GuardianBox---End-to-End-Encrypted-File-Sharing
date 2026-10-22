/** Upload ciphertext with progress. The body is opaque bytes; metadata travels in headers. */
export function uploadBlob(ciphertext, { iv, salt, expiresInMs, maxDownloads }, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/files');
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.setRequestHeader('x-iv', iv);
    if (salt) xhr.setRequestHeader('x-salt', salt);
    xhr.setRequestHeader('x-expires-in-ms', String(expiresInMs));
    if (maxDownloads) xhr.setRequestHeader('x-max-downloads', String(maxDownloads));
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress?.(e.loaded / e.total);
    xhr.onload = () => {
      let body = {};
      try {
        body = JSON.parse(xhr.responseText);
      } catch {}
      xhr.status === 201 ? resolve(body) : reject(new Error(body.error || `Upload failed (${xhr.status})`));
    };
    xhr.onerror = () => reject(new Error('Network error during upload'));
    xhr.send(ciphertext);
  });
}

export async function fetchMeta(id) {
  const res = await fetch(`/api/files/${id}/meta`);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'File not found or expired');
  return res.json();
}

export async function fetchBlob(id) {
  const res = await fetch(`/api/files/${id}/blob`);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'File not found or expired');
  return new Uint8Array(await res.arrayBuffer());
}

export async function deleteFile(id, token) {
  const res = await fetch(`/api/files/${id}`, { method: 'DELETE', headers: { 'x-delete-token': token } });
  if (!res.ok) throw new Error('Could not delete file');
}
