import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import {
  S3Client,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';

/**
 * Blob storage abstraction. Stores opaque ciphertext only.
 *  - S3_BUCKET set  -> AWS S3 (or MinIO via S3_ENDPOINT)
 *  - otherwise      -> local disk (development)
 */
export function createStorage(env = process.env) {
  return env.S3_BUCKET ? createS3(env) : createLocal(env.BLOB_DIR || './data/blobs');
}

function createS3(env) {
  const bucket = env.S3_BUCKET;
  const client = new S3Client({
    region: env.AWS_REGION || 'us-east-1',
    endpoint: env.S3_ENDPOINT || undefined, // e.g. http://localhost:9000 for MinIO
    forcePathStyle: Boolean(env.S3_ENDPOINT),
  });
  const key = (id) => `blobs/${id}`;
  return {
    kind: 's3',
    // Streams the request body to S3 in multipart chunks: no full-file buffering.
    async put(id, stream) {
      const upload = new Upload({
        client,
        params: { Bucket: bucket, Key: key(id), Body: stream, ContentType: 'application/octet-stream' },
        queueSize: 3,
        partSize: 8 * 1024 * 1024,
      });
      await upload.done();
    },
    async get(id) {
      const out = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key(id) }));
      return out.Body; // Readable
    },
    async remove(id) {
      await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key(id) }));
    },
  };
}

function createLocal(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const file = (id) => path.join(dir, id);
  return {
    kind: 'local',
    async put(id, stream) {
      await pipeline(stream, fs.createWriteStream(file(id)));
    },
    async get(id) {
      return fs.createReadStream(file(id));
    },
    async remove(id) {
      await fs.promises.rm(file(id), { force: true });
    },
  };
}
