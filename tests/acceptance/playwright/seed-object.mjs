/**
 * Uploads the acceptance report body (`tests/acceptance/report.md`) to
 * the object store at the fixed key `r3-acceptance/report.md`. Reads
 * the `CENTRAL_TEST_MINIO_*` environment — the same variables the
 * integration suites use.
 *
 * Exits non-zero on any failure; invoked only when the runner confirmed
 * the endpoint is reachable.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  S3Client,
  CreateBucketCommand,
  PutObjectCommand,
} from '@aws-sdk/client-s3';

const endpoint = process.env.CENTRAL_TEST_MINIO_ENDPOINT;
if (!endpoint) {
  console.error('seed-object: CENTRAL_TEST_MINIO_ENDPOINT unset');
  process.exit(1);
}
const bucket = process.env.CENTRAL_TEST_MINIO_BUCKET ?? 'central-artifacts';
const accessKeyId = process.env.CENTRAL_TEST_MINIO_ACCESS_KEY ?? 'minioadmin';
const secretAccessKey =
  process.env.CENTRAL_TEST_MINIO_SECRET_KEY ?? 'minioadmin';
const useTls = process.env.CENTRAL_TEST_MINIO_TLS === '1';

const body = readFileSync(
  path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    'report.md',
  ),
);

const client = new S3Client({
  endpoint,
  region: process.env.CENTRAL_TEST_MINIO_REGION ?? 'us-east-1',
  forcePathStyle: true,
  tls: useTls,
  credentials: { accessKeyId, secretAccessKey },
});

// The bucket may not exist yet — `initialBuckets` is not honoured by
// every s3mock build and a reused MinIO volume may predate the env.
try {
  await client.send(new CreateBucketCommand({ Bucket: bucket }));
} catch (e) {
  const name = e?.name ?? '';
  if (name !== 'BucketAlreadyOwnedByYou' && name !== 'BucketAlreadyExists') {
    throw e;
  }
}
// The durable `ready_key`/`object_key` — the derived
// `v1/ready/<workspace>/<artifact>/<content-generation>` the artifact
// row carries and the S3 adapter will accept for reads.
const KEY =
  'v1/ready/019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a/' +
  '019e0000-0000-7000-8000-00000000c003/019e0000-0000-7000-8000-00000000c011';
await client.send(
  new PutObjectCommand({
    Bucket: bucket,
    Key: KEY,
    Body: body,
    ContentType: 'text/markdown',
  }),
);
console.log(`seed-object: put ${body.length} bytes at s3://${bucket}/${KEY}`);
