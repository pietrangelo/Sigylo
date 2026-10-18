// Files travel as a sealed manifest, deposited like any secret, followed by
// sealed chunks of 1 MiB (see crates/sealing/src/core/file.rs). Chunks go up
// and come down one request at a time, in order: a 10 MB file costs eleven
// requests each way, well inside the relay's rate limit.

import type { Relay, RelayError, Result } from './relay';

/** Largest file Sigylo seals: 10 MiB, ten chunks. */
export const MAX_FILE_LEN = 10 * 1024 * 1024;

/** A chunk not sent yet, sent with no reply back (it may have arrived), or taken by the relay. */
export type ChunkState = 'missing' | 'unsure' | 'stored';

/**
 * A file upload kept in memory: the deposit (or inbox) id, the sealed chunks
 * and where each one stands, so a retry sends only what the relay lacks.
 * The manifest went first and, for an answer, used up the request: losing
 * the chunks would lose the answer.
 */
export type Upload = { readonly id: Uint8Array; readonly chunks: readonly Uint8Array[]; readonly state: ChunkState[] };

/** Refusals the relay gives before it stores anything: that chunk surely did not arrive. */
const REFUSED_BEFORE_STORING: ReadonlySet<RelayError> = new Set(['NotFound', 'RateLimited', 'PayloadTooLarge', 'StorageFull']);

export function startUpload(id: Uint8Array, chunks: readonly Uint8Array[]): Upload {
  return { id, chunks: [...chunks], state: chunks.map(() => 'missing') };
}

/**
 * Sends the chunks the relay does not have yet, in order, stopping at the
 * first refusal. The relay takes each index once and answers 404 after: for
 * a chunk whose earlier send may have arrived, that 404 means it did. A 404
 * for a chunk that surely never arrived means the deposit is gone (expired or
 * revoked): `NotFound`, and no retry can help.
 */
export async function resumeUpload(relay: Relay, upload: Upload): Promise<Result<true>> {
  for (const [index, chunk] of upload.chunks.entries()) {
    if (upload.state[index] === 'stored') continue;
    const result = await relay.putChunk(upload.id, index, chunk);
    if (result.ok || (result.error === 'NotFound' && upload.state[index] === 'unsure')) {
      upload.state[index] = 'stored';
      continue;
    }
    if (!REFUSED_BEFORE_STORING.has(result.error)) upload.state[index] = 'unsure';
    return result;
  }
  return { ok: true, value: true };
}

/**
 * Fetches the chunks still missing from `have`, in order. Chunks of a
 * burn-after-reading file are destroyed as they arrive, so `have` keeps what
 * already came: a retry after a dropped connection asks only for the rest.
 */
export async function downloadChunks(
  relay: Relay,
  id: Uint8Array,
  count: number,
  claim: Uint8Array | undefined,
  have: Uint8Array[],
): Promise<Result<Uint8Array[]>> {
  for (let index = 0; index < count; index++) {
    if (have[index] !== undefined) continue;
    const result = await relay.openChunk(id, index, claim);
    if (!result.ok) return result;
    have[index] = result.value;
  }
  return { ok: true, value: have };
}

/**
 * Hands the bytes to the browser as a download. Always as
 * application/octet-stream and never shown in this page, so a sealed HTML or
 * SVG file cannot run with Sigylo's origin.
 */
export function saveFile(name: string, bytes: Uint8Array): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: 'application/octet-stream' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.rel = 'noopener';
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
