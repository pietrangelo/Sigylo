// Files travel as a sealed manifest, deposited like any secret, followed by
// sealed chunks of 1 MiB (see crates/sealing/src/core/file.rs). Chunks go up
// and come down one request at a time, in order: a 10 MB file costs eleven
// requests each way, well inside the relay's rate limit.

import type { Relay, Result } from './relay';

/** Largest file Sigylo seals: 10 MiB, ten chunks. */
export const MAX_FILE_LEN = 10 * 1024 * 1024;

/** Uploads every chunk in order, stopping at the first refusal. */
export async function uploadChunks(relay: Relay, id: Uint8Array, chunks: readonly Uint8Array[]): Promise<Result<true>> {
  for (const [index, chunk] of chunks.entries()) {
    const result = await relay.putChunk(id, index, chunk);
    if (!result.ok) return result;
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
