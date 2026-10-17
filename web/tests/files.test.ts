import { describe, expect, it } from 'vitest';
import { downloadChunks, uploadChunks } from '../src/lib/files';
import { Relay } from '../src/lib/relay';

const id = new Uint8Array(16).fill(1);
const chunk = (n: number) => new Uint8Array(300).fill(n);

/** A relay that keeps uploaded chunks and hands each one out once (burn after reading). */
function burningRelay(failAt?: number) {
  const stored = new Map<number, Uint8Array>();
  const asked: number[] = [];
  const relay = new Relay(async (url, init) => {
    const match = /\/chunks\/(\d+)(\/open)?$/.exec(url);
    const index = Number(match![1]);
    if (match![2] === undefined) {
      if (index === failAt) return new Response('{"error":"VaultUnavailable"}', { status: 503 });
      stored.set(index, init.body as Uint8Array);
      return new Response('{}', { status: 201 });
    }
    asked.push(index);
    const found = stored.get(index);
    if (found === undefined || index === failAt) return new Response('{"error":"NotFound"}', { status: 404 });
    stored.delete(index);
    return new Response(found as BodyInit, { status: 200 });
  });
  return { relay, stored, asked };
}

describe('files', () => {
  it('uploads every chunk in order and downloads them back', async () => {
    const { relay, stored } = burningRelay();
    expect(await uploadChunks(relay, id, [chunk(1), chunk(2), chunk(3)])).toEqual({ ok: true, value: true });
    expect([...stored.keys()]).toEqual([0, 1, 2]);
    const result = await downloadChunks(relay, id, 3, undefined, []);
    expect(result).toEqual({ ok: true, value: [chunk(1), chunk(2), chunk(3)] });
  });

  it('stops uploading at the first refusal', async () => {
    const { relay, stored } = burningRelay(1);
    expect(await uploadChunks(relay, id, [chunk(1), chunk(2), chunk(3)])).toEqual({ ok: false, error: 'VaultUnavailable' });
    expect([...stored.keys()]).toEqual([0]);
  });

  describe('adversary', () => {
    it('a retry after a dropped download asks only for the chunks still missing', async () => {
      // Burning chunks come once: asking again for one already received would fail.
      const { relay, asked } = burningRelay();
      await uploadChunks(relay, id, [chunk(1), chunk(2), chunk(3)]);
      const first = await relay.openChunk(id, 0);
      const have = first.ok ? [first.value] : [];
      const result = await downloadChunks(relay, id, 3, undefined, have);
      expect(result).toEqual({ ok: true, value: [chunk(1), chunk(2), chunk(3)] });
      expect(asked).toEqual([0, 1, 2]);
    });

    it('a missing chunk is reported, not papered over', async () => {
      const { relay } = burningRelay(2);
      await uploadChunks(relay, id, [chunk(1), chunk(2)]);
      const have: Uint8Array[] = [];
      expect(await downloadChunks(relay, id, 3, undefined, have)).toEqual({ ok: false, error: 'NotFound' });
      expect(have).toEqual([chunk(1), chunk(2)]);
    });
  });
});
