import { describe, expect, it } from 'vitest';
import { fileName } from '../src/lib/crypto';
import { downloadChunks, resumeUpload, startUpload } from '../src/lib/files';
import { Relay, type RelayError } from '../src/lib/relay';

const id = new Uint8Array(16).fill(1);
const chunk = (n: number) => new Uint8Array(300).fill(n);
const uploadChunks = (relay: Relay, id: Uint8Array, chunks: Uint8Array[]) => resumeUpload(relay, startUpload(id, chunks));

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

/** What goes wrong with one attempt to put a chunk. */
type Fault = 'drop' | 'lost-reply' | RelayError;

const STATUS: Partial<Record<RelayError, number>> = { RateLimited: 429, PayloadTooLarge: 413, StorageFull: 507, VaultUnavailable: 503, Unexpected: 500 };

/**
 * A relay like the real one: each index is taken once, then 404, and a gone
 * deposit is 404 for every index. `faults` spoils the next attempts at an
 * index: the connection drops before the chunk arrives, or after it was
 * stored (the reply is lost), or the relay refuses.
 */
function flakyRelay(faults: Record<number, Fault[]> = {}) {
  const stored = new Map<number, Uint8Array>();
  const sent: number[] = [];
  const deposit = { gone: false };
  const relay = new Relay(async (url, init) => {
    const index = Number(/\/chunks\/(\d)$/.exec(url)![1]);
    sent.push(index);
    const fault = faults[index]?.shift();
    if (fault === 'drop') throw new TypeError('Failed to fetch');
    if (fault !== undefined && fault !== 'lost-reply') return new Response(JSON.stringify({ error: fault }), { status: STATUS[fault] ?? 500 });
    if (deposit.gone || stored.has(index)) return new Response('{"error":"NotFound"}', { status: 404 });
    stored.set(index, (init.body as Uint8Array).slice());
    if (fault === 'lost-reply') throw new TypeError('Failed to fetch');
    return new Response('{}', { status: 201 });
  });
  return { relay, stored, sent, deposit };
}

describe('resumable upload', () => {
  const three = () => [chunk(1), chunk(2), chunk(3)];

  it('a retry sends only the chunks the relay does not have yet, byte for byte the same', async () => {
    const { relay, stored, sent } = flakyRelay({ 1: ['RateLimited'] });
    const upload = startUpload(id, three());
    expect(await resumeUpload(relay, upload)).toEqual({ ok: false, error: 'RateLimited' });
    expect(upload.state).toEqual(['stored', 'missing', 'missing']);
    expect(await resumeUpload(relay, upload)).toEqual({ ok: true, value: true });
    expect(sent).toEqual([0, 1, 1, 2]);
    expect([...stored.entries()]).toEqual([
      [0, chunk(1)],
      [1, chunk(2)],
      [2, chunk(3)],
    ]);
    expect(upload.state).toEqual(['stored', 'stored', 'stored']);
  });

  it('a connection dropped before the chunk arrived just sends it again', async () => {
    const { relay, stored } = flakyRelay({ 1: ['drop'] });
    const upload = startUpload(id, three());
    expect(await resumeUpload(relay, upload)).toEqual({ ok: false, error: 'Network' });
    expect(upload.state[1]).toBe('unsure');
    expect(await resumeUpload(relay, upload)).toEqual({ ok: true, value: true });
    expect(stored.size).toBe(3);
  });

  it('a finished upload sends nothing more', async () => {
    const { relay, sent } = flakyRelay();
    const upload = startUpload(id, three());
    await resumeUpload(relay, upload);
    sent.length = 0;
    expect(await resumeUpload(relay, upload)).toEqual({ ok: true, value: true });
    expect(sent).toEqual([]);
  });

  describe('adversary', () => {
    it('a chunk stored before its reply was lost answers 404 on the retry: it is taken as in', async () => {
      const { relay, stored, sent } = flakyRelay({ 1: ['lost-reply'] });
      const upload = startUpload(id, three());
      expect(await resumeUpload(relay, upload)).toEqual({ ok: false, error: 'Network' });
      expect(await resumeUpload(relay, upload)).toEqual({ ok: true, value: true });
      expect(sent).toEqual([0, 1, 1, 2]);
      expect(stored.get(1)).toEqual(chunk(2));
    });

    it('a server error may come after the chunk was stored, so it counts as maybe in', async () => {
      for (const error of ['VaultUnavailable', 'Unexpected'] as const) {
        const upload = startUpload(id, three());
        expect(await resumeUpload(flakyRelay({ 0: [error] }).relay, upload)).toEqual({ ok: false, error });
        expect(upload.state[0], error).toBe('unsure');
      }
    });

    it('a 404 for a chunk that never reached the relay means the upload is gone', async () => {
      for (const error of ['RateLimited', 'StorageFull', 'PayloadTooLarge'] as const) {
        const { relay, deposit, sent } = flakyRelay({ 1: [error] });
        const upload = startUpload(id, three());
        expect(await resumeUpload(relay, upload)).toEqual({ ok: false, error });
        expect(upload.state[1], error).toBe('missing');
        deposit.gone = true;
        expect(await resumeUpload(relay, upload)).toEqual({ ok: false, error: 'NotFound' });
        expect(sent).toEqual([0, 1, 1]);
      }
    });

    it('a refusal after a lost reply does not make the chunk certainly missing', async () => {
      const { relay, deposit } = flakyRelay({ 1: ['lost-reply', 'RateLimited'] });
      const upload = startUpload(id, three());
      await resumeUpload(relay, upload);
      expect(await resumeUpload(relay, upload)).toEqual({ ok: false, error: 'RateLimited' });
      expect(upload.state[1]).toBe('unsure');
      // Expired meanwhile: the unsure chunk cannot tell, the next one can.
      deposit.gone = true;
      expect(await resumeUpload(relay, upload)).toEqual({ ok: false, error: 'NotFound' });
      expect(upload.state).toEqual(['stored', 'stored', 'missing']);
    });

    it('the upload keeps its own copy of the list, not the caller\'s', async () => {
      const chunks = three();
      const upload = startUpload(id, chunks);
      chunks.length = 0;
      expect(upload.chunks.length).toBe(3);
      expect(upload.state.length).toBe(3);
    });
  });
});

describe('fileName', () => {
  it('normalizes to NFC', () => {
    expect(fileName('été.txt')).toBe('été.txt');
  });

  it('turns what Windows refuses into underscores, so ordinary names seal', () => {
    expect(fileName('Q&A: why?.txt')).toBe('Q&A_ why_.txt');
    expect(fileName('a<b>|"c"*.md')).toBe('a_b___c__.md');
  });

  it('drops emoji presentation selectors, which draw nothing', () => {
    expect(fileName('❤️ foto.png')).toBe('❤ foto.png');
  });

  it('leaves anything that hides to the engine, which refuses it', () => {
    expect(fileName('invoice‮fdp.exe')).toBe('invoice‮fdp.exe');
  });
});
