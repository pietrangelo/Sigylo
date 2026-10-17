import { describe, expect, it } from 'vitest';
import { encode } from '../src/lib/base64url';
import { Relay } from '../src/lib/relay';

type Call = { url: string; init: RequestInit };

function fakeRelay(status: number, body: unknown, calls: Call[] = []): Relay {
  return new Relay(async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status });
  });
}

const id = new Uint8Array(16).fill(1);

describe('relay client', () => {
  it('deposits base64url fields and returns the id the relay chose', async () => {
    const calls: Call[] = [];
    const result = await fakeRelay(201, { id: encode(id), expires_at: 42 }, calls).deposit(Uint8Array.of(1, 2), 'burn_after_reading', 3600, new Uint8Array(32));
    expect(result).toEqual({ ok: true, value: { id, expiresAt: 42 } });
    expect(calls[0]!.url).toBe('/api/secrets');
    expect(JSON.parse(calls[0]!.init.body as string)).toEqual({
      payload: 'AQI',
      retention: 'burn_after_reading',
      lifetime_seconds: 3600,
      revocation_token: encode(new Uint8Array(32)),
    });
  });

  it('posts a request and returns the id the relay chose', async () => {
    const calls: Call[] = [];
    const result = await fakeRelay(201, { id: encode(id), expires_at: 7 }, calls).postRequest(Uint8Array.of(9), 3600);
    expect(result).toEqual({ ok: true, value: { id, expiresAt: 7 } });
    expect(JSON.parse(calls[0]!.init.body as string)).toEqual({ recipient_key: 'CQ', lifetime_seconds: 3600 });
  });

  it('decodes an opened envelope', async () => {
    const result = await fakeRelay(200, { payload: 'AQI', burned: true }).open(id);
    expect(result).toEqual({ ok: true, value: { envelope: Uint8Array.of(1, 2), burned: true } });
  });

  it('maps relay error codes', async () => {
    expect(await fakeRelay(404, { error: 'NotFound' }).open(id)).toEqual({ ok: false, error: 'NotFound' });
    expect(await fakeRelay(429, { error: 'RateLimited' }).open(id)).toEqual({ ok: false, error: 'RateLimited' });
  });

  describe('adversary', () => {
    it('opens with POST, without credentials or referrer, never cached', async () => {
      const calls: Call[] = [];
      await fakeRelay(200, { payload: 'AQI', burned: true }, calls).open(id);
      expect(calls[0]!.init).toMatchObject({ method: 'POST', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' });
      expect(calls[0]!.url).toBe(`/api/secrets/${encode(id)}/open`);
    });

    it('treats malformed or unknown responses as errors, not data', async () => {
      expect(await fakeRelay(200, { payload: 'not base64!', burned: true }).open(id)).toEqual({ ok: false, error: 'Unexpected' });
      expect(await fakeRelay(200, { payload: 'AQI' }).open(id)).toEqual({ ok: false, error: 'Unexpected' });
      expect(await fakeRelay(500, { error: '<script>' }).open(id)).toEqual({ ok: false, error: 'Unexpected' });
    });

    it('never sends an id of its own and refuses a receipt without a proper one', async () => {
      const calls: Call[] = [];
      await fakeRelay(201, { id: encode(id), expires_at: 42 }, calls).deposit(Uint8Array.of(1), 'until_expiry', 300, new Uint8Array(32));
      expect(JSON.parse(calls[0]!.init.body as string)).not.toHaveProperty('id');
      for (const receipt of [{ expires_at: 42 }, { id: 'AAEC', expires_at: 42 }, { id: encode(id) }]) {
        expect(await fakeRelay(201, receipt).deposit(Uint8Array.of(1), 'until_expiry', 300, new Uint8Array(32))).toEqual({ ok: false, error: 'Unexpected' });
      }
    });

    it('reports network failures without throwing', async () => {
      const relay = new Relay(async () => {
        throw new TypeError('offline');
      });
      expect(await relay.open(id)).toEqual({ ok: false, error: 'Network' });
    });
  });
});
