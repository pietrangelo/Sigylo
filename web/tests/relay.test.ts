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

  it('sends account messages as base64url and reads the session back', async () => {
    const calls: Call[] = [];
    const token = new Uint8Array(32).fill(4);
    const login = await fakeRelay(200, { session: encode(token), expires_at: 99 }, calls).loginFinish(new Uint8Array(16), Uint8Array.of(1, 2));
    expect(login).toEqual({ ok: true, value: { token, expiresAt: 99 } });
    expect(calls[0]!.url).toBe('/api/account/login/finish');
    expect(JSON.parse(calls[0]!.init.body as string)).toEqual({ handle: encode(new Uint8Array(16)), finalization: 'AQI' });
  });

  it('presents the session as a bearer token, and reads an empty keyring', async () => {
    const calls: Call[] = [];
    const token = new Uint8Array(32).fill(4);
    const read = await fakeRelay(200, { keyring: null, version: 0 }, calls).readKeyring(token);
    expect(read).toEqual({ ok: true, value: { keyring: null, version: 0 } });
    expect(calls[0]!.init).toMatchObject({ method: 'GET', headers: { Authorization: `Bearer ${encode(token)}` } });
    expect(calls[0]!.init.body).toBeUndefined();
    const stored = await fakeRelay(200, { version: 3 }, calls).storeKeyring(token, Uint8Array.of(7), 2);
    expect(stored).toEqual({ ok: true, value: 3 });
    expect(JSON.parse(calls[1]!.init.body as string)).toEqual({ keyring: 'Bw', version: 2 });
  });

  it('maps account error codes', async () => {
    const token = new Uint8Array(32);
    expect(await fakeRelay(409, { error: 'Conflict' }).storeKeyring(token, Uint8Array.of(1), 0)).toEqual({ ok: false, error: 'Conflict' });
    expect(await fakeRelay(401, { error: 'Unauthorized' }).readKeyring(token)).toEqual({ ok: false, error: 'Unauthorized' });
    expect(await fakeRelay(429, { error: 'Throttled' }).loginStart('ada', new Uint8Array(96))).toEqual({ ok: false, error: 'Throttled' });
  });

  describe('adversary', () => {
    it('refuses a session token or keyring of the wrong shape', async () => {
      const short = encode(new Uint8Array(16));
      expect(await fakeRelay(200, { session: short, expires_at: 1 }).loginFinish(new Uint8Array(16), new Uint8Array(64))).toEqual({ ok: false, error: 'Unexpected' });
      for (const body of [{ keyring: 'not base64!', version: 1 }, { keyring: null, version: -1 }, { keyring: null, version: 1.5 }, { keyring: null }]) {
        expect(await fakeRelay(200, body).readKeyring(new Uint8Array(32))).toEqual({ ok: false, error: 'Unexpected' });
      }
    });

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
