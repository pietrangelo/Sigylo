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
const inbox = new Uint8Array(16).fill(2);

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

  it('posts a request and returns its public id and private inbox, both chosen by the relay', async () => {
    const calls: Call[] = [];
    const result = await fakeRelay(201, { id: encode(id), inbox: encode(inbox), expires_at: 7 }, calls).postRequest(Uint8Array.of(9), 3600);
    expect(result).toEqual({ ok: true, value: { id, inbox, expiresAt: 7 } });
    expect(JSON.parse(calls[0]!.init.body as string)).toEqual({ recipient_key: 'CQ', lifetime_seconds: 3600 });
  });

  it('decodes an opened envelope', async () => {
    const result = await fakeRelay(200, { payload: 'AQI', burned: true }).open(id);
    expect(result).toEqual({ ok: true, value: { envelope: Uint8Array.of(1, 2), burned: true } });
  });

  it('deposits a file manifest with its chunk count, and answers a request with one', async () => {
    const calls: Call[] = [];
    await fakeRelay(201, { id: encode(id), expires_at: 42 }, calls).deposit(Uint8Array.of(1, 2), 'until_expiry', 300, new Uint8Array(32), 3);
    expect(JSON.parse(calls[0]!.init.body as string)).toMatchObject({ payload: 'AQI', chunks: 3 });
    await fakeRelay(201, { id: encode(inbox), expires_at: 42 }, calls).answer(id, Uint8Array.of(1), 'until_expiry', 300, 2);
    expect(JSON.parse(calls[1]!.init.body as string)).toMatchObject({ chunks: 2 });
    await fakeRelay(201, { id: encode(inbox), expires_at: 42 }, calls).answer(id, Uint8Array.of(1), 'until_expiry', 300);
    expect(JSON.parse(calls[2]!.init.body as string)).not.toHaveProperty('chunks');
  });

  it('learns from an answer where its chunks go, and refuses a receipt without that', async () => {
    // The sender uploads a file answer's chunks to the inbox, never to the public request id.
    const answered = await fakeRelay(201, { id: encode(inbox), expires_at: 42 }).answer(id, Uint8Array.of(1), 'until_expiry', 300, 2);
    expect(answered).toEqual({ ok: true, value: { id: inbox, expiresAt: 42 } });
    for (const body of [{ expires_at: 42 }, { id: 'AAEC', expires_at: 42 }]) {
      expect(await fakeRelay(201, body).answer(id, Uint8Array.of(1), 'until_expiry', 300)).toEqual({ ok: false, error: 'Unexpected' });
    }
  });

  it('decodes an opened file with its chunk count and claim', async () => {
    const claim = new Uint8Array(32).fill(5);
    const result = await fakeRelay(200, { payload: 'AQI', burned: true, chunks: 2, claim: encode(claim) }).open(id);
    expect(result).toEqual({ ok: true, value: { envelope: Uint8Array.of(1, 2), burned: true, chunks: 2, claim } });
    const lasting = await fakeRelay(200, { payload: 'AQI', burned: false, chunks: 4 }).open(id);
    expect(lasting).toEqual({ ok: true, value: { envelope: Uint8Array.of(1, 2), burned: false, chunks: 4 } });
  });

  it('uploads a chunk as raw bytes and fetches one back with the claim', async () => {
    const calls: Call[] = [];
    const chunk = new Uint8Array(300).fill(7);
    const up = await new Relay(async (url, init) => {
      calls.push({ url, init });
      return new Response('{}', { status: 201 });
    }).putChunk(id, 4, chunk);
    expect(up).toEqual({ ok: true, value: true });
    expect(calls[0]!.url).toBe(`/api/secrets/${encode(id)}/chunks/4`);
    expect(calls[0]!.init).toMatchObject({ method: 'POST', body: chunk, credentials: 'omit', referrerPolicy: 'no-referrer' });

    const claim = new Uint8Array(32).fill(9);
    const down = await new Relay(async (url, init) => {
      calls.push({ url, init });
      return new Response(chunk, { status: 200 });
    }).openChunk(id, 1, claim);
    expect(down).toEqual({ ok: true, value: chunk });
    expect(calls[1]!.url).toBe(`/api/secrets/${encode(id)}/chunks/1/open`);
    expect(JSON.parse(calls[1]!.init.body as string)).toEqual({ claim: encode(claim) });
  });

  it('maps relay error codes', async () => {
    expect(await fakeRelay(404, { error: 'NotFound' }).open(id)).toEqual({ ok: false, error: 'NotFound' });
    expect(await fakeRelay(429, { error: 'RateLimited' }).open(id)).toEqual({ ok: false, error: 'RateLimited' });
    expect(await fakeRelay(507, { error: 'StorageFull' }).postRequest(id, 300)).toEqual({ ok: false, error: 'StorageFull' });
  });

  it('sends account messages as base64url and reads the session back', async () => {
    const calls: Call[] = [];
    const token = new Uint8Array(32).fill(4);
    const login = await fakeRelay(200, { session: encode(token), expires_at: 99 }, calls).loginFinish(new Uint8Array(16), Uint8Array.of(1, 2));
    expect(login).toEqual({ ok: true, value: { token, expiresAt: 99, pass: null } });
    expect(calls[0]!.url).toBe('/api/account/login/finish');
    expect(JSON.parse(calls[0]!.init.body as string)).toEqual({ handle: encode(new Uint8Array(16)), finalization: 'AQI' });
  });

  it('carries the device pass both ways, and signs out everywhere with the bearer', async () => {
    const calls: Call[] = [];
    const pass = new Uint8Array(56).fill(6);
    await fakeRelay(200, { handle: 'AA', response: 'AA' }, calls).loginStart('ada', new Uint8Array(96), pass);
    expect(JSON.parse(calls[0]!.init.body as string).pass).toBe(encode(pass));
    await fakeRelay(200, { handle: 'AA', response: 'AA' }, calls).loginStart('ada', new Uint8Array(96));
    expect(JSON.parse(calls[1]!.init.body as string)).not.toHaveProperty('pass');
    const token = new Uint8Array(32).fill(4);
    const granted = await fakeRelay(200, { session: encode(token), expires_at: 9, pass: encode(pass) }).loginFinish(new Uint8Array(16), new Uint8Array(64));
    expect(granted).toEqual({ ok: true, value: { token, expiresAt: 9, pass } });
    const odd = await fakeRelay(200, { session: encode(token), expires_at: 9, pass: 'AAAA' }).loginFinish(new Uint8Array(16), new Uint8Array(64));
    expect(odd).toEqual({ ok: true, value: { token, expiresAt: 9, pass: null } });
    expect(await fakeRelay(200, {}, calls).logoutEverywhere(token)).toEqual({ ok: true, value: true });
    expect(calls[2]!.url).toBe('/api/account/logout/everywhere');
    expect(calls[2]!.init).toMatchObject({ method: 'POST', headers: { Authorization: `Bearer ${encode(token)}` } });
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

    it('refuses a request receipt whose inbox is missing, malformed or the public id', async () => {
      // An inbox equal to the request id would let the request link burn the answer.
      for (const receipt of [
        { id: encode(id), expires_at: 7 },
        { id: encode(id), inbox: 'AAEC', expires_at: 7 },
        { id: encode(id), inbox: encode(id), expires_at: 7 },
      ]) {
        expect(await fakeRelay(201, receipt).postRequest(new Uint8Array([9]), 3600)).toEqual({ ok: false, error: 'Unexpected' });
      }
    });

    it('refuses an expiry that is not a whole positive number of seconds, from every reader', async () => {
      // A fractional or out-of-range expiry would be written into the account
      // keyring, whose strict parser would then refuse the keyring for good.
      const token = new Uint8Array(32).fill(4);
      for (const expires_at of [1.5, 0, -1, 2 ** 53, 1e300, '42', null, true]) {
        const unexpected = { ok: false, error: 'Unexpected' };
        const receipt = { id: encode(id), inbox: encode(inbox), expires_at };
        expect(await fakeRelay(201, receipt).deposit(Uint8Array.of(1), 'until_expiry', 300, new Uint8Array(32)), `deposit ${expires_at}`).toEqual(unexpected);
        expect(await fakeRelay(201, receipt).answer(id, Uint8Array.of(1), 'until_expiry', 300), `answer ${expires_at}`).toEqual(unexpected);
        expect(await fakeRelay(201, receipt).postRequest(Uint8Array.of(9), 3600), `request ${expires_at}`).toEqual(unexpected);
        expect(await fakeRelay(200, { recipient_key: 'CQ', expires_at }).fetchRequest(id), `fetch ${expires_at}`).toEqual(unexpected);
        const session = { session: encode(token), expires_at };
        expect(await fakeRelay(200, session).loginFinish(new Uint8Array(16), new Uint8Array(64)), `login ${expires_at}`).toEqual(unexpected);
      }
      // The largest safe integer is still a valid expiry.
      const far = await fakeRelay(200, { recipient_key: 'CQ', expires_at: Number.MAX_SAFE_INTEGER }).fetchRequest(id);
      expect(far).toEqual({ ok: true, value: { publicKey: Uint8Array.of(9), expiresAt: Number.MAX_SAFE_INTEGER } });
    });

    it('refuses opened files whose count or claim is malformed', async () => {
      for (const body of [
        { payload: 'AQI', burned: true, chunks: 0 },
        { payload: 'AQI', burned: true, chunks: 1.5 },
        { payload: 'AQI', burned: true, chunks: '2' },
        { payload: 'AQI', burned: true, chunks: 2, claim: 'AAEC' },
        { payload: 'AQI', burned: true, claim: encode(new Uint8Array(32)) },
      ]) {
        expect(await fakeRelay(200, body).open(id)).toEqual({ ok: false, error: 'Unexpected' });
      }
    });

    it('treats an empty or failed chunk download as an error', async () => {
      const empty = new Relay(async () => new Response(new Uint8Array(0), { status: 200 }));
      expect(await empty.openChunk(id, 0)).toEqual({ ok: false, error: 'Unexpected' });
      expect(await fakeRelay(404, { error: 'NotFound' }).openChunk(id, 0)).toEqual({ ok: false, error: 'NotFound' });
      expect(await fakeRelay(507, { error: 'StorageFull' }).putChunk(id, 0, Uint8Array.of(1))).toEqual({ ok: false, error: 'StorageFull' });
    });

    it('reports network failures without throwing', async () => {
      const relay = new Relay(async () => {
        throw new TypeError('offline');
      });
      expect(await relay.open(id)).toEqual({ ok: false, error: 'Network' });
      expect(await relay.putChunk(id, 0, Uint8Array.of(1))).toEqual({ ok: false, error: 'Network' });
      expect(await relay.openChunk(id, 0)).toEqual({ ok: false, error: 'Network' });
    });
  });
});
