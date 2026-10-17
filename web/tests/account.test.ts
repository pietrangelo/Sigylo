import { describe, expect, it } from 'vitest';
import { decode, encode } from '../src/lib/base64url';
import { Accounts, normalizeUsername, type AccountEngine } from '../src/lib/account';
import { EMPTY, addSeal, type Seal } from '../src/lib/keyring';
import { Relay } from '../src/lib/relay';

// A toy engine and a toy relay: enough OPAQUE-shaped behaviour to test the
// orchestration (what is sent, what stays here), not the cryptography.
const enc = new TextEncoder();
const dec = new TextDecoder();

function tag(bytes: Uint8Array): number {
  return bytes.reduce((h, b) => (h * 31 + b) >>> 0, 7);
}

function toyEngine(): AccountEngine {
  const pending = (password: Uint8Array, kind: 'reg' | 'login') => ({
    // Registration answers never authenticate; login answers carry the record byte.
    request: new Uint8Array(kind === 'reg' ? 32 : 96).fill(1),
    finish(response: Uint8Array) {
      if (kind === 'login' && response[0] !== (tag(password) & 0xff)) throw new Error('NotAuthentic');
      return { message: new Uint8Array(kind === 'reg' ? 192 : 64).fill(tag(password) & 0xff), keyringKey: new Uint8Array(32).fill(tag(password) & 0x7f), free() {} };
    },
    free() {},
  });
  return {
    beginRegistration: (pw) => {
      if (pw.length < 8) throw new Error('InvalidPassword');
      return pending(pw, 'reg');
    },
    beginLogin: (pw) => pending(pw, 'login'),
    sealWithKey: (plaintext, key) => Uint8Array.of(0x53, key[0]!, ...plaintext.map((b) => b ^ key[0]!)),
    openLink: (envelope, key) => {
      if (envelope[0] !== 0x53 || envelope[1] !== key[0]) throw new Error('NotAuthentic');
      return envelope.slice(2).map((b) => b ^ key[0]!);
    },
  };
}

type Call = { url: string; init: RequestInit };

/** The relay: accounts by name, one session, one keyring with a version. */
function toyRelay(calls: Call[]) {
  const records = new Map<string, number>();
  const state = { keyring: null as string | null, version: 0 };
  const session = encode(new Uint8Array(32).fill(9));
  let parked = '';
  const fetchImpl = async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const body = init.body ? JSON.parse(init.body as string) : {};
    const reply = (status: number, json: unknown) => new Response(JSON.stringify(json), { status });
    const authorized = (init.headers as Record<string, string> | undefined)?.['Authorization'] === `Bearer ${session}`;
    switch (url) {
      case '/api/account/register/start':
        return reply(200, { response: encode(new Uint8Array(64)) });
      case '/api/account/register/finish':
        if (records.has(body.username)) return reply(409, { error: 'AlreadyRegistered' });
        records.set(body.username, decode(body.record)![0]!);
        return reply(201, {});
      case '/api/account/login/start': {
        const response = new Uint8Array(320).fill(records.get(body.username) ?? 0xee);
        parked = body.username;
        return reply(200, { handle: encode(new Uint8Array(16)), response: encode(response) });
      }
      case '/api/account/login/finish':
        return records.has(parked) ? reply(200, { session, expires_at: 99 }) : reply(401, { error: 'NotAuthentic' });
      case '/api/account/keyring':
        if (!authorized) return reply(401, { error: 'Unauthorized' });
        if (init.method === 'GET') return reply(200, state);
        if (body.version !== state.version) return reply(409, { error: 'Conflict' });
        state.keyring = body.keyring;
        state.version += 1;
        return reply(200, { version: state.version });
      case '/api/account/logout':
        return reply(200, {});
      default:
        return reply(404, { error: 'NotFound' });
    }
  };
  return { relay: new Relay(fetchImpl), state, fetchImpl };
}

function seal(n: number): Seal {
  return { id: encode(new Uint8Array(16).fill(n)), token: encode(new Uint8Array(32).fill(n)), sealed: 1, expires: 4_000_000_000 };
}

describe('accounts', () => {
  it('registers, signs in and comes back with a session and the keyring key', async () => {
    const calls: Call[] = [];
    const accounts = new Accounts(toyEngine(), toyRelay(calls).relay);
    const result = await accounts.register('Ada ', 'correct horse battery');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.username).toBe('ada');
    expect(result.value.token).toEqual(new Uint8Array(32).fill(9));
    expect(result.value.keyringKey.length).toBe(32);
    expect(calls.map((c) => c.url)).toEqual([
      '/api/account/register/start',
      '/api/account/register/finish',
      '/api/account/login/start',
      '/api/account/login/finish',
    ]);
  });

  it('a wrong password fails on the device: KE3 is never sent', async () => {
    const calls: Call[] = [];
    const accounts = new Accounts(toyEngine(), toyRelay(calls).relay);
    await accounts.register('ada', 'correct horse battery');
    calls.length = 0;
    expect(await accounts.signIn('ada', 'wrong horse battery')).toEqual({ ok: false, error: 'NotAuthentic' });
    expect(calls.map((c) => c.url)).toEqual(['/api/account/login/start']);
  });

  it('passes the relay verdicts through', async () => {
    const accounts = new Accounts(toyEngine(), toyRelay([]).relay);
    await accounts.register('ada', 'correct horse battery');
    expect(await accounts.register('ADA', 'another password')).toEqual({ ok: false, error: 'AlreadyRegistered' });
    expect(await accounts.register('bob', 'short')).toEqual({ ok: false, error: 'InvalidPassword' });
  });

  it('seals the keyring on this device and reads it back', async () => {
    const calls: Call[] = [];
    const { relay, state } = toyRelay(calls);
    const accounts = new Accounts(toyEngine(), relay);
    const session = await accounts.register('ada', 'correct horse battery');
    if (!session.ok) throw new Error('no session');
    const updated = await accounts.update(session.value, (k) => addSeal(k, seal(1)));
    expect(updated).toEqual({ ok: true, value: addSeal(EMPTY, seal(1)) });
    expect(state.version).toBe(1);
    expect(dec.decode(decode(state.keyring!)!)).not.toContain('seals');
    expect(await accounts.keyring(session.value)).toEqual({ ok: true, value: { data: addSeal(EMPTY, seal(1)), version: 1 } });
  });

  it('when another device wrote meanwhile, re-applies the change on top of it', async () => {
    const { relay, state, fetchImpl } = toyRelay([]);
    const accounts = new Accounts(toyEngine(), relay);
    const session = await accounts.register('ada', 'correct horse battery');
    if (!session.ok) throw new Error('no session');
    const phone = new Accounts(toyEngine(), relay);
    await phone.update(session.value, (k) => addSeal(k, seal(1)));
    // The phone adds seal 2 just as this tab is about to store seal 3.
    let raced = false;
    const racing = new Accounts(toyEngine(), new Relay(async (url, init) => {
      if (url === '/api/account/keyring' && init.method === 'POST' && !raced) {
        raced = true;
        await phone.update(session.value, (k) => addSeal(k, seal(2)));
      }
      return fetchImpl(url, init);
    }));
    const result = await racing.update(session.value, (k) => addSeal(k, seal(3)));
    expect(result.ok).toBe(true);
    const ids = await accounts.keyring(session.value);
    expect(ids.ok && ids.value.data.seals.map((s) => s.id)).toEqual([seal(3).id, seal(2).id, seal(1).id]);
    expect(state.version).toBe(3);
  });

  it('signing out wipes the token and the keyring key from this tab', async () => {
    const accounts = new Accounts(toyEngine(), toyRelay([]).relay);
    const session = await accounts.register('ada', 'correct horse battery');
    if (!session.ok) throw new Error('no session');
    await accounts.signOut(session.value);
    expect(session.value.token.every((b) => b === 0)).toBe(true);
    expect(session.value.keyringKey.every((b) => b === 0)).toBe(true);
  });

  it('normalizes names the way the relay compares them', () => {
    expect(normalizeUsername(' Élodie ')).toBe('élodie');
    expect(normalizeUsername('ÉLODIE')).toBe('élodie');
  });

  describe('adversary', () => {
    it('the password never leaves the device, in any request or header', async () => {
      const calls: Call[] = [];
      const accounts = new Accounts(toyEngine(), toyRelay(calls).relay);
      const session = await accounts.register('ada', 'correct horse battery');
      if (!session.ok) throw new Error('no session');
      await accounts.update(session.value, (k) => addSeal(k, seal(1)));
      await accounts.signIn('ada', 'correct horse battery');
      for (const { init } of calls) {
        const wire = `${String(init.body ?? '')} ${JSON.stringify(init.headers ?? {})}`;
        expect(wire).not.toContain('horse');
        expect(wire).not.toContain(encode(enc.encode('correct horse battery')));
        expect(init).toMatchObject({ credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' });
      }
    });

    it('a keyring sealed under another key is refused, not half-read', async () => {
      const { relay, state } = toyRelay([]);
      const accounts = new Accounts(toyEngine(), relay);
      const session = await accounts.register('ada', 'correct horse battery');
      if (!session.ok) throw new Error('no session');
      state.keyring = encode(Uint8Array.of(0x53, 0x01, 0x02));
      state.version = 1;
      expect(await accounts.keyring(session.value)).toEqual({ ok: false, error: 'KeyringUnreadable' });
      const garbage = toyEngine().sealWithKey(enc.encode('{"v":1,"seals":[{"id":"x"}]}'), session.value.keyringKey);
      state.keyring = encode(garbage);
      expect(await accounts.keyring(session.value)).toEqual({ ok: false, error: 'KeyringUnreadable' });
    });
  });
});
