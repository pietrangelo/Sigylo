import { describe, expect, it } from 'vitest';
import { decode, encode } from '../src/lib/base64url';
import { Accounts, normalizeUsername, type AccountEngine } from '../src/lib/account';
import type { SeedStore } from '../src/lib/identity';
import { EMPTY, addSeal, parseKeyring, readWatermark, watermarkSlot, type KeyringData, type Seal } from '../src/lib/keyring';
import { loadPass, passSlot } from '../src/lib/passes';
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
  let passes = 0;
  const fetchImpl = async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const body = init.body ? JSON.parse(init.body as string) : {};
    const reply = (status: number, json: unknown) => new Response(JSON.stringify(json), { status });
    const authorized = (init.headers as Record<string, string> | undefined)?.['Authorization'] === `Bearer ${session}`;
    switch (url) {
      case '/api/account/register/start':
        // Like the relay: a taken name gets no OPRF evaluation at all.
        if (records.has(body.username)) return reply(409, { error: 'AlreadyRegistered' });
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
        if (!records.has(parked)) return reply(401, { error: 'NotAuthentic' });
        passes += 1;
        return reply(200, { session, expires_at: 99, pass: encode(new Uint8Array(56).fill(passes)) });
      case '/api/account/keyring':
        if (!authorized) return reply(401, { error: 'Unauthorized' });
        if (init.method === 'GET') return reply(200, state);
        if (body.version !== state.version) return reply(409, { error: 'Conflict' });
        state.keyring = body.keyring;
        state.version += 1;
        return reply(200, { version: state.version });
      case '/api/account/logout':
        return reply(200, {});
      case '/api/account/logout/everywhere':
      case '/api/account/close':
        return authorized ? reply(200, {}) : reply(401, { error: 'Unauthorized' });
      default:
        return reply(404, { error: 'NotFound' });
    }
  };
  return { relay: new Relay(fetchImpl), state, fetchImpl };
}

class MemoryStore implements SeedStore {
  items = new Map<string, string>();
  getItem(key: string) {
    return this.items.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.items.set(key, value);
  }
}

/** What the relay holds, opened with the toy engine: the generation sealed inside. */
function storedKeyring(state: { keyring: string | null }, keyringKey: Uint8Array): KeyringData | null {
  return state.keyring === null ? null : parseKeyring(dec.decode(toyEngine().openLink(decode(state.keyring)!, keyringKey)));
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
    expect(updated).toEqual({ ok: true, value: { ...addSeal(EMPTY, seal(1)), gen: 1 } });
    expect(state.version).toBe(1);
    expect(dec.decode(decode(state.keyring!)!)).not.toContain('seals');
    expect(await accounts.keyring(session.value)).toEqual({ ok: true, value: { data: { ...addSeal(EMPTY, seal(1)), gen: 1 }, version: 1 } });
  });

  it('every write bumps the generation sealed inside the keyring, and this device remembers it', async () => {
    const { relay, state } = toyRelay([]);
    const store = new MemoryStore();
    const accounts = new Accounts(toyEngine(), relay, store);
    const session = await accounts.register('ada', 'correct horse battery');
    if (!session.ok) throw new Error('no session');
    await accounts.update(session.value, (k) => addSeal(k, seal(1)));
    await accounts.update(session.value, (k) => addSeal(k, seal(2)));
    expect(storedKeyring(state, session.value.keyringKey)?.gen).toBe(2);
    expect(readWatermark(store, await watermarkSlot(session.value.keyringKey))).toBe(2);
  });

  it('a keyring from before generations still opens, and its next write is generation 1', async () => {
    const { relay, state } = toyRelay([]);
    const accounts = new Accounts(toyEngine(), relay, new MemoryStore());
    const session = await accounts.register('ada', 'correct horse battery');
    if (!session.ok) throw new Error('no session');
    state.keyring = encode(toyEngine().sealWithKey(enc.encode(JSON.stringify({ v: 1, seals: [seal(1)] })), session.value.keyringKey));
    state.version = 4;
    expect(await accounts.keyring(session.value)).toEqual({ ok: true, value: { data: { v: 1, gen: 0, seals: [seal(1)] }, version: 4 } });
    await accounts.update(session.value, (k) => addSeal(k, seal(2)));
    expect(storedKeyring(state, session.value.keyringKey)).toEqual({ v: 1, gen: 1, seals: [seal(2), seal(1)] });
  });

  it('no false alarm: on a fresh device, after another device wrote, or for another account', async () => {
    const { relay, state } = toyRelay([]);
    const laptop = new MemoryStore();
    const accounts = new Accounts(toyEngine(), relay, laptop);
    const session = await accounts.register('ada', 'correct horse battery');
    if (!session.ok) throw new Error('no session');
    await accounts.update(session.value, (k) => addSeal(k, seal(1)));
    const phone = new Accounts(toyEngine(), relay, new MemoryStore());
    expect((await phone.keyring(session.value)).ok).toBe(true);
    await phone.update(session.value, (k) => addSeal(k, seal(2)));
    await phone.update(session.value, (k) => addSeal(k, seal(3)));
    expect(storedKeyring(state, session.value.keyringKey)?.gen).toBe(3);
    expect((await accounts.keyring(session.value)).ok).toBe(true);
    expect(readWatermark(laptop, await watermarkSlot(session.value.keyringKey))).toBe(3);
    // Bob, on the same laptop, starts from his own generation 0.
    const bobs = new Accounts(toyEngine(), toyRelay([]).relay, laptop);
    const bob = await bobs.register('bob', 'another long password');
    if (!bob.ok) throw new Error('no session');
    expect(await bobs.keyring(bob.value)).toEqual({ ok: true, value: { data: EMPTY, version: 0 } });
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

  it('shows the pass of the last login and keeps the new one', async () => {
    const calls: Call[] = [];
    const store = new MemoryStore();
    const accounts = new Accounts(toyEngine(), toyRelay(calls).relay, store);
    await accounts.register('ada', 'correct horse battery');
    const first = JSON.parse(calls.find((c) => c.url === '/api/account/login/start')!.init.body as string);
    expect(first.pass).toBeUndefined();
    calls.length = 0;
    await accounts.signIn('ADA', 'correct horse battery');
    const second = JSON.parse(calls[0]!.init.body as string);
    expect(second.pass).toBe(encode(new Uint8Array(56).fill(1)));
    expect(loadPass(store, await passSlot('ada'))).toEqual(new Uint8Array(56).fill(2));
  });

  it('signing out everywhere ends the session here too', async () => {
    const calls: Call[] = [];
    const accounts = new Accounts(toyEngine(), toyRelay(calls).relay, new MemoryStore());
    const session = await accounts.register('ada', 'correct horse battery');
    if (!session.ok) throw new Error('no session');
    expect(await accounts.signOutEverywhere(session.value)).toEqual({ ok: true, value: true });
    expect(calls.at(-1)!.url).toBe('/api/account/logout/everywhere');
    expect(session.value.token.every((b) => b === 0)).toBe(true);
    expect(session.value.keyringKey.every((b) => b === 0)).toBe(true);
  });

  it('closing the account forgets its pass on this device', async () => {
    const store = new MemoryStore();
    const accounts = new Accounts(toyEngine(), toyRelay([]).relay, store);
    const session = await accounts.register('ada', 'correct horse battery');
    if (!session.ok) throw new Error('no session');
    expect(loadPass(store, await passSlot('ada'))).not.toBeNull();
    expect(await accounts.close(session.value)).toEqual({ ok: true, value: true });
    expect(loadPass(store, await passSlot('ada'))).toBeNull();
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

    it('a relay serving an older keyring is caught, and the newer one is never overwritten', async () => {
      const calls: Call[] = [];
      const { relay, state } = toyRelay(calls);
      const store = new MemoryStore();
      const accounts = new Accounts(toyEngine(), relay, store);
      const session = await accounts.register('ada', 'correct horse battery');
      if (!session.ok) throw new Error('no session');
      await accounts.update(session.value, (k) => addSeal(k, seal(1)));
      const old = state.keyring;
      await accounts.update(session.value, (k) => addSeal(k, seal(2)));
      // The relay hands back the copy without seal 2, under the current version.
      state.keyring = old;
      expect(await accounts.keyring(session.value)).toEqual({ ok: false, error: 'KeyringRolledBack' });
      calls.length = 0;
      expect(await accounts.update(session.value, (k) => addSeal(k, seal(3)))).toEqual({ ok: false, error: 'KeyringRolledBack' });
      expect(calls.filter((c) => c.init.method === 'POST')).toEqual([]);
      expect(state.keyring).toBe(old);
      expect(readWatermark(store, await watermarkSlot(session.value.keyringKey))).toBe(2);
    });

    it('a relay claiming there is no keyring, once one was seen, is caught too', async () => {
      const { relay, state } = toyRelay([]);
      const accounts = new Accounts(toyEngine(), relay, new MemoryStore());
      const session = await accounts.register('ada', 'correct horse battery');
      if (!session.ok) throw new Error('no session');
      await accounts.update(session.value, (k) => addSeal(k, seal(1)));
      state.keyring = null;
      expect(await accounts.keyring(session.value)).toEqual({ ok: false, error: 'KeyringRolledBack' });
      // A keyring from before generations is generation 0: older than one already seen.
      state.keyring = encode(toyEngine().sealWithKey(enc.encode('{"v":1,"seals":[]}'), session.value.keyringKey));
      expect(await accounts.keyring(session.value)).toEqual({ ok: false, error: 'KeyringRolledBack' });
    });

    it('storage that throws turns the check off, never the keyring', async () => {
      const hostile: SeedStore = {
        getItem() {
          throw new Error('SecurityError');
        },
        setItem() {
          throw new Error('QuotaExceededError');
        },
      };
      const { relay } = toyRelay([]);
      const accounts = new Accounts(toyEngine(), relay, hostile);
      const session = await accounts.register('ada', 'correct horse battery');
      if (!session.ok) throw new Error('no session');
      expect((await accounts.update(session.value, (k) => addSeal(k, seal(1)))).ok).toBe(true);
      expect(await accounts.keyring(session.value)).toEqual({ ok: true, value: { data: { ...addSeal(EMPTY, seal(1)), gen: 1 }, version: 1 } });
    });

    it('the device keeps no trace of the name', async () => {
      const store = new MemoryStore();
      const accounts = new Accounts(toyEngine(), toyRelay([]).relay, store);
      const session = await accounts.register('ada', 'correct horse battery');
      if (!session.ok) throw new Error('no session');
      await accounts.update(session.value, (k) => addSeal(k, seal(1)));
      expect(store.items.size).toBe(2); // the device pass and the keyring watermark
      for (const [key, value] of store.items) expect(`${key} ${value}`).not.toMatch(/ada|horse/);
    });
  });
});
