import { describe, expect, it } from 'vitest';
import { encode } from '../src/lib/base64url';
import type { SeedStore } from '../src/lib/identity';
import {
  EMPTY,
  MAX_SEALS,
  addSeal,
  parseKeyring,
  pruneExpired,
  raiseWatermark,
  readWatermark,
  removeSeal,
  serializeKeyring,
  watermarkSlot,
  type Seal,
} from '../src/lib/keyring';

function seal(n: number, expires = 2_000_000_000): Seal {
  const id = new Uint8Array(16).fill(7);
  id.set([n & 0xff, n >> 8]);
  return { id: encode(id), token: encode(new Uint8Array(32).fill(n & 0xff)), sealed: 1_700_000_000 + n, expires };
}

describe('keyring', () => {
  it('round-trips through its text form', () => {
    const keyring = addSeal(addSeal(EMPTY, seal(1)), seal(2));
    expect(parseKeyring(serializeKeyring(keyring))).toEqual(keyring);
  });

  it('keeps the newest seal first and replaces one with the same id', () => {
    const keyring = addSeal(addSeal(addSeal(EMPTY, seal(1)), seal(2)), { ...seal(1), expires: 5 });
    expect(keyring.seals.map((s) => s.sealed)).toEqual([seal(1).sealed, seal(2).sealed]);
    expect(keyring.seals[0]!.expires).toBe(5);
  });

  it('forgets removed and expired seals', () => {
    const keyring = addSeal(addSeal(EMPTY, seal(1, 100)), seal(2, 300));
    expect(removeSeal(keyring, seal(2).id).seals).toEqual([seal(1, 100)]);
    expect(pruneExpired(keyring, 200).seals).toEqual([seal(2, 300)]);
  });

  it('keeps at most MAX_SEALS, dropping the oldest', () => {
    let keyring = EMPTY;
    for (let i = 0; i < MAX_SEALS + 5; i++) keyring = addSeal(keyring, seal(i));
    expect(keyring.seals.length).toBe(MAX_SEALS);
    expect(keyring.seals.at(-1)).toEqual(seal(5));
    expect(new TextEncoder().encode(serializeKeyring(keyring)).length).toBeLessThan(60 * 1024);
  });

  it('carries its generation through every change; a keyring from before generations reads as 0', () => {
    const keyring = { ...addSeal(EMPTY, seal(1)), gen: 7 };
    expect(parseKeyring(serializeKeyring(keyring))).toEqual(keyring);
    expect(addSeal(keyring, seal(2)).gen).toBe(7);
    expect(removeSeal(keyring, seal(1).id).gen).toBe(7);
    expect(pruneExpired(keyring, 0).gen).toBe(7);
    expect(parseKeyring(JSON.stringify({ v: 1, seals: [seal(1)] }))).toEqual({ v: 1, gen: 0, seals: [seal(1)] });
  });

  it('never mutates the keyring it was given', () => {
    const keyring = addSeal(EMPTY, seal(1));
    addSeal(keyring, seal(2));
    removeSeal(keyring, seal(1).id);
    expect(keyring.seals).toEqual([seal(1)]);
    expect(EMPTY.seals).toEqual([]);
  });

  describe('adversary', () => {
    it('refuses anything but a well-formed keyring', () => {
      for (const text of [
        '',
        'null',
        '[]',
        '{"v":2,"seals":[]}',
        '{"v":1}',
        '{"v":1,"seals":{}}',
        '{"v":1,"seals":[],"extra":1}',
        JSON.stringify({ v: 1, seals: [{ ...seal(1), id: 'AAEC' }] }),
        JSON.stringify({ v: 1, seals: [{ ...seal(1), token: encode(new Uint8Array(31)) }] }),
        JSON.stringify({ v: 1, seals: [{ ...seal(1), expires: '2030' }] }),
        JSON.stringify({ v: 1, seals: [{ ...seal(1), link: 'https://example.org' }] }),
        JSON.stringify({ v: 1, seals: [null] }),
        '{"v":1,"gen":-1,"seals":[]}',
        '{"v":1,"gen":1.5,"seals":[]}',
        '{"v":1,"gen":"9","seals":[]}',
        '{"v":1,"gen":null,"seals":[]}',
        '{"v":1,"gen":9007199254740992,"seals":[]}',
        '{"v":1,"gen":1,"seals":[],"extra":1}',
        '{"v":1,"gen":1}',
      ]) {
        expect(parseKeyring(text), text).toBeNull();
      }
    });

    it('a parsed keyring shares nothing with the attacker-controlled input', () => {
      const parsed = parseKeyring(serializeKeyring(addSeal(EMPTY, seal(1))))!;
      expect(Object.getPrototypeOf(parsed.seals[0])).toBe(Object.prototype);
      expect(parseKeyring('{"v":1,"seals":[],"__proto__":{"x":1}}')).toBeNull();
      expect(parseKeyring('{"v":1,"seals":[],"__proto__":{"gen":1}}')).toBeNull();
    });
  });
});

class MemoryStore implements SeedStore {
  items = new Map<string, string>();
  getItem(key: string) {
    return this.items.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.items.set(key, value);
  }
}

describe('keyring watermark', () => {
  const key = new Uint8Array(32).fill(5);

  it('has one slot per keyring key, derived from it', async () => {
    const slot = await watermarkSlot(key);
    expect(slot).toMatch(/^sigylo\.keyring\.v1\.[A-Za-z0-9_-]{22}$/);
    expect(await watermarkSlot(key.slice())).toBe(slot);
    expect(await watermarkSlot(new Uint8Array(32).fill(6))).not.toBe(slot);
  });

  it('starts at 0 on a fresh device and only ever rises', async () => {
    const store = new MemoryStore();
    const slot = await watermarkSlot(key);
    expect(readWatermark(store, slot)).toBe(0);
    raiseWatermark(store, slot, 3);
    expect(readWatermark(store, slot)).toBe(3);
    raiseWatermark(store, slot, 2);
    expect(readWatermark(store, slot)).toBe(3);
    raiseWatermark(store, slot, 4);
    expect(store.items.get(slot)).toBe('4');
  });

  describe('adversary', () => {
    it('the slot reveals neither the key nor anything typed by the person', async () => {
      const slot = await watermarkSlot(key);
      expect(slot).not.toContain(encode(key).slice(0, 8));
      expect(slot).not.toContain('ada');
    });

    it('a mangled stored value reads as 0 and is replaced on the next write', async () => {
      const slot = await watermarkSlot(key);
      for (const junk of ['', '-1', '1e3', '0x10', ' 5', '5abc', '05', '1.5', '9007199254740993', 'NaN']) {
        const store = new MemoryStore();
        store.setItem(slot, junk);
        expect(readWatermark(store, slot), junk).toBe(0);
        raiseWatermark(store, slot, 2);
        expect(readWatermark(store, slot)).toBe(2);
      }
    });

    it('works without storage, or with storage that throws, without remembering anything', async () => {
      const slot = await watermarkSlot(key);
      const hostile: SeedStore = {
        getItem() {
          throw new Error('SecurityError');
        },
        setItem() {
          throw new Error('QuotaExceededError');
        },
      };
      expect(readWatermark(hostile, slot)).toBe(0);
      expect(() => raiseWatermark(hostile, slot, 5)).not.toThrow();
      expect(readWatermark(null, slot)).toBe(0);
      expect(() => raiseWatermark(null, slot, 5)).not.toThrow();
    });
  });
});
