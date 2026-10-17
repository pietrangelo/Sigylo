import { describe, expect, it } from 'vitest';
import { encode } from '../src/lib/base64url';
import { EMPTY, MAX_SEALS, addSeal, parseKeyring, pruneExpired, removeSeal, serializeKeyring, type Seal } from '../src/lib/keyring';

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
      ]) {
        expect(parseKeyring(text), text).toBeNull();
      }
    });

    it('a parsed keyring shares nothing with the attacker-controlled input', () => {
      const parsed = parseKeyring(serializeKeyring(addSeal(EMPTY, seal(1))))!;
      expect(Object.getPrototypeOf(parsed.seals[0])).toBe(Object.prototype);
      expect(parseKeyring('{"v":1,"seals":[],"__proto__":{"x":1}}')).toBeNull();
    });
  });
});
