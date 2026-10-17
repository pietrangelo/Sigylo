import { describe, expect, it } from 'vitest';
import { decode, decodeExact, encode } from '../src/lib/base64url';

describe('base64url', () => {
  it('roundtrips every length around the 3-byte boundary', () => {
    for (let len = 0; len < 40; len++) {
      const bytes = Uint8Array.from({ length: len }, (_, i) => (i * 37 + len) & 0xff);
      expect(decode(encode(bytes))).toEqual(bytes);
    }
  });

  it('matches RFC 4648 vectors without padding', () => {
    const vectors: [string, string][] = [['', ''], ['f', 'Zg'], ['fo', 'Zm8'], ['foo', 'Zm9v'], ['foob', 'Zm9vYg'], ['fooba', 'Zm9vYmE']];
    for (const [plain, encoded] of vectors) {
      expect(encode(new TextEncoder().encode(plain))).toBe(encoded);
    }
    expect(encode(Uint8Array.of(0xfb, 0xff))).toBe('-_8');
  });

  describe('adversary', () => {
    it('rejects padding, standard alphabet, whitespace and junk', () => {
      for (const bad of ['Zg==', 'Zm+v', 'Zm/v', 'Zm9 v', 'Zm9v\n', '%41', 'Z']) {
        expect(decode(bad), bad).toBeNull();
      }
    });

    it('rejects non-canonical trailing bits so a link has one spelling', () => {
      expect(decode('Zh')).toBeNull(); // 'Zg' with a stray low bit
    });

    it('enforces exact lengths', () => {
      expect(decodeExact(encode(new Uint8Array(32)), 32)).not.toBeNull();
      expect(decodeExact(encode(new Uint8Array(31)), 32)).toBeNull();
    });
  });
});
