import { describe, expect, it } from 'vitest';
import { encode } from '../src/lib/base64url';
import { IDENTITY_KEY, loadOrCreateSeed, type SeedStore } from '../src/lib/identity';

class MemoryStore implements SeedStore {
  items = new Map<string, string>();
  getItem(key: string) {
    return this.items.get(key) ?? null;
  }
  setItem(key: string, value: string) {
    this.items.set(key, value);
  }
}

let counter = 0;
const fresh = () => new Uint8Array(32).fill(++counter);

describe('sender identity', () => {
  it('is created once and then reused, so the sender code never changes', () => {
    const store = new MemoryStore();
    const first = loadOrCreateSeed(store, fresh);
    expect(first).toHaveLength(32);
    expect(store.items.get(IDENTITY_KEY)).toBe(encode(first));
    expect(loadOrCreateSeed(store, fresh)).toEqual(first);
  });

  it('works without storage, with a seed for this page only', () => {
    expect(loadOrCreateSeed(null, fresh)).toHaveLength(32);
  });

  describe('adversary', () => {
    it('replaces a corrupted or truncated stored seed instead of using it', () => {
      for (const junk of ['', 'not base64url!', encode(new Uint8Array(31)), encode(new Uint8Array(33))]) {
        const store = new MemoryStore();
        store.setItem(IDENTITY_KEY, junk);
        const seed = loadOrCreateSeed(store, fresh);
        expect(seed).toHaveLength(32);
        expect(store.items.get(IDENTITY_KEY)).toBe(encode(seed));
      }
    });

    it('survives storage that throws (private browsing, blocked site data)', () => {
      const hostile: SeedStore = {
        getItem() {
          throw new Error('SecurityError');
        },
        setItem() {
          throw new Error('QuotaExceededError');
        },
      };
      expect(loadOrCreateSeed(hostile, fresh)).toHaveLength(32);
    });
  });
});
