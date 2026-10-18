import { describe, expect, it } from 'vitest';
import { MAX_PASSES, PASSES_KEY, PASS_LEN, dropPass, loadPass, passSlot, savePass } from '../src/lib/passes';

function memoryStore() {
  const items = new Map<string, string>();
  return {
    items,
    getItem: (key: string) => items.get(key) ?? null,
    setItem: (key: string, value: string) => void items.set(key, value),
  };
}

const pass = (n: number) => new Uint8Array(PASS_LEN).fill(n);

describe('device passes', () => {
  it('keeps one pass per account and gives it back', async () => {
    const store = memoryStore();
    const ada = await passSlot('ada');
    const bob = await passSlot('bob');
    expect(loadPass(store, ada)).toBeNull();
    savePass(store, ada, pass(1));
    savePass(store, bob, pass(2));
    savePass(store, ada, pass(3));
    expect(loadPass(store, ada)).toEqual(pass(3));
    expect(loadPass(store, bob)).toEqual(pass(2));
    dropPass(store, ada);
    expect(loadPass(store, ada)).toBeNull();
    expect(loadPass(store, bob)).toEqual(pass(2));
  });

  it('remembers a bounded number of accounts, dropping the least recently used', async () => {
    const store = memoryStore();
    const slots = await Promise.all([...Array(MAX_PASSES + 1).keys()].map((i) => passSlot(`user-${i}`)));
    slots.forEach((slot, i) => savePass(store, slot, pass(i)));
    expect(loadPass(store, slots[0]!)).toBeNull();
    expect(loadPass(store, slots[MAX_PASSES]!)).toEqual(pass(MAX_PASSES));
    expect(Object.keys(JSON.parse(store.items.get(PASSES_KEY)!))).toHaveLength(MAX_PASSES);
  });

  it('works without storage, and with storage that throws', async () => {
    const slot = await passSlot('ada');
    expect(loadPass(null, slot)).toBeNull();
    savePass(null, slot, pass(1));
    const broken = {
      getItem: () => {
        throw new Error('SecurityError');
      },
      setItem: () => {
        throw new Error('QuotaExceededError');
      },
    };
    expect(loadPass(broken, slot)).toBeNull();
    savePass(broken, slot, pass(1));
    dropPass(broken, slot);
  });

  describe('adversary', () => {
    it('the account name is never stored, only a hash of it', async () => {
      const store = memoryStore();
      savePass(store, await passSlot('élodie'), pass(1));
      expect(store.items.get(PASSES_KEY)).not.toContain('lodie');
      expect(await passSlot('ada')).not.toBe(await passSlot('ada '));
    });

    it('damaged storage reads as no pass, never as a wrong-sized one', async () => {
      const store = memoryStore();
      const slot = await passSlot('ada');
      for (const junk of ['not json', '[]', 'null', JSON.stringify({ [slot]: 'AAAA' }), JSON.stringify({ [slot]: 7 })]) {
        store.items.set(PASSES_KEY, junk);
        expect(loadPass(store, slot)).toBeNull();
      }
      savePass(store, slot, pass(4));
      expect(loadPass(store, slot)).toEqual(pass(4));
    });
  });
});
