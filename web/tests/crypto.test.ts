import { afterEach, describe, expect, it, vi } from 'vitest';

// The real engine is not needed: only how loading it behaves.
const init = vi.hoisted(() => vi.fn());
vi.mock('../src/lib/wasm/sigylo_wasm.js', () => ({ default: init }));

describe('loadEngine', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    init.mockReset();
  });

  it('tries again after a failed download, instead of failing for good', async () => {
    // The page preloads the engine; a dropped connection then must not break the click.
    vi.stubGlobal('fetch', vi.fn(async () => new Response()));
    vi.stubGlobal('requestAnimationFrame', (frame: () => void) => setTimeout(frame));
    init.mockRejectedValueOnce(new Error('offline')).mockResolvedValue({});
    const { loadEngine } = await import('../src/lib/crypto');
    await expect(loadEngine()).rejects.toThrow('offline');
    await expect(loadEngine()).resolves.toBeUndefined();
    await expect(loadEngine()).resolves.toBeUndefined();
    expect(init).toHaveBeenCalledTimes(2);
  });

  it('settles even when the tab gets no frames', async () => {
    // A hidden tab never runs requestAnimationFrame callbacks.
    vi.stubGlobal('fetch', vi.fn(async () => new Response()));
    vi.stubGlobal('requestAnimationFrame', () => 0);
    init.mockResolvedValue({});
    const { loadEngine } = await import('../src/lib/crypto');
    await expect(loadEngine()).resolves.toBeUndefined();
  });
});
