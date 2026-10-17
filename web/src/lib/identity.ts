// The sender identity that signs answers to requests (Ed25519 + ML-DSA-65).
// Its 32-byte seed is kept in this browser's local storage and never leaves
// the device; keeping it makes the sender code the same at every answer, so
// a recipient who checked it once can recognize it again. Where storage is
// unavailable the seed lasts for this page only: answers are still signed.

import { decodeExact, encode } from './base64url';

export const IDENTITY_KEY = 'sigylo.sender.v1';
export const SEED_LEN = 32;

export interface SeedStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export function loadOrCreateSeed(store: SeedStore | null, create: () => Uint8Array): Uint8Array {
  try {
    const saved = store?.getItem(IDENTITY_KEY);
    const seed = saved ? decodeExact(saved, SEED_LEN) : null;
    if (seed !== null) return seed;
  } catch {
    // Unreadable storage: fall through to a fresh seed.
  }
  const seed = create();
  try {
    store?.setItem(IDENTITY_KEY, encode(seed));
  } catch {
    // Storage refused (private browsing, quota): the seed lives for this page only.
  }
  return seed;
}

export function browserStore(): SeedStore | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}
