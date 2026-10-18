// Device passes: after each login the relay hands this device a pass, and
// the next login shows it, so this device's logins spend an allowance of
// their own and a flood of guesses for the name cannot lock its owner out.
// A pass opens nothing by itself. They are kept in this browser's local
// storage under a hash of the account name, never the name itself; where
// storage is unavailable the device simply logs in without one.

import { decodeExact, encode } from './base64url';
import type { SeedStore } from './identity';

export const PASSES_KEY = 'sigylo.pass.v1';
export const PASS_LEN = 56;
/** Accounts remembered on one device; the least recently used goes first. */
export const MAX_PASSES = 8;

type Saved = Record<string, string>;

/** Where an account's pass is filed: a hash of its (normalized) name. */
export async function passSlot(username: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`sigylo/v1/pass\0${username}`));
  return encode(new Uint8Array(digest).slice(0, 16));
}

function read(store: SeedStore | null): Saved {
  try {
    const saved: unknown = JSON.parse(store?.getItem(PASSES_KEY) ?? '{}');
    return saved !== null && typeof saved === 'object' && !Array.isArray(saved) ? (saved as Saved) : {};
  } catch {
    return {};
  }
}

function write(store: SeedStore | null, saved: Saved): void {
  try {
    store?.setItem(PASSES_KEY, JSON.stringify(saved));
  } catch {
    // Storage refused (private browsing, quota): the next login goes without a pass.
  }
}

export function loadPass(store: SeedStore | null, slot: string): Uint8Array | null {
  const text = read(store)[slot];
  return typeof text === 'string' ? decodeExact(text, PASS_LEN) : null;
}

export function savePass(store: SeedStore | null, slot: string, pass: Uint8Array): void {
  const saved = read(store);
  delete saved[slot];
  const kept = Object.entries(saved).slice(-(MAX_PASSES - 1));
  write(store, Object.fromEntries([...kept, [slot, encode(pass)]]));
}

export function dropPass(store: SeedStore | null, slot: string): void {
  const saved = read(store);
  if (!(slot in saved)) return;
  delete saved[slot];
  write(store, saved);
}
