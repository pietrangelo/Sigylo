// The account's keyring: what a signed-in sender keeps about the secrets
// they sealed, so they can destroy any of them later from any device. It
// holds revocation capabilities, never a link that opens a secret. It is
// sealed on this device with the keyring key before it reaches the relay.
//
// The relay's version number is not authenticated, so a hostile relay could
// serve an older sealed keyring and a seal would silently vanish from the
// list. The sealed JSON carries its own generation, bumped at every write,
// and this device remembers the highest one it has seen for the account: an
// older copy is refused, never written over. A device that has never seen
// the account has nothing to compare with.

import { decodeExact, encode } from './base64url';
import type { SeedStore } from './identity';
import { ID_LEN, KEY_LEN } from './links';

/** One sealed secret: its id, its revocation token, and two dates (Unix seconds). */
export type Seal = { id: string; token: string; sealed: number; expires: number };

/** `gen` counts the writes; a keyring sealed before generations existed reads as 0. */
export type KeyringData = { v: 1; gen: number; seals: Seal[] };

/** Oldest entries go first beyond this, so the sealed keyring stays well under 64 KiB. */
export const MAX_SEALS = 300;

export const EMPTY: KeyringData = { v: 1, gen: 0, seals: [] };

function isSeal(value: unknown): value is Seal {
  const s = value as Partial<Seal> | null;
  return (
    typeof s === 'object' &&
    s !== null &&
    Object.keys(s).length === 4 &&
    typeof s.id === 'string' &&
    decodeExact(s.id, ID_LEN) !== null &&
    typeof s.token === 'string' &&
    decodeExact(s.token, KEY_LEN) !== null &&
    Number.isSafeInteger(s.sealed) &&
    Number.isSafeInteger(s.expires)
  );
}

/** Strict: anything but a well-formed keyring is refused, never half-read. */
export function parseKeyring(text: string): KeyringData | null {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return null;
  }
  const k = json as Partial<KeyringData> | null;
  if (typeof k !== 'object' || k === null || k.v !== 1 || !Array.isArray(k.seals)) return null;
  const hasGen = Object.prototype.hasOwnProperty.call(k, 'gen');
  const gen: unknown = hasGen ? k.gen : 0;
  if (Object.keys(k).length !== (hasGen ? 3 : 2) || typeof gen !== 'number' || !Number.isSafeInteger(gen) || gen < 0) return null;
  return k.seals.every(isSeal) ? { v: 1, gen, seals: k.seals.map((s) => ({ ...s })) } : null;
}

export function serializeKeyring(keyring: KeyringData): string {
  return JSON.stringify({ v: 1, gen: keyring.gen, seals: keyring.seals });
}

/** Adds (or replaces) a seal, newest first, keeping at most MAX_SEALS. */
export function addSeal(keyring: KeyringData, seal: Seal): KeyringData {
  const others = keyring.seals.filter((s) => s.id !== seal.id);
  return { ...keyring, seals: [seal, ...others].slice(0, MAX_SEALS) };
}

export function removeSeal(keyring: KeyringData, id: string): KeyringData {
  return { ...keyring, seals: keyring.seals.filter((s) => s.id !== id) };
}

/** Expired secrets are gone from the relay already; forget them here too. */
export function pruneExpired(keyring: KeyringData, nowSeconds: number): KeyringData {
  return { ...keyring, seals: keyring.seals.filter((s) => s.expires > nowSeconds) };
}

/**
 * Where this device keeps the account's highest generation: named by a hash
 * of the keyring key, so storage shows neither the name nor the key.
 */
export async function watermarkSlot(keyringKey: Uint8Array): Promise<string> {
  const label = new TextEncoder().encode('sigylo/v1/keyring-watermark');
  const input = new Uint8Array(label.length + keyringKey.length);
  input.set(label);
  input.set(keyringKey, label.length);
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
    return `sigylo.keyring.v1.${encode(digest.subarray(0, 16))}`;
  } finally {
    input.fill(0);
  }
}

/** The highest generation seen here; 0 when there is none, it is mangled or storage refuses. */
export function readWatermark(store: SeedStore | null, slot: string): number {
  try {
    const saved = store?.getItem(slot) ?? '';
    const gen = /^(0|[1-9][0-9]{0,15})$/.test(saved) ? Number(saved) : 0;
    return Number.isSafeInteger(gen) ? gen : 0;
  } catch {
    return 0;
  }
}

/** Remembers `gen` if it is higher than what is remembered: the watermark never goes down. */
export function raiseWatermark(store: SeedStore | null, slot: string, gen: number): void {
  if (gen <= readWatermark(store, slot)) return;
  try {
    store?.setItem(slot, String(gen));
  } catch {
    // Storage refused (private browsing, quota): this device just cannot tell.
  }
}
