// The account's keyring: what a signed-in sender keeps about the secrets
// they sealed, so they can destroy any of them later from any device. It
// holds revocation capabilities, never a link that opens a secret. It is
// sealed on this device with the keyring key before it reaches the relay.

import { decodeExact } from './base64url';
import { ID_LEN, KEY_LEN } from './links';

/** One sealed secret: its id, its revocation token, and two dates (Unix seconds). */
export type Seal = { id: string; token: string; sealed: number; expires: number };

export type KeyringData = { v: 1; seals: Seal[] };

/** Oldest entries go first beyond this, so the sealed keyring stays well under 64 KiB. */
export const MAX_SEALS = 300;

export const EMPTY: KeyringData = { v: 1, seals: [] };

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
  if (typeof k !== 'object' || k === null || k.v !== 1 || !Array.isArray(k.seals) || Object.keys(k).length !== 2) return null;
  return k.seals.every(isSeal) ? { v: 1, seals: k.seals.map((s) => ({ ...s })) } : null;
}

export function serializeKeyring(keyring: KeyringData): string {
  return JSON.stringify({ v: 1, seals: keyring.seals });
}

/** Adds (or replaces) a seal, newest first, keeping at most MAX_SEALS. */
export function addSeal(keyring: KeyringData, seal: Seal): KeyringData {
  const others = keyring.seals.filter((s) => s.id !== seal.id);
  return { v: 1, seals: [seal, ...others].slice(0, MAX_SEALS) };
}

export function removeSeal(keyring: KeyringData, id: string): KeyringData {
  return { v: 1, seals: keyring.seals.filter((s) => s.id !== id) };
}

/** Expired secrets are gone from the relay already; forget them here too. */
export function pruneExpired(keyring: KeyringData, nowSeconds: number): KeyringData {
  return { v: 1, seals: keyring.seals.filter((s) => s.expires > nowSeconds) };
}
