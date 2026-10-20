// Loads the Rust/Wasm sealing engine. The .wasm file is fetched with a
// Subresource Integrity hash computed at build time, so the browser refuses
// to run a module that differs by a single byte from the one we built.

import init, * as engine from './wasm/sigylo_wasm.js';
import wasmUrl from './wasm/sigylo_wasm_bg.wasm?url';
import wasmIntegrity from 'virtual:wasm-integrity';

let ready: Promise<void> | null = null;

export async function loadEngine(): Promise<void> {
  ready ??= init({ module_or_path: fetch(wasmUrl, { integrity: wasmIntegrity, credentials: 'omit' }) }).then(
    () => undefined,
    (e: unknown) => {
      // A failed download is not remembered: the next call tries again.
      ready = null;
      throw e;
    },
  );
  await ready;
  // Let the browser paint the busy state before Argon2id holds the thread for
  // seconds; a hidden tab gets no frames, hence the timer.
  await new Promise((resolve) => {
    requestAnimationFrame(() => setTimeout(resolve));
    setTimeout(resolve, 100);
  });
}

/** Stable error codes thrown by the engine (names of the Rust `SealError` variants). */
export type SealErrorCode =
  | 'NotAuthentic'
  | 'FingerprintMismatch'
  | 'PassphraseExpectationMismatch'
  | 'MalformedEnvelope'
  | 'PlaintextTooLarge'
  | 'PlaintextEmpty'
  | 'FileTooLarge'
  | 'InvalidFileName'
  | 'InvalidPassphrase'
  | 'WrongMode'
  | 'InvalidSenderCode'
  | 'UnexpectedSender'
  | 'Unknown';

export function errorCode(error: unknown): SealErrorCode {
  const message = error instanceof Error ? error.message : '';
  const known: SealErrorCode[] = ['NotAuthentic', 'FingerprintMismatch', 'PassphraseExpectationMismatch', 'MalformedEnvelope', 'PlaintextTooLarge', 'PlaintextEmpty', 'FileTooLarge', 'InvalidFileName', 'InvalidPassphrase', 'WrongMode', 'InvalidSenderCode', 'UnexpectedSender'];
  return known.find((code) => code === message) ?? 'Unknown';
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

/** Passphrases are NFC-normalized so "è" typed on any keyboard is the same bytes. */
export function passphraseBytes(passphrase: string): Uint8Array | undefined {
  return passphrase === '' ? undefined : encoder.encode(passphrase.normalize('NFC'));
}

/**
 * File names are NFC-normalized too: the name the recipient sees is the one
 * that was sealed. Characters Windows refuses become underscores and emoji
 * presentation selectors are dropped, so ordinary names seal; no-break and
 * other wide spaces (macOS puts U+202F before AM/PM in screenshot names)
 * become plain ones, so a run stays a run. Anything that could hide part of
 * the name is left for the engine to refuse.
 */
export function fileName(name: string): string {
  return name
    .normalize('NFC')
    .replace(/[<>:"|?*]/g, '_')
    .replace(/[\uFE0E\uFE0F]/g, '')
    .replace(/[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g, ' ');
}

export function textBytes(text: string): Uint8Array {
  return encoder.encode(text);
}

export function bytesText(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

export { engine };
