// Loads the Rust/Wasm sealing engine. The .wasm file is fetched with a
// Subresource Integrity hash computed at build time, so the browser refuses
// to run a module that differs by a single byte from the one we built.

import init, * as engine from './wasm/sigylo_wasm.js';
import wasmUrl from './wasm/sigylo_wasm_bg.wasm?url';
import wasmIntegrity from 'virtual:wasm-integrity';

let ready: Promise<void> | null = null;

export function loadEngine(): Promise<void> {
  ready ??= init({ module_or_path: fetch(wasmUrl, { integrity: wasmIntegrity, credentials: 'omit' }) }).then(() => undefined);
  return ready;
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

/** File names are NFC-normalized too: the name the recipient sees is the one that was sealed. */
export function fileName(name: string): string {
  return name.normalize('NFC');
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
