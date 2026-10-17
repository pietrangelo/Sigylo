// Adversary: whoever can read the Wasm engine's memory after a call (a later
// script bug, a memory dump, a debugger) must not find a key, a seed, a
// passphrase or a plaintext there. Runs on the engine built by `npm run build`.

import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import * as engine from '../src/lib/wasm/sigylo_wasm.js';

let memory: WebAssembly.Memory;

beforeAll(() => {
  const wasm = readFileSync(new URL('../src/lib/wasm/sigylo_wasm_bg.wasm', import.meta.url));
  memory = engine.initSync({ module: wasm }).memory;
});

function leftIn(needle: Uint8Array): boolean {
  const heap = new Uint8Array(memory.buffer);
  outer: for (let i = 0; i <= heap.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (heap[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

const text = (s: string) => new TextEncoder().encode(s);
const secret = text('password del DB: cavallo-corretto-batteria-graffetta 🔐 e3b0c44298fc1c149afb');
const passphrase = text('seconda chiave fuori banda 7f9a');

describe('adversary: Wasm memory after use', () => {
  it('keeps neither the key nor the plaintext once a link secret is sealed and opened', () => {
    const sealed = engine.sealForLink(secret.slice(), passphrase.slice());
    const key = sealed.key;
    const envelope = sealed.envelope;
    sealed.free();
    expect(leftIn(secret), 'plaintext after sealing').toBe(false);
    expect(leftIn(key), 'link key after sealing').toBe(false);

    const opened = engine.openLink(envelope, key.slice(), passphrase.slice());
    expect(opened).toEqual(secret);
    expect(leftIn(secret), 'plaintext after opening').toBe(false);
    expect(leftIn(key), 'link key after opening').toBe(false);
    expect(leftIn(passphrase), 'passphrase').toBe(false);
  });

  it('keeps neither the seed nor the plaintext in request mode', () => {
    const recipient = engine.newRecipient();
    const seed = recipient.seed;
    const publicKey = recipient.publicKey;
    const fingerprint = recipient.fingerprint;
    recipient.free();
    expect(leftIn(seed), 'seed after key generation').toBe(false);

    const envelope = engine.sealForRecipient(secret.slice(), publicKey, fingerprint, undefined);
    expect(leftIn(secret), 'plaintext after sealing').toBe(false);

    const opened = engine.openAsRecipient(envelope, seed.slice(), undefined);
    expect(opened).toEqual(secret);
    expect(leftIn(secret), 'plaintext after opening').toBe(false);
    expect(leftIn(seed), 'seed after opening').toBe(false);
  });

  it('wipes the plaintext even when sealing is refused', () => {
    const recipient = engine.newRecipient();
    const publicKey = recipient.publicKey;
    recipient.free();
    expect(() => engine.sealForRecipient(secret.slice(), publicKey, new Uint8Array(32), undefined)).toThrow('FingerprintMismatch');
    expect(leftIn(secret)).toBe(false);
  });
});
