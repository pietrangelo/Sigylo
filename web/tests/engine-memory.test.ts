// Adversary: whoever can read the Wasm engine's memory after a call (a later
// script bug, a memory dump, a debugger) must not find a key, a seed, a
// passphrase or a plaintext there. Runs on the engine built by `npm run build`.

import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, it } from 'vitest';
import * as engine from '../src/lib/wasm/sigylo_wasm.js';

let memory: WebAssembly.Memory;

// Rust lays the Wasm stack out first: 1 MiB growing down from STACK_TOP,
// then static data and the heap.
const STACK_TOP = 1 << 20;
// The outermost frames stay live between calls; deeper bytes are dead stack.
const LIVE_FRAMES = 4096;

beforeAll(() => {
  const wasm = readFileSync(new URL('../src/lib/wasm/sigylo_wasm_bg.wasm', import.meta.url));
  memory = engine.initSync({ module: wasm }).memory;
  expect(deadStack(), 'stack is blank at start').toBe(0);
});

/** Bytes left behind in the dead part of the stack by earlier calls. */
function deadStack(): number {
  const stack = new Uint8Array(memory.buffer, 0, STACK_TOP - LIVE_FRAMES);
  return stack.reduce((count, byte) => count + (byte === 0 ? 0 : 1), 0);
}

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

    const envelope = engine.sealForRecipient(secret.slice(), publicKey, fingerprint, undefined, undefined);
    expect(leftIn(secret), 'plaintext after sealing').toBe(false);

    const received = engine.openAsRecipient(envelope, seed.slice(), undefined);
    const opened = received.plaintext;
    expect(received.senderCode).toBeUndefined();
    received.free();
    expect(opened).toEqual(secret);
    expect(leftIn(secret), 'plaintext after opening').toBe(false);
    expect(leftIn(seed), 'seed after opening').toBe(false);
  });

  it('keeps neither the sender seed nor the plaintext when signing and verifying', () => {
    const sender = engine.newSender();
    const senderSeed = sender.seed;
    const code = sender.code;
    sender.free();
    expect(leftIn(senderSeed), 'sender seed after key generation').toBe(false);
    expect(engine.senderCode(senderSeed.slice())).toBe(code);
    expect(leftIn(senderSeed), 'sender seed after showing its code').toBe(false);

    const recipient = engine.newRecipient();
    const seed = recipient.seed;
    const publicKey = recipient.publicKey;
    const fingerprint = recipient.fingerprint;
    recipient.free();
    const envelope = engine.sealForRecipient(secret.slice(), publicKey, fingerprint, passphrase.slice(), senderSeed.slice());
    expect(leftIn(secret), 'plaintext after signing').toBe(false);
    expect(leftIn(senderSeed), 'sender seed after signing').toBe(false);

    const received = engine.openAsRecipient(envelope, seed.slice(), passphrase.slice());
    const opened = received.plaintext;
    expect(received.senderCode).toBe(code);
    received.free();
    expect(opened).toEqual(secret);
    expect(leftIn(secret), 'plaintext after verifying').toBe(false);
    expect(leftIn(seed), 'seed after verifying').toBe(false);
  });

  it('leaves nothing in the dead stack, however deep a call went', () => {
    // ML-DSA key expansion is the deepest call: its secret vectors sit on the stack.
    engine.newSender().free();
    expect(deadStack(), 'after ML-DSA key generation').toBe(0);
    const recipient = engine.newRecipient();
    const envelope = engine.sealForRecipient(secret.slice(), recipient.publicKey, recipient.fingerprint, undefined, engine.newSender().seed);
    expect(deadStack(), 'after signing').toBe(0);
    engine.openAsRecipient(envelope, recipient.seed, undefined).free();
    recipient.free();
    expect(deadStack(), 'after verifying').toBe(0);
  });

  it('wipes the plaintext even when sealing is refused', () => {
    const recipient = engine.newRecipient();
    const publicKey = recipient.publicKey;
    recipient.free();
    expect(() => engine.sealForRecipient(secret.slice(), publicKey, new Uint8Array(32), undefined, undefined)).toThrow('FingerprintMismatch');
    expect(leftIn(secret)).toBe(false);
  });
});
