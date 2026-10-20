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
  // Jump between occurrences of the first byte: the heap grows to tens of MiB with files.
  for (let i = heap.indexOf(needle[0]!); i !== -1 && i <= heap.length - needle.length; i = heap.indexOf(needle[0]!, i + 1)) {
    let j = 1;
    while (j < needle.length && heap[i + j] === needle[j]) j++;
    if (j === needle.length) return true;
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

  it('keeps neither the keyring key nor the keyring once it is sealed and opened', () => {
    const key = new Uint8Array(32).map((_, i) => 200 - i);
    const envelope = engine.sealWithKey(secret.slice(), key.slice());
    expect(leftIn(secret), 'keyring after sealing').toBe(false);
    expect(leftIn(key), 'keyring key after sealing').toBe(false);
    expect(engine.openLink(envelope, key.slice(), undefined)).toEqual(secret);
    expect(leftIn(secret), 'keyring after opening').toBe(false);
    expect(leftIn(key), 'keyring key after opening').toBe(false);
  });

  // No relay here, so the answers are built from valid group elements of
  // another run: registration completes (it is unauthenticated by design),
  // login runs Argon2id and then fails to open the envelope, as with a
  // wrong password. Either way the password must be gone afterwards.
  const password = text('la mia password OPAQUE 4c1d 🔑');

  it('keeps neither the password nor the keyring key after a registration', () => {
    const other = engine.beginRegistration(text('another password').slice());
    const point = other.request;
    other.free();
    const registration = engine.beginRegistration(password.slice());
    expect(registration.request.length).toBe(32);
    const admission = registration.finish(Uint8Array.of(...point, ...point));
    const keyringKey = admission.keyringKey;
    expect(admission.message.length).toBe(192);
    admission.free();
    registration.free();
    expect(leftIn(password), 'password after registration').toBe(false);
    expect(leftIn(keyringKey), 'keyring key after registration').toBe(false);
  });

  it('keeps no password after a failed login, and a login state works once', () => {
    const other = engine.beginLogin(text('another password').slice());
    const ke1 = other.request;
    other.free();
    const login = engine.beginLogin(password.slice());
    const response = new Uint8Array(320);
    response.set(ke1.slice(0, 32), 0); // OPRF evaluation: a valid point
    response.set(ke1.slice(64, 96), 224); // relay key share: a valid point
    expect(() => login.finish(response)).toThrow('NotAuthentic');
    expect(() => login.finish(response)).toThrow('NotAuthentic');
    login.free();
    expect(leftIn(password), 'password after login').toBe(false);
  });

  it('refuses a short password without keeping it', () => {
    const short = text('short7!');
    expect(() => engine.beginLogin(short.slice())).toThrow('InvalidPassword');
    expect(leftIn(short)).toBe(false);
  });

  it('keeps neither the file, its key nor the link key once a file is sealed and opened', () => {
    // A 1.5 MiB file with a marker in the first chunk, across the chunk
    // boundary and at the very end.
    const marker = text('contenuto riservato del file 4c1d');
    const contents = new Uint8Array(1024 * 1024 + 512 * 1024).fill(0x2e);
    for (const at of [0, 1024 * 1024 - 10, contents.length - marker.length]) contents.set(marker, at);
    const sealed = engine.sealFileForLink('bilancio.xlsx', contents.slice(), passphrase.slice());
    const key = sealed.key;
    const envelope = sealed.envelope;
    const chunks = sealed.chunks as Uint8Array[];
    sealed.free();
    expect(chunks).toHaveLength(2);
    expect(leftIn(marker), 'file contents after sealing').toBe(false);
    expect(leftIn(key), 'link key after sealing').toBe(false);

    const manifest = engine.openLink(envelope, key.slice(), passphrase.slice());
    const fileKey = manifest.slice(6, 38);
    const info = engine.fileInfo(manifest.slice());
    expect([info?.name, info?.size, info?.chunks]).toEqual(['bilancio.xlsx', contents.length, 2]);
    info?.free();
    const opened = engine.openFile(manifest.slice(), chunks);
    expect(opened).toEqual(contents);
    expect(leftIn(marker), 'file contents after opening').toBe(false);
    expect(leftIn(fileKey), 'file key after opening').toBe(false);
    expect(leftIn(key), 'link key after opening').toBe(false);
  }, 60_000);

  it('wipes the passphrase, the seeds and the keys when a call is refused on an earlier argument', () => {
    // Every secret argument is under a wiping owner before anything is checked:
    // a refused file name or a bad key must not leave the others behind.
    const pass = text('passphrase di una chiamata rifiutata 51ce');
    const sender = engine.newSender();
    const senderSeed = sender.seed;
    sender.free();
    const recipient = engine.newRecipient();
    const seed = recipient.seed;
    const publicKey = recipient.publicKey;
    const fingerprint = recipient.fingerprint;
    recipient.free();
    const contents = new Uint8Array(64).fill(0x2e);
    const key = new Uint8Array(32).map((_, i) => 90 + i);
    const refused: [string, () => unknown][] = [
      ['answer file with a refused name', () => engine.sealFileForRecipient('a  b.txt', contents.slice(), publicKey, fingerprint, pass.slice(), senderSeed.slice())],
      ['answer file to a bad key', () => engine.sealFileForRecipient('a.txt', contents.slice(), new Uint8Array(5), fingerprint, pass.slice(), senderSeed.slice())],
      ['answer to a bad fingerprint', () => engine.sealForRecipient(secret.slice(), publicKey, new Uint8Array(5), pass.slice(), senderSeed.slice())],
      ['empty answer', () => engine.sealForRecipient(new Uint8Array(0), publicKey, fingerprint, pass.slice(), senderSeed.slice())],
      ['link file with a refused name', () => engine.sealFileForLink('a  b.txt', contents.slice(), pass.slice())],
      ['empty link secret', () => engine.sealForLink(new Uint8Array(0), pass.slice())],
      ['link open of a bad envelope', () => engine.openLink(new Uint8Array(5), key.slice(), pass.slice())],
      ['link open with a bad key', () => engine.openLink(new Uint8Array(5), new Uint8Array(5), pass.slice())],
      ['recipient open of a bad envelope', () => engine.openAsRecipient(new Uint8Array(5), seed.slice(), pass.slice())],
      ['recipient open with a bad pin', () => engine.openAsRecipient(new Uint8Array(5), seed.slice(), pass.slice(), new Uint8Array(5))],
      ['expected sender with a bad fingerprint', () => engine.isExpectedSender(new Uint8Array(5), new Uint8Array(32), senderSeed.slice())],
      ['empty keyring', () => engine.sealWithKey(new Uint8Array(0), key.slice())],
    ];
    for (const [what, call] of refused) {
      expect(call, what).toThrow();
      expect(leftIn(pass), `passphrase after ${what}`).toBe(false);
      expect(leftIn(senderSeed), `sender seed after ${what}`).toBe(false);
      expect(leftIn(seed), `recipient seed after ${what}`).toBe(false);
      expect(leftIn(key), `key after ${what}`).toBe(false);
    }
  });

  it('wipes the file even when sealing it is refused', () => {
    const marker = text('file rifiutato per il nome 9e2b');
    const contents = new Uint8Array(4096).fill(0x2e);
    contents.set(marker, 100);
    expect(() => engine.sealFileForLink('evil\u202Efdp.exe', contents.slice(), undefined)).toThrow('InvalidFileName');
    expect(leftIn(marker)).toBe(false);
  });
});

