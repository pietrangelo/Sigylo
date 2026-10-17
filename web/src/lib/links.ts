// Links live entirely in the URL fragment (after '#'). Browsers never send
// the fragment to any server, so neither the host serving the page nor the
// relay ever learns the key, the seed or the revocation token.
//
//   #/s/<id>/<key>       open a secret (link mode)
//   #/s/<id>/<key>/p     ... that also needs a passphrase
//   #/x/<id>/<token>     revoke a secret before it is read (sender only)
//   #/r/<id>/<fpr>       answer a request: seal to the recipient's public key
//   #/k/<id>/<seed>      the recipient's private link to read the answer
//   #/terms, #/privacy   the terms of service and the privacy notice

import { decodeExact, encode } from './base64url';

export const ID_LEN = 16;
export const KEY_LEN = 32;

export type Route =
  | { kind: 'compose' }
  | { kind: 'secret'; id: Uint8Array; key: Uint8Array; passphrase: boolean }
  | { kind: 'revoke'; id: Uint8Array; token: Uint8Array }
  | { kind: 'answer'; id: Uint8Array; fingerprint: Uint8Array }
  | { kind: 'inbox'; id: Uint8Array; seed: Uint8Array }
  | { kind: 'terms' }
  | { kind: 'privacy' }
  | { kind: 'invalid' };

export function parseFragment(fragment: string): Route {
  const path = fragment.replace(/^#/, '');
  if (path === '' || path === '/') return { kind: 'compose' };
  if (path === '/terms') return { kind: 'terms' };
  if (path === '/privacy') return { kind: 'privacy' };
  const parts = path.split('/');
  if (parts[0] !== '') return { kind: 'invalid' };
  const [, kind, idText, secretText, flag, ...rest] = parts;
  if (rest.length > 0 || idText === undefined || secretText === undefined) return { kind: 'invalid' };
  const id = decodeExact(idText, ID_LEN);
  const secret = decodeExact(secretText, KEY_LEN);
  if (id === null || secret === null) return { kind: 'invalid' };
  if (kind === 's' && (flag === undefined || flag === 'p')) {
    return { kind: 'secret', id, key: secret, passphrase: flag === 'p' };
  }
  if (flag !== undefined) return { kind: 'invalid' };
  switch (kind) {
    case 'x':
      return { kind: 'revoke', id, token: secret };
    case 'r':
      return { kind: 'answer', id, fingerprint: secret };
    case 'k':
      return { kind: 'inbox', id, seed: secret };
    default:
      return { kind: 'invalid' };
  }
}

function link(origin: string, ...parts: string[]): string {
  return `${origin}/#/${parts.join('/')}`;
}

export function secretLink(origin: string, id: Uint8Array, key: Uint8Array, passphrase: boolean): string {
  const parts = ['s', encode(id), encode(key)];
  if (passphrase) parts.push('p');
  return link(origin, ...parts);
}

export function revokeLink(origin: string, id: Uint8Array, token: Uint8Array): string {
  return link(origin, 'x', encode(id), encode(token));
}

export function requestLink(origin: string, id: Uint8Array, fingerprint: Uint8Array): string {
  return link(origin, 'r', encode(id), encode(fingerprint));
}

export function inboxLink(origin: string, id: Uint8Array, seed: Uint8Array): string {
  return link(origin, 'k', encode(id), encode(seed));
}
