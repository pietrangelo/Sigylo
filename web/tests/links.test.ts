import { describe, expect, it } from 'vitest';
import { encode } from '../src/lib/base64url';
import { inboxLink, parseFragment, requestLink, revokeLink, secretLink } from '../src/lib/links';

const id = Uint8Array.from({ length: 16 }, (_, i) => i);
const key = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
const origin = 'https://sigylo.example';

function fragmentOf(link: string): string {
  return new URL(link).hash;
}

describe('links', () => {
  it('roundtrip through the fragment', () => {
    expect(parseFragment(fragmentOf(secretLink(origin, id, key, false)))).toEqual({ kind: 'secret', id, key, passphrase: false });
    expect(parseFragment(fragmentOf(secretLink(origin, id, key, true)))).toEqual({ kind: 'secret', id, key, passphrase: true });
    expect(parseFragment(fragmentOf(revokeLink(origin, id, key)))).toEqual({ kind: 'revoke', id, token: key });
    expect(parseFragment(fragmentOf(requestLink(origin, id, key)))).toEqual({ kind: 'answer', id, fingerprint: key });
    expect(parseFragment(fragmentOf(inboxLink(origin, id, key)))).toEqual({ kind: 'inbox', id, seed: key });
  });

  it('keeps every secret after the #, out of reach of servers', () => {
    const link = new URL(secretLink(origin, id, key, true));
    expect(link.pathname).toBe('/');
    expect(link.search).toBe('');
    expect(link.hash).toContain(encode(key));
  });

  it('the terms of service and the privacy notice have their own pages', () => {
    expect(parseFragment('#/terms')).toEqual({ kind: 'terms' });
    expect(parseFragment('#/privacy')).toEqual({ kind: 'privacy' });
  });

  it('the account has its own page', () => {
    expect(parseFragment('#/account')).toEqual({ kind: 'account' });
  });

  it('an empty fragment is the compose page', () => {
    expect(parseFragment('')).toEqual({ kind: 'compose' });
    expect(parseFragment('#/')).toEqual({ kind: 'compose' });
  });

  describe('adversary', () => {
    it('rejects wrong lengths, unknown kinds, flags and extra segments', () => {
      const i = encode(id);
      const k = encode(key);
      for (const bad of [
        `#/s/${i}/${encode(key.slice(1))}`,
        `#/s/${encode(id.slice(1))}/${k}`,
        `#/z/${i}/${k}`,
        `#/s/${i}/${k}/q`,
        `#/x/${i}/${k}/p`,
        `#/s/${i}/${k}/p/more`,
        `#s/${i}/${k}`,
        `#/s/${i}`,
        `#/s/${i}/${k}==`,
        '#/terms/',
        '#/terms/x',
        '#/Terms',
        '#terms',
        '#/privacy/p',
        '#/account/',
        '#/account/x',
        '#/Account',
      ]) {
        expect(parseFragment(bad).kind, bad).toBe('invalid');
      }
    });
  });
});
