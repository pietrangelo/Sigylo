import { describe, expect, it } from 'vitest';
import { encode } from '../src/lib/base64url';
import { dropKeyFromAddress, inboxLink, leavingLoses, linkFragment, openPasted, parseFragment, requestLink, revokeLink, secretLink } from '../src/lib/links';

const id = Uint8Array.from({ length: 16 }, (_, i) => i);
const key = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
const pin = Uint8Array.from({ length: 32 }, (_, i) => i * 7);
const origin = 'https://sigylo.example';

function fragmentOf(link: string): string {
  return new URL(link).hash;
}

describe('links', () => {
  it('roundtrip through the fragment', () => {
    expect(parseFragment(fragmentOf(secretLink(origin, id, key, false)))).toEqual({ kind: 'secret', id, key, passphrase: false });
    expect(parseFragment(fragmentOf(secretLink(origin, id, key, true)))).toEqual({ kind: 'secret', id, key, passphrase: true });
    expect(parseFragment(fragmentOf(revokeLink(origin, id, key)))).toEqual({ kind: 'revoke', id, token: key });
    expect(parseFragment(fragmentOf(requestLink(origin, id, key)))).toEqual({ kind: 'answer', id, fingerprint: key, expectedSender: null });
    expect(parseFragment(fragmentOf(inboxLink(origin, id, key)))).toEqual({ kind: 'inbox', id, seed: key, expectedSender: null });
  });

  it('request and inbox links can carry the expected sender pin', () => {
    expect(parseFragment(fragmentOf(requestLink(origin, id, key, pin)))).toEqual({ kind: 'answer', id, fingerprint: key, expectedSender: pin });
    expect(parseFragment(fragmentOf(inboxLink(origin, id, key, pin)))).toEqual({ kind: 'inbox', id, seed: key, expectedSender: pin });
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
    expect(parseFragment('#/me')).toEqual({ kind: 'me' });
  });

  it('the account has its own page', () => {
    expect(parseFragment('#/account')).toEqual({ kind: 'account' });
  });

  it('pages holding something that opens once are the ones a quiet link must not leave', () => {
    const at = (link: string) => parseFragment(new URL(link).hash);
    expect(leavingLoses(at(secretLink('https://sigylo.net', id, key, false)))).toBe(true);
    expect(leavingLoses(at(inboxLink('https://sigylo.net', id, key)))).toBe(true);
    expect(leavingLoses(at(requestLink('https://sigylo.net', id, key)))).toBe(true);
    for (const page of ['#/', '#/me', '#/account', '#/terms', '#/privacy', '#/nonsense']) {
      expect(leavingLoses(parseFragment(page)), page).toBe(false);
    }
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
        '#/me/x',
        `#/s/${i}/${k}/${encode(pin)}`,
        `#/x/${i}/${k}/${encode(pin)}`,
        `#/r/${i}/${k}/${encode(pin.slice(1))}`,
        `#/k/${i}/${k}/${encode(pin)}/more`,
        `#/k/${i}/${k}/p`,
      ]) {
        expect(parseFragment(bad).kind, bad).toBe('invalid');
      }
    });
  });

  describe('a link pasted into the app', () => {
    const site = 'https://sigylo.net';

    it('opens every kind of Sigylo link at its fragment', () => {
      for (const link of [secretLink(site, id, key, false), secretLink(site, id, key, true), revokeLink(site, id, key), requestLink(site, id, key), inboxLink(site, id, key)]) {
        expect(linkFragment(link)).toBe(new URL(link).hash);
        expect(linkFragment(`  ${link}\n`)).toBe(new URL(link).hash);
      }
    });

    describe('adversary', () => {
      it('refuses links that are not sigylo.net secrets', () => {
        const fragment = new URL(secretLink(site, id, key, false)).hash;
        for (const bad of [
          `http://sigylo.net/${fragment}`,
          `https://sigylo.net.evil.example/${fragment}`,
          `https://evil.example/${fragment}`,
          `https://sigylo.net@evil.example/${fragment}`,
          `https://user@sigylo.net/${fragment}`,
          `https://sigylo.net:8443/${fragment}`,
          `https://sigylo.net/other${fragment}`,
          `https://sigylo.net/?x=1${fragment}`,
          `javascript:alert(1)//${fragment}`,
          'https://sigylo.net/',
          'https://sigylo.net/#/',
          'https://sigylo.net/#/terms',
          'https://sigylo.net/#/s/short/key',
          fragment,
          '',
        ]) {
          expect(linkFragment(bad), bad).toBeNull();
        }
      });
    });
  });
});

describe('dropping the key from the address bar', () => {
  it('replaces the entry with the root of the page, whatever path served it', () => {
    const urls: (string | URL | null | undefined)[] = [];
    expect(dropKeyFromAddress({ replaceState: (_data, _unused, url) => urls.push(url) })).toBe(true);
    expect(urls).toEqual(['/']);
  });

  describe('adversary', () => {
    it('a path that reads as another host still resolves to this origin, without a fragment', () => {
      // The SPA fallback serves the page at //x.example/: replacing with the
      // pathname would resolve to https://x.example/ and make replaceState throw.
      const base = 'https://sigylo.net//x.example/#/s/AAAAAAAAAAAAAAAAAAAAAA/' + 'A'.repeat(43);
      expect(new URL(new URL(base).pathname, base).origin).toBe('https://x.example');
      let target = '';
      dropKeyFromAddress({ replaceState: (_data, _unused, url) => (target = new URL(String(url), base).href) });
      expect(target).toBe('https://sigylo.net/');
    });

    it('never throws, so a refusal can neither show an error nor hide the secret', () => {
      const refusing = {
        replaceState() {
          throw new DOMException('cross-origin', 'SecurityError');
        },
      };
      expect(dropKeyFromAddress(refusing)).toBe(false);
    });
  });
});

// Chromium writes every address the page goes to, fragment and all, into a
// History database on disk, and replaceState adds a visit without removing
// the old one (checked on Chromium 2026-11-06). WebView2, the app's webview on
// Windows, is Chromium. So a link pasted into the app opens in memory only.
describe('opening a link pasted into the app', () => {
  const site = 'https://sigylo.net';
  type Call = { method: string; url: string | URL | null | undefined };
  function recorder(calls: Call[]): Pick<History, 'replaceState' | 'pushState'> {
    return {
      replaceState: (_data, _unused, url) => void calls.push({ method: 'replaceState', url }),
      pushState: (_data, _unused, url) => void calls.push({ method: 'pushState', url }),
    };
  }

  it('gives the route of the link, and leaves the address at the root without a fragment', () => {
    const calls: Call[] = [];
    expect(openPasted(secretLink(site, id, key, true), recorder(calls))).toEqual({ kind: 'secret', id, key, passphrase: true });
    expect(openPasted(inboxLink(site, id, key, pin), recorder(calls))).toEqual({ kind: 'inbox', id, seed: key, expectedSender: pin });
    // The root, without '#', so a click on '#/' afterwards is a hashchange.
    expect(calls).toEqual([
      { method: 'replaceState', url: '/' },
      { method: 'replaceState', url: '/' },
    ]);
  });

  describe('adversary', () => {
    it('no kind of link ever puts its secret into the address or the history', () => {
      for (const link of [secretLink(site, id, key, false), revokeLink(site, id, key), requestLink(site, id, key, pin), inboxLink(site, id, key)]) {
        const calls: Call[] = [];
        expect(openPasted(`  ${link}\n`, recorder(calls))).not.toBeNull();
        for (const { url } of calls) {
          expect(String(url), link).not.toContain('#');
          expect(String(url), link).not.toContain(encode(key));
        }
      }
    });

    it('a link the app refuses opens nothing and leaves the address alone', () => {
      for (const bad of [`https://evil.example/${fragmentOf(secretLink(site, id, key, false))}`, '#/s/x/y', '', 'javascript:alert(1)']) {
        const calls: Call[] = [];
        expect(openPasted(bad, recorder(calls)), bad).toBeNull();
        expect(calls, bad).toEqual([]);
      }
    });

    it('a history that refuses does not stop the link from opening', () => {
      const refusing = {
        replaceState() {
          throw new DOMException('cross-origin', 'SecurityError');
        },
        pushState() {
          throw new DOMException('cross-origin', 'SecurityError');
        },
      };
      expect(openPasted(secretLink(site, id, key, false), refusing)).toEqual({ kind: 'secret', id, key, passphrase: false });
    });
  });
});
