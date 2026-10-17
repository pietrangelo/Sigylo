import { describe, expect, it } from 'vitest';
import { appCsp } from '../vite-plugin-app';
import { ipcFetch, WEB_ORIGIN, type Invoke } from '../src/lib/platform';

type Call = { cmd: string; args: Record<string, unknown> };

function recording(reply: unknown, calls: Call[] = []): Invoke {
  return async (cmd, args) => {
    calls.push({ cmd, args });
    return reply;
  };
}

describe('platform', () => {
  it('links made in the app point at the public site', () => {
    expect(WEB_ORIGIN).toBe('https://sigylo.net');
  });

  describe('relay through the app shell', () => {
    it('hands method, path below /api and body to the shell', async () => {
      const calls: Call[] = [];
      const fetch = ipcFetch(recording({ status: 201, body: '{"id":"x"}' }, calls));
      const response = await fetch('/api/secrets', { method: 'POST', body: '{"payload":"AQI"}' });
      expect(calls).toEqual([{ cmd: 'relay', args: { method: 'POST', path: '/secrets', body: '{"payload":"AQI"}' } }]);
      expect(response.status).toBe(201);
      expect(await response.json()).toEqual({ id: 'x' });
    });

    it('hands a signed-in session to the shell, without the Bearer prefix', async () => {
      const calls: Call[] = [];
      const token = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
      await ipcFetch(recording({ status: 200, body: '{}' }, calls))('/api/account/keyring', { method: 'GET', headers: { Authorization: `Bearer ${token}` } });
      expect(calls[0]!.args).toEqual({ method: 'GET', path: '/account/keyring', body: null, session: token });
    });

    it('sends no body when there is none', async () => {
      const calls: Call[] = [];
      await ipcFetch(recording({ status: 200, body: '{}' }, calls))('/api/requests/abc', { method: 'GET' });
      expect(calls[0]!.args).toEqual({ method: 'GET', path: '/requests/abc', body: null });
    });

    it('keeps error statuses so the relay client can read the code', async () => {
      const response = await ipcFetch(recording({ status: 404, body: '{"error":"NotFound"}' }))('/api/secrets/a/open', { method: 'POST' });
      expect(response.ok).toBe(false);
      expect(await response.json()).toEqual({ error: 'NotFound' });
    });

    it('a shell that cannot reach the relay is a network failure', async () => {
      const failing: Invoke = async () => {
        throw new Error('Network');
      };
      await expect(ipcFetch(failing)('/api/secrets', { method: 'POST', body: '{}' })).rejects.toThrow();
    });

    describe('adversary', () => {
      it('refuses any other authorization than a bearer session', async () => {
        for (const value of ['Basic dXNlcjpwYXNz', 'bearer x', 'Bearer', 'Bearer  x', 'Token x']) {
          await expect(ipcFetch(recording({ status: 200, body: '{}' }))('/api/account/close', { method: 'POST', headers: { Authorization: value } })).rejects.toThrow();
        }
      });

      it('refuses anything outside the relay API before reaching the shell', async () => {
        const calls: Call[] = [];
        const fetch = ipcFetch(recording({ status: 200, body: '{}' }, calls));
        for (const url of ['https://evil.example/api/secrets', '//evil.example/api/secrets', '/apix/secrets', '/secrets', 'api/secrets']) {
          await expect(fetch(url, { method: 'POST' })).rejects.toThrow();
        }
        expect(calls).toEqual([]);
      });

      it('a malformed shell reply is not mistaken for an answer', async () => {
        for (const reply of [null, {}, { status: '200', body: '{}' }, { status: 200 }, { status: 99, body: '' }, { status: 600, body: '' }]) {
          await expect(ipcFetch(recording(reply))('/api/secrets', { method: 'POST', body: '{}' })).rejects.toThrow();
        }
      });

      it('a body that is not text is refused rather than stringified', async () => {
        await expect(ipcFetch(recording({ status: 200, body: '{}' }))('/api/secrets', { method: 'POST', body: new Blob(['x']) })).rejects.toThrow();
      });
    });
  });

  describe('content security policy of the app', () => {
    const page = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; base-uri 'none'" />`;

    it('lets the page reach only its own bundle and the app shell, never the network', () => {
      const html = appCsp(page);
      expect(html).toContain("connect-src 'self' ipc: http://ipc.localhost;");
      expect(html).not.toMatch(/https?:\/\/(?!ipc\.localhost)/);
      expect(html).toContain("script-src 'self' 'wasm-unsafe-eval'");
    });

    it('fails the build instead of shipping a page without the policy', () => {
      expect(() => appCsp('<html></html>')).toThrow();
    });
  });
});
