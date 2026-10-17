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

    it('hands a file chunk to the shell in base64url', async () => {
      const calls: Call[] = [];
      const chunk = new Uint8Array([0, 1, 2, 250, 251, 255]);
      const response = await ipcFetch(recording({ status: 201, body: '{}' }, calls))('/api/secrets/abc/chunks/3', { method: 'POST', body: chunk });
      expect(calls).toEqual([{ cmd: 'relay', args: { method: 'POST', path: '/secrets/abc/chunks/3', body: 'AAEC-vv_' } }]);
      expect(response.status).toBe(201);
    });

    it('gives a chunk from the shell back as bytes', async () => {
      const response = await ipcFetch(recording({ status: 200, body: 'AAEC-vv_', binary: true }))('/api/secrets/abc/chunks/0/open', { method: 'POST', body: '{}' });
      expect(response.headers.get('Content-Type')).toBe('application/octet-stream');
      expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([0, 1, 2, 250, 251, 255]));
    });

    it('a shell that cannot reach the relay is a network failure', async () => {
      const failing: Invoke = async () => {
        throw new Error('Network');
      };
      await expect(ipcFetch(failing)('/api/secrets', { method: 'POST', body: '{}' })).rejects.toThrow();
    });

    describe('adversary', () => {
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

      it('a chunk reply that is not canonical base64url is not mistaken for a chunk', async () => {
        for (const reply of [
          { status: 200, body: 'AAEC+vv/', binary: true },
          { status: 200, body: 'AQJ', binary: true },
          { status: 200, body: 'AQI=', binary: true },
          { status: 200, body: 'AQI', binary: 'yes' },
        ]) {
          await expect(ipcFetch(recording(reply))('/api/secrets/abc/chunks/0/open', { method: 'POST', body: '{}' })).rejects.toThrow();
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
