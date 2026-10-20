// Drives the built app through WebDriver (tauri-driver + WebKitWebDriver) and
// checks, in the real webview, what the unit tests can only assume: the page
// has no network and no Tauri API beyond its two commands, and the webview
// never leaves the bundle. Nothing here talks to the production relay.
//
//   node app/smoke/smoke.mjs <app binary> <downloads dir>   (tauri-driver on :4444)

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const DRIVER = 'http://127.0.0.1:4444';
// The downloads folder app-smoke.sh gives the app.
const DOWNLOADS = process.argv[3];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function wd(method, path, body) {
  const response = await fetch(DRIVER + path, { method, headers: { 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) });
  const { value } = await response.json();
  if (value?.error) throw new Error(`${path}: ${value.error} ${value.message}`);
  return value;
}

const { sessionId } = await wd('POST', '/session', { capabilities: { alwaysMatch: { 'tauri:options': { application: process.argv[2] } } } });
const run = (script) => wd('POST', `/session/${sessionId}/execute/sync`, { script, args: [] });
const runAsync = (script) => wd('POST', `/session/${sessionId}/execute/async`, { script: `const done = arguments[arguments.length - 1]; ${script}`, args: [] });
const url = () => wd('GET', `/session/${sessionId}/url`);

// Compare scheme and host, not a prefix: http://tauri.localhost.evil.example is not the bundle.
const inBundle = (u) => {
  const { protocol, host } = new URL(u);
  return (protocol === 'tauri:' && host === 'localhost') || (protocol === 'http:' && host === 'tauri.localhost');
};

let failures = 0;
function check(name, actual, expected) {
  const ok = typeof expected === 'function' ? expected(actual) : actual === expected;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}: ${JSON.stringify(actual)}`);
  if (!ok) failures++;
}

try {
  for (let i = 0; i < 50 && !(await run('return !!document.querySelector("[data-testid=paste-link]")')); i++) await sleep(200);
  check('serves the bundle', await url(), inBundle);
  check('shows the app view with the paste box', await run('return !!document.querySelector("[data-testid=paste-link]")'), true);
  check('exposes no global Tauri API', await run('return typeof window.__TAURI__'), 'undefined');
  check(
    'the page cannot reach the network',
    await runAsync('fetch("https://example.com/", { cache: "no-store" }).then(() => done("reached"), () => done("blocked"))'),
    'blocked',
  );
  check(
    'the relay command refuses calls outside the API',
    await runAsync('window.__TAURI_INTERNALS__.invoke("relay", { method: "GET", path: "/admin", body: null }).then(() => done("sent"), (e) => done(String(e)))'),
    'UnknownRoute',
  );
  check(
    'plugin commands are not granted',
    await runAsync('window.__TAURI_INTERNALS__.invoke("plugin:opener|open_url", { url: "https://example.com/" }).then(() => done("allowed"), () => done("refused"))'),
    'refused',
  );
  check(
    'the shell opens no page but the legal ones',
    await runAsync('window.__TAURI_INTERNALS__.invoke("open_legal", { page: "https://example.com/" }).then(() => done("opened"), (e) => done(String(e)))'),
    'UnknownPage',
  );
  await run(`const input = document.querySelector("#paste"); input.value = "https://evil.example/#/s/AAECAwQFBgcICQoLDA0ODw/AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8"; input.dispatchEvent(new Event("input", { bubbles: true })); document.querySelector("[data-testid=paste-link] button").click();`);
  await sleep(300);
  check('a pasted foreign link is refused', await run('return !!document.querySelector("[data-testid=paste-link] [role=alert]")'), true);
  check('and nothing navigated', await run('return location.hash'), '');
  // Saving an opened file: the page hands the webview an octet-stream blob,
  // exactly as files.ts saveFile does, and it must land in the downloads.
  await run(`const url = URL.createObjectURL(new Blob([new TextEncoder().encode("sealed bytes")], { type: "application/octet-stream" })); const a = document.createElement("a"); a.href = url; a.download = "smoke-check.bin"; a.rel = "noopener"; document.body.append(a); a.click(); a.remove();`);
  const saved = join(DOWNLOADS, 'smoke-check.bin');
  for (let i = 0; i < 50 && !existsSync(saved); i++) await sleep(200);
  check('a saved file lands in the downloads', existsSync(saved) && readFileSync(saved, 'utf8'), 'sealed bytes');
  check('and the page stays where it was', await url(), inBundle);
  await run('location.href = "https://example.com/"');
  await sleep(1500);
  check('the webview never leaves the bundle', await url(), inBundle);
} finally {
  await wd('DELETE', `/session/${sessionId}`).catch(() => {});
}

if (failures > 0) {
  console.error(`${failures} check(s) failed`);
  process.exit(1);
}
