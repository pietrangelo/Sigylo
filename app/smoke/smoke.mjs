// Drives the built app through WebDriver (tauri-driver + WebKitWebDriver) and
// checks, in the real webview, what the unit tests can only assume: the page
// has no network and no Tauri API beyond its two commands, and the webview
// never leaves the bundle. Nothing here talks to the production relay.
//
//   node app/smoke/smoke.mjs <path to the app binary>   (tauri-driver on :4444)

const DRIVER = 'http://127.0.0.1:4444';
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

let failures = 0;
function check(name, actual, expected) {
  const ok = typeof expected === 'function' ? expected(actual) : actual === expected;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}: ${JSON.stringify(actual)}`);
  if (!ok) failures++;
}

try {
  for (let i = 0; i < 50 && !(await run('return !!document.querySelector("[data-testid=paste-link]")')); i++) await sleep(200);
  check('serves the bundle', await url(), (u) => u.startsWith('tauri://localhost') || u.startsWith('http://tauri.localhost'));
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
  await run('location.href = "https://example.com/"');
  await sleep(1500);
  check('the webview never leaves the bundle', await url(), (u) => !u.includes('example.com'));
} finally {
  await wd('DELETE', `/session/${sessionId}`).catch(() => {});
}

if (failures > 0) {
  console.error(`${failures} check(s) failed`);
  process.exit(1);
}
