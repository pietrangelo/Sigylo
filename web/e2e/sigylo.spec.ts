import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { type Browser, type Page, type Request } from '@playwright/test';
import { expect, test } from './fixtures';
import { catalogs } from '../src/lib/i18n';
import { legal } from '../src/lib/legal';

const SECRET = 'password del DB: cavallo-corretto-batteria-graffetta 🔐';

async function freshPage(browser: Browser, address?: string): Promise<Page> {
  // Its own client address, so the per-address write limit of the rest of the suite does not apply.
  const context = await browser.newContext(address === undefined ? {} : { extraHTTPHeaders: { 'CF-Connecting-IP': address } });
  return context.newPage();
}

async function sealSecret(page: Page, options: { passphrase?: string; retention?: 'burn' | 'expiry' } = {}) {
  await page.goto('/');
  await page.getByTestId('secret').fill(SECRET);
  if (options.retention === 'expiry') await page.getByTestId('retention-expiry').check();
  if (options.passphrase) {
    await page.getByTestId('with-passphrase').check();
    await page.getByTestId('passphrase').fill(options.passphrase);
  }
  await page.getByTestId('seal').click();
  await expect(page.getByTestId('sent')).toBeVisible();
  return {
    link: await page.getByTestId('secret-link').inputValue(),
    revoke: await page.getByTestId('revoke-link').inputValue(),
  };
}

test('burn after reading: opens once with the passphrase, then is gone', async ({ page, browser }) => {
  const { link } = await sealSecret(page, { passphrase: 'seconda chiave' });
  expect(link).toMatch(/\/#\/s\/[A-Za-z0-9_-]{22}\/[A-Za-z0-9_-]{43}\/p$/);

  const reader = await freshPage(browser);
  await reader.goto(link);
  await reader.getByTestId('open-passphrase').fill('sbagliata');
  await reader.getByTestId('reveal').click();
  await expect(reader.getByTestId('open-error')).toBeVisible();
  // The envelope was burned by that read but is still in memory: retry works.
  await reader.getByTestId('open-passphrase').fill('seconda chiave');
  await reader.getByTestId('reveal').click();
  await expect(reader.getByTestId('plaintext')).toHaveValue(SECRET);
  await expect(reader.getByTestId('retention-note')).toHaveClass(/notice/);
  expect(new URL(reader.url()).hash).toBe('');

  const latecomer = await freshPage(browser);
  await latecomer.goto(link);
  await latecomer.getByTestId('open-passphrase').fill('seconda chiave');
  await latecomer.getByTestId('reveal').click();
  await expect(latecomer.getByTestId('open-error')).toContainText('Non c');
});

// 2.5 MiB: three chunks, the last one short. The marker sits at both ends.
const MARKER = 'contenuto riservato del file 4c1d';
function fileContents(): Buffer {
  const contents = Buffer.alloc(2.5 * 1024 * 1024, 0x2e);
  contents.write(MARKER, 0);
  contents.write(MARKER, contents.length - MARKER.length);
  return contents;
}

async function sealFile(page: Page, options: { retention?: 'burn' | 'expiry' } = {}) {
  await page.goto('/');
  await page.getByTestId('kind-file').check();
  await page.getByTestId('file').setInputFiles({ name: 'Bilancio 2026 è pronto.xlsx', mimeType: 'text/html', buffer: fileContents() });
  if (options.retention === 'expiry') await page.getByTestId('retention-expiry').check();
  await page.getByTestId('seal').click();
  await expect(page.getByTestId('sent')).toBeVisible();
  return { link: await page.getByTestId('secret-link').inputValue(), revoke: await page.getByTestId('revoke-link').inputValue() };
}

async function openAndSave(reader: Page, link: string): Promise<{ name: string; contents: Buffer }> {
  await reader.goto(link);
  await reader.getByTestId('reveal').click();
  await expect(reader.getByTestId('file-name')).toHaveText('Bilancio 2026 è pronto.xlsx');
  const [download] = await Promise.all([reader.waitForEvent('download'), reader.getByTestId('save-file').click()]);
  return { name: download.suggestedFilename(), contents: await readFile((await download.path())!) };
}

test('a file sealed by link: saved once, then gone', async ({ page, browser }) => {
  const { link } = await sealFile(page);
  const reader = await freshPage(browser);
  const saved = await openAndSave(reader, link);
  expect(saved.name).toBe('Bilancio 2026 è pronto.xlsx');
  expect(saved.contents.equals(fileContents())).toBe(true);
  await expect(reader.getByTestId('retention-note')).toHaveClass(/notice/);
  expect(new URL(reader.url()).hash).toBe('');

  const latecomer = await freshPage(browser);
  await latecomer.goto(link);
  await latecomer.getByTestId('reveal').click();
  await expect(latecomer.getByTestId('open-error')).toContainText('Non c');
});

test('a file kept until expiry can be saved more than once', async ({ page, browser }) => {
  const { link } = await sealFile(page, { retention: 'expiry' });
  for (let i = 0; i < 2; i++) {
    const saved = await openAndSave(await freshPage(browser), link);
    expect(saved.contents.equals(fileContents())).toBe(true);
  }
});

/** One value from the e2e database (scripts/e2e.sh passes its URL). */
function sql(query: string): string {
  return execFileSync('psql', [process.env.SIGYLO_E2E_DATABASE_URL!, '-tAXc', query], { encoding: 'utf8' }).trim();
}

/** How many objects the local R2 bucket holds (scripts/e2e.sh passes its state directory). */
function r2Objects(): number {
  try {
    return readdirSync(`${process.env.SIGYLO_E2E_STATE}/v3/r2/sigylo-chunks/blobs`).length;
  } catch {
    return 0;
  }
}

test('a file’s chunks live in R2, never in the database, and leave R2 once revoked', async ({ page, request }) => {
  test.skip(!process.env.SIGYLO_E2E_DATABASE_URL, 'needs scripts/e2e.sh');
  const before = r2Objects();
  const { revoke } = await sealFile(page, { retention: 'expiry' });
  expect(r2Objects()).toBe(before + 3);
  // 2.5 MiB of chunks went by, but the database holds only names and sizes.
  expect(Number(sql("select pg_total_relation_size('custody.chunks')"))).toBeLessThan(256 * 1024);
  expect(Number(sql('select coalesce(max(size), 0) from custody.chunks'))).toBe(1024 * 1024 + 16);

  const sender = await page.context().newPage();
  await sender.goto(revoke);
  await sender.getByTestId('revoke').click();
  await expect(sender.getByTestId('revoked')).toBeVisible();
  // Revoking deletes a file's chunks from R2 at once, not at the next cron,
  // so revoking in a loop cannot pile objects up in R2.
  await expect.poll(r2Objects).toBe(before);
  expect(sql('select count(*) from custody.garbage')).toBe('0');
  // The cron (every 15 minutes in production) still runs cleanly.
  const cron = await request.post('/cdn-cgi/local/explorer/api/local/scheduled?worker=sigylo&cron=*/15+*+*+*+*', {
    data: { cron: '*/15 * * * *' },
  });
  expect(cron.ok(), await cron.text()).toBe(true);
});

test('request mode: a file sealed to the recipient’s post-quantum key', async ({ page, browser }) => {
  await page.goto('/');
  await page.getByTestId('tab-receive').click();
  await page.getByTestId('create-request').click();
  const requestLink = await page.getByTestId('request-link').inputValue();
  const inboxLink = await page.getByTestId('inbox-link').inputValue();

  const sender = await freshPage(browser);
  await sender.goto(requestLink);
  await sender.getByTestId('kind-file').check();
  await sender.getByTestId('file').setInputFiles({ name: 'Bilancio 2026 è pronto.xlsx', mimeType: 'application/vnd.ms-excel', buffer: fileContents() });
  await sender.getByTestId('answer').click();
  await expect(sender.getByTestId('answered')).toBeVisible();

  const saved = await openAndSave(await freshPage(browser), inboxLink);
  expect(saved.contents.equals(fileContents())).toBe(true);
});

test('until expiry: readable more than once', async ({ page, browser }) => {
  const { link } = await sealSecret(page, { retention: 'expiry' });
  for (let i = 0; i < 2; i++) {
    const reader = await freshPage(browser);
    await reader.goto(link);
    await reader.getByTestId('reveal').click();
    await expect(reader.getByTestId('plaintext')).toHaveValue(SECRET);
    await expect(reader.getByTestId('retention-note')).toHaveClass(/success/);
  }
});

test('the sender can destroy a secret before it is read', async ({ page, browser }) => {
  const { link, revoke } = await sealSecret(page);
  const sender = await freshPage(browser);
  await sender.goto(revoke);
  await sender.getByTestId('revoke').click();
  await expect(sender.getByTestId('revoked')).toBeVisible();

  const reader = await freshPage(browser);
  await reader.goto(link);
  await reader.getByTestId('reveal').click();
  await expect(reader.getByTestId('open-error')).toBeVisible();
});

async function createRequest(page: Page, expectedSender?: string): Promise<{ requestLink: string; inboxLink: string }> {
  await page.goto('/');
  await page.getByTestId('tab-receive').click();
  if (expectedSender !== undefined) await page.getByTestId('expected-sender').fill(expectedSender);
  await page.getByTestId('create-request').click();
  return {
    requestLink: await page.getByTestId('request-link').inputValue(),
    inboxLink: await page.getByTestId('inbox-link').inputValue(),
  };
}

const SENDER_CODE = /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){4}$/;

test('request mode: sealed to the recipient’s post-quantum key and signed by the sender', async ({ page, browser }) => {
  const { requestLink, inboxLink } = await createRequest(page);

  const sender = await freshPage(browser);
  await sender.goto(requestLink);
  await expect(sender.getByTestId('sender-code')).toHaveText(SENDER_CODE);
  const code = await sender.getByTestId('sender-code').textContent();
  await sender.getByTestId('secret').fill(SECRET);
  await sender.getByTestId('answer').click();
  await expect(sender.getByTestId('answered')).toBeVisible();

  const recipient = await freshPage(browser);
  await recipient.goto(inboxLink);
  await recipient.getByTestId('reveal').click();
  await expect(recipient.getByTestId('plaintext')).toHaveValue(SECRET);
  await expect(recipient.getByTestId('sender-code')).toHaveText(code!);
  await expect(recipient.getByTestId('unsigned')).toHaveCount(0);
});

async function senderCodeOf(page: Page): Promise<string> {
  await page.goto('/#/me');
  await expect(page.getByTestId('sender-code')).toHaveText(SENDER_CODE);
  return (await page.getByTestId('sender-code').textContent())!;
}

test('a request can wait for one expected sender, and only that sender', async ({ page, browser }) => {
  const alice = await freshPage(browser);
  const code = await senderCodeOf(alice);
  await alice.reload();
  await expect(alice.getByTestId('sender-code'), 'the code survives a reload').toHaveText(code);
  // Typed loosely, as dictated over the phone.
  const { requestLink, inboxLink } = await createRequest(page, code.toLowerCase().replaceAll('-', ' '));
  expect(requestLink).not.toContain(code);
  expect(requestLink.split('/')).toHaveLength(8);

  const stranger = await freshPage(browser);
  await stranger.goto(requestLink);
  await expect(stranger.getByTestId('not-expected')).toBeVisible();
  await expect(stranger.getByTestId('sender-code'), 'another browser is another sender').not.toHaveText(code);
  await expect(stranger.getByTestId('answer')).toHaveCount(0);

  await alice.goto(requestLink);
  await alice.getByTestId('secret').fill(SECRET);
  await alice.getByTestId('answer').click();
  await expect(alice.getByTestId('answered')).toBeVisible();

  const recipient = await freshPage(browser);
  await recipient.goto(inboxLink);
  await recipient.getByTestId('reveal').click();
  await expect(recipient.getByTestId('plaintext')).toHaveValue(SECRET);
  await expect(recipient.getByTestId('sender-code')).toHaveText(code);
});

test.describe('adversary', () => {
  test('an answer from anyone but the expected sender is refused unread, even bypassing the page', async ({ page, browser }) => {
    const alice = await freshPage(browser);
    const { requestLink, inboxLink } = await createRequest(page, await senderCodeOf(alice));
    // Mallory drops the pin from the request link, so her page lets her answer.
    const mallory = await freshPage(browser);
    await mallory.goto(requestLink.replace(/\/[A-Za-z0-9_-]{43}$/, ''));
    await mallory.getByTestId('secret').fill('a fake secret from mallory');
    await mallory.getByTestId('answer').click();
    await expect(mallory.getByTestId('answered')).toBeVisible();
    // The real sender learns the request was used up.
    await alice.goto(requestLink);
    await alice.getByTestId('secret').fill(SECRET);
    await alice.getByTestId('answer').click();
    await expect(alice.getByTestId('answer-error')).toHaveText(catalogs.it.requestGone);

    const recipient = await freshPage(browser);
    await recipient.goto(inboxLink);
    await recipient.getByTestId('reveal').click();
    await expect(recipient.getByTestId('open-error')).toHaveText(catalogs.it.errUnexpectedSender);
    await expect(recipient.getByTestId('plaintext')).toHaveCount(0);
  });

  test('a mistyped expected sender code is refused before any request exists', async ({ page }) => {
    const posts: Request[] = [];
    page.on('request', (r) => r.url().includes('/api/requests') && posts.push(r));
    await page.goto('/');
    await page.getByTestId('tab-receive').click();
    await page.getByTestId('expected-sender').fill('GHDW-RWEX-C79Z-J2JG-YKF');
    await page.getByTestId('create-request').click();
    await expect(page.getByRole('alert')).toHaveText(catalogs.it.errSenderCode);
    expect(posts).toHaveLength(0);
  });

  test('a request link with another fingerprint refuses to seal and sends nothing', async ({ page, browser }) => {
    await page.goto('/');
    await page.getByTestId('tab-receive').click();
    await page.getByTestId('create-request').click();
    const requestLink = await page.getByTestId('request-link').inputValue();
    const forged = requestLink.replace(/\/[A-Za-z0-9_-]{43}$/, `/${'A'.repeat(42)}Q`);

    const victim = await freshPage(browser);
    const answers: Request[] = [];
    victim.on('request', (r) => r.url().includes('/answer') && answers.push(r));
    await victim.goto(forged);
    await victim.getByTestId('secret').fill(SECRET);
    await victim.getByTestId('answer').click();
    await expect(victim.getByTestId('answer-error')).toContainText('non corrisponde');
    expect(answers).toHaveLength(0);
  });

  test('no key, passphrase or plaintext ever leaves the browser', async ({ page, browser }) => {
    const outgoing: { url: string; body: string }[] = [];
    const record = (r: Request) => outgoing.push({ url: r.url(), body: r.postData() ?? '' });
    page.on('request', record);
    const { link } = await sealSecret(page, { passphrase: 'seconda chiave' });

    const reader = await freshPage(browser);
    reader.on('request', record);
    await reader.goto(link);
    await reader.getByTestId('open-passphrase').fill('seconda chiave');
    await reader.getByTestId('reveal').click();
    await expect(reader.getByTestId('plaintext')).toHaveValue(SECRET);

    const key = link.split('/').at(-2)!;
    const origin = new URL(link).origin;
    for (const { url, body } of outgoing) {
      expect(new URL(url).origin, url).toBe(origin);
      for (const leak of [key, 'seconda chiave', 'cavallo-corretto']) {
        expect(url.includes(leak) || body.includes(leak), `${leak} leaked in ${url}`).toBe(false);
      }
    }
  });

  test('no file byte, file name or key leaves the browser unsealed', async ({ page, browser }) => {
    const outgoing: { url: string; body: Buffer }[] = [];
    const record = (r: Request) => outgoing.push({ url: r.url(), body: r.postDataBuffer() ?? Buffer.alloc(0) });
    page.on('request', record);
    const { link } = await sealFile(page);
    const reader = await freshPage(browser);
    reader.on('request', record);
    await openAndSave(reader, link);

    const key = link.split('/').at(-1)!;
    expect(outgoing.filter((o) => o.url.includes('/chunks/')).length).toBe(6);
    for (const { url, body } of outgoing) {
      for (const leak of [key, MARKER, 'Bilancio']) {
        expect(url.includes(leak) || body.includes(leak), `${leak} leaked in ${url}`).toBe(false);
      }
    }
  });

  test('chunks of a burned file go only to whoever opened it', async ({ page, request, browser }) => {
    const { link } = await sealFile(page);
    const id = link.split('/').at(-2)!;
    // Before anyone opens it, chunks are not served, and a GET never is.
    expect((await request.get(`/api/secrets/${id}/chunks/0/open`)).status()).toBe(405);
    expect((await request.post(`/api/secrets/${id}/chunks/0/open`, { data: {} })).status()).toBe(404);

    const reader = await freshPage(browser);
    const responses: string[] = [];
    reader.on('response', (r) => r.url().endsWith('/open') && !r.url().includes('/chunks/') && responses.push(r.url()));
    await openAndSave(reader, link);
    // Afterwards the chunks are gone, claim or no claim, and nothing can be added,
    // not even a chunk of a size the sealer makes (256 + 16 bytes).
    for (const body of [{}, { claim: 'A'.repeat(43) }]) {
      expect((await request.post(`/api/secrets/${id}/chunks/2/open`, { data: body })).status()).toBe(404);
    }
    const refill = await request.post(`/api/secrets/${id}/chunks/0`, { data: Buffer.alloc(272, 1), headers: { 'Content-Type': 'application/octet-stream' } });
    expect(refill.status()).toBe(404);
    expect(responses).toHaveLength(1);
  });

  test('the page runs under the strict policy without violations', async ({ page }) => {
    const violations: string[] = [];
    page.on('console', (m) => m.text().includes('Content Security Policy') && violations.push(m.text()));
    const response = await page.goto('/');
    const csp = response!.headers()['content-security-policy'] ?? '';
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).not.toContain('unsafe-inline');
    await sealSecret(page);
    expect(violations).toEqual([]);
    for (const tag of await page.locator('script[src], link[rel=stylesheet]').all()) {
      expect(await tag.getAttribute('integrity')).toMatch(/^sha384-/);
    }
  });

  test('whoever burns a secret cannot refill its link', async ({ page, request, browser }) => {
    const { link } = await sealSecret(page);
    const id = link.split('/').at(-2)!;
    const thief = await freshPage(browser);
    await thief.goto(link);
    await thief.getByTestId('reveal').click();
    await expect(thief.getByTestId('plaintext')).toHaveValue(SECRET);
    const payload = 'U0dZAQEA' + 'A'.repeat(400);

    // Choosing the id is refused outright; a plain deposit lands elsewhere.
    const forged = await request.post('/api/secrets', {
      data: { id, payload, retention: 'burn_after_reading', lifetime_seconds: 3600 },
    });
    expect(forged.status()).toBe(400);
    const elsewhere = await request.post('/api/secrets', {
      data: { payload, retention: 'burn_after_reading', lifetime_seconds: 3600 },
    });
    expect(elsewhere.status()).toBe(201);
    expect((await elsewhere.json()).id).not.toBe(id);

    const recipient = await freshPage(browser);
    await recipient.goto(link);
    await recipient.getByTestId('reveal').click();
    await expect(recipient.getByTestId('open-error')).toContainText('Non c');
  });

  test('whoever holds the request link can neither burn nor fetch the answer', async ({ page, request, browser }) => {
    await page.goto('/');
    await page.getByTestId('tab-receive').click();
    await page.getByTestId('create-request').click();
    const requestLink = await page.getByTestId('request-link').inputValue();
    const inboxLink = await page.getByTestId('inbox-link').inputValue();
    const requestId = requestLink.split('/').at(-2)!;
    expect(inboxLink.split('/').at(-2)).not.toBe(requestId);

    const sender = await freshPage(browser);
    await sender.goto(requestLink);
    await sender.getByTestId('secret').fill(SECRET);
    await sender.getByTestId('answer').click();
    await expect(sender.getByTestId('answered')).toBeVisible();

    // Someone who read the request link on its way to the sender tries to burn the answer.
    expect((await request.post(`/api/secrets/${requestId}/open`)).status()).toBe(404);

    const recipient = await freshPage(browser);
    await recipient.goto(inboxLink);
    await recipient.getByTestId('reveal').click();
    await expect(recipient.getByTestId('plaintext')).toHaveValue(SECRET);
  });

  test('a page on another site cannot call the relay', async ({ request }) => {
    const payload = 'U0dZAQEA' + 'A'.repeat(400);
    const data = { payload, retention: 'burn_after_reading', lifetime_seconds: 3600 };
    const foreign = await request.post('/api/secrets', { data, headers: { Origin: 'https://evil.example' } });
    expect(foreign.status()).toBe(403);
    expect(await foreign.json()).toEqual({ error: 'CrossOrigin' });
  });

  test('one client address gets 30 writes a minute, then 429', async ({ request }) => {
    const data = { payload: 'U0dZAQEA' + 'A'.repeat(400), retention: 'burn_after_reading', lifetime_seconds: 300 };
    const headers = { 'CF-Connecting-IP': '2001:db8:7:7::1' };
    // The limiter counts in fixed one-minute windows: a run that straddles two
    // of them gets up to 60 writes through before the 429.
    let allowed = 0;
    while (allowed <= 60 && (await request.post('/api/secrets', { data, headers })).status() === 201) allowed++;
    expect(allowed).toBeGreaterThanOrEqual(30);
    expect(allowed).toBeLessThanOrEqual(60);
    // Another address in the same IPv6 /64 is the same client.
    const next = await request.post('/api/secrets', { data, headers: { 'CF-Connecting-IP': '2001:db8:7:7::2' } });
    expect(next.status()).toBe(429);
  });

  test('a link preview bot (GET) cannot burn a secret', async ({ page, request, browser }) => {
    const { link } = await sealSecret(page);
    const id = link.split('/').at(-2)!;
    const probe = await request.get(`/api/secrets/${id}/open`);
    expect(probe.status()).toBe(405);
    const reader = await freshPage(browser);
    await reader.goto(link);
    await reader.getByTestId('reveal').click();
    await expect(reader.getByTestId('plaintext')).toHaveValue(SECRET);
  });
});

test('the page speaks the browser language', async ({ browser }) => {
  for (const [locale, lang] of [['fr-FR', 'fr'], ['es-ES', 'es'], ['de-DE', 'de'], ['en-US', 'en'], ['it-IT', 'it']] as const) {
    const context = await browser.newContext({ locale });
    const page = await context.newPage();
    await page.goto('/');
    await expect(page.locator('html')).toHaveAttribute('lang', lang);
    await expect(page.getByText(catalogs[lang].tagline)).toBeVisible();
    await expect(page.getByTestId('seal')).toHaveText(catalogs[lang].seal);
    await context.close();
  }
});

test('the footer opens the terms and the privacy notice in a new tab, in the browser language', async ({ browser }) => {
  for (const [locale, lang] of [['it-IT', 'it'], ['de-DE', 'de']] as const) {
    const context = await browser.newContext({ locale });
    const page = await context.newPage();
    const violations: string[] = [];
    context.on('console', (m) => m.text().includes('Content Security Policy') && violations.push(m.text()));
    await page.goto('/');
    for (const [testId, kind] of [['terms-link', 'terms'], ['privacy-link', 'privacy']] as const) {
      const [tab] = await Promise.all([context.waitForEvent('page'), page.getByTestId(testId).click()]);
      await expect(tab.getByRole('heading', { level: 2, name: legal[lang][kind].title })).toBeVisible();
      expect(new URL(tab.url()).hash).toBe(`#/${kind}`);
      await tab.close();
    }
    await expect(page.getByTestId('seal')).toBeVisible();
    expect(violations).toEqual([]);
    await context.close();
  }
});

// Argon2id (64 MiB) runs on every sign-up and sign-in: give it time on a busy runner.
const ARGON = { timeout: 30_000 };

test('account: sign up, keep seals across devices, destroy one, close the account', async ({ browser }) => {
  test.setTimeout(120_000);
  const page = await freshPage(browser, '198.51.100.1');
  const name = `e2e-${Date.now().toString(36)}`;
  const password = 'una password lunga e mia 🔑';
  const wire: string[] = [];
  const listen = (p: Page) => p.on('request', (r: Request) => wire.push(`${r.url()} ${r.postData() ?? ''} ${JSON.stringify(r.headers())}`));
  listen(page);

  await page.goto('/');
  await page.getByTestId('account-link').click();
  await page.getByTestId('tab-sign-up').click();
  await page.getByTestId('username').fill(name);
  await page.getByTestId('password').fill(password);
  await page.getByTestId('account-submit').click();
  await expect(page.getByTestId('signed-in')).toContainText(name, ARGON);
  await expect(page.getByTestId('no-seals')).toBeVisible();

  // Sealed while signed in: the revocation token goes into the sealed keyring.
  await page.locator('.brand').click();
  await page.getByTestId('secret').fill(SECRET);
  await page.getByTestId('seal').click();
  await expect(page.getByTestId('saved-to-account')).toBeVisible(ARGON);
  const link = await page.getByTestId('secret-link').inputValue();

  // Another device: a wrong password opens nothing, the right one shows the seal.
  const laptop = await freshPage(browser, '198.51.100.2');
  listen(laptop);
  await laptop.goto('/#/account');
  await laptop.getByTestId('username').fill(name.toUpperCase());
  await laptop.getByTestId('password').fill('non è la mia password');
  await laptop.getByTestId('account-submit').click();
  await expect(laptop.getByRole('alert')).toHaveText(catalogs.it.errBadLogin, ARGON);
  await laptop.getByTestId('password').fill(password);
  await laptop.getByTestId('account-submit').click();
  await expect(laptop.getByTestId('seals').locator('li')).toHaveCount(1, ARGON);
  await laptop.getByTestId('destroy-seal').click();
  await expect(laptop.getByTestId('no-seals')).toBeVisible();

  const reader = await freshPage(browser, '198.51.100.3');
  await reader.goto(link);
  await reader.getByTestId('reveal').click();
  await expect(reader.getByTestId('open-error')).toContainText('Non c');

  // The first device sees the change, then closes the account.
  await page.getByTestId('account-link').click();
  await expect(page.getByTestId('no-seals')).toBeVisible();
  await page.getByTestId('close-account').click();
  await page.getByTestId('confirm-close').click();
  await expect(page.getByTestId('account-notice')).toHaveText(catalogs.it.closed);
  await page.getByTestId('username').fill(name);
  await page.getByTestId('password').fill(password);
  await page.getByTestId('account-submit').click();
  await expect(page.getByRole('alert')).toHaveText(catalogs.it.errBadLogin, ARGON);

  // OPAQUE: the password never travelled, in any form, in any request.
  const encoded = Buffer.from(password, 'utf8');
  for (const line of wire) {
    expect(line).not.toContain('password lunga');
    expect(line).not.toContain(encoded.toString('base64url'));
    expect(line).not.toContain(encodeURIComponent(password));
  }
  expect(wire.some((l) => l.includes('/api/account/login/finish'))).toBe(true);
});

test('account: signing out everywhere ends every device, and the next login shows the device pass', async ({ browser, request }) => {
  test.setTimeout(120_000);
  const page = await freshPage(browser, '203.0.113.71');
  const name = `e2e-${Date.now().toString(36)}`;
  const password = 'una password lunga e mia 🔑';
  const starts: string[] = [];
  page.on('request', (r: Request) => {
    if (r.url().endsWith('/api/account/login/start')) starts.push(r.postData() ?? '');
  });
  await page.goto('/#/account');
  await page.getByTestId('tab-sign-up').click();
  await page.getByTestId('username').fill(name);
  await page.getByTestId('password').fill(password);
  await page.getByTestId('account-submit').click();
  await expect(page.getByTestId('signed-in')).toContainText(name, ARGON);

  const laptop = await freshPage(browser, '203.0.113.72');
  await laptop.goto('/#/account');
  await laptop.getByTestId('username').fill(name);
  await laptop.getByTestId('password').fill(password);
  await laptop.getByTestId('account-submit').click();
  await expect(laptop.getByTestId('signed-in')).toContainText(name, ARGON);

  await page.getByTestId('sign-out-everywhere').click();
  await expect(page.getByTestId('account-notice')).toHaveText(catalogs.it.signedOutEverywhere);
  // The laptop's session is gone too: its next keyring read is refused.
  await laptop.locator('.brand').click();
  await laptop.getByTestId('account-link').click();
  await expect(laptop.getByTestId('username')).toBeVisible();

  // Signing in again from the first device shows the pass its last login received.
  await page.getByTestId('tab-sign-in').click();
  await page.getByTestId('username').fill(name);
  await page.getByTestId('password').fill(password);
  await page.getByTestId('account-submit').click();
  await expect(page.getByTestId('signed-in')).toContainText(name, ARGON);
  expect(starts).toHaveLength(2);
  expect(JSON.parse(starts[0]!)).not.toHaveProperty('pass');
  expect(JSON.parse(starts[1]!).pass).toMatch(/^[A-Za-z0-9_-]{75}$/);

  // The relay names the secret it runs on (the one scripts/e2e.sh configures).
  const canary = await request.get('/api/account/canary', { headers: { 'CF-Connecting-IP': '203.0.113.73' } });
  expect(canary.status()).toBe(200);
  expect(await canary.json()).toEqual({ canary: 'voB1TN7wcGcZY8Ms-nY-RlT9xSOkkNM1KZPxcTdw61k' });
});

test('account: a relay serving an older copy of the keyring is caught, and nothing is overwritten', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/#/account');
  await page.getByTestId('tab-sign-up').click();
  await page.getByTestId('username').fill(`e2e-rb-${Date.now().toString(36)}`);
  await page.getByTestId('password').fill('una password lunga e mia 🔑');
  await page.getByTestId('account-submit').click();
  await expect(page.getByTestId('no-seals')).toBeVisible(ARGON);

  // Two seals: the keyring read before the second one is the older copy.
  const reads: string[] = [];
  page.on('response', async (r) => {
    if (r.url().endsWith('/api/account/keyring') && r.request().method() === 'GET') reads.push(await r.text());
  });
  for (let i = 0; i < 2; i++) {
    if (i === 0) await page.locator('.brand').click();
    else await page.getByRole('button', { name: catalogs.it.another }).click();
    await page.getByTestId('secret').fill(SECRET);
    await page.getByTestId('seal').click();
    await expect(page.getByTestId('saved-to-account')).toBeVisible(ARGON);
  }
  const older = reads.at(-1)!;
  expect(JSON.parse(older).version).toBe(1);

  // From now on the relay hands back that older copy; no write may reach it.
  const writes: string[] = [];
  await page.route('**/api/account/keyring', (route) => {
    if (route.request().method() === 'GET') return route.fulfill({ status: 200, contentType: 'application/json', body: older });
    writes.push(route.request().method());
    return route.abort();
  });
  await page.getByTestId('account-link').click();
  await expect(page.getByRole('alert')).toHaveText(catalogs.it.errKeyringRolledBack);
  await page.locator('.brand').click();
  await page.getByTestId('secret').fill(SECRET);
  await page.getByTestId('seal').click();
  await expect(page.getByTestId('sent')).toBeVisible();
  await expect(page.getByText(catalogs.it.notSaved)).toBeVisible();
  expect(writes).toEqual([]);
});

test('request mode: a file answer whose upload broke is finished by a retry, not lost', async ({ page, browser }) => {
  const { requestLink, inboxLink } = await createRequest(page);
  const sender = await freshPage(browser);
  // Chunk 1 reaches the relay and is stored, but the reply is lost on the way back.
  await sender.route(
    '**/chunks/1',
    async (route) => {
      await route.fetch();
      await route.abort('connectionreset');
    },
    { times: 1 },
  );
  await sender.goto(requestLink);
  await sender.getByTestId('kind-file').check();
  await sender.getByTestId('file').setInputFiles({ name: 'Bilancio 2026 è pronto.xlsx', mimeType: 'application/vnd.ms-excel', buffer: fileContents() });
  await sender.getByTestId('answer').click();
  await expect(sender.getByTestId('answer-error')).toHaveText(catalogs.it.errNetwork);
  const sent: string[] = [];
  sender.on('request', (r) => {
    if (r.url().includes('/chunks/')) sent.push(r.url().replace(/.*\/chunks\//, ''));
  });
  await sender.getByTestId('retry-upload').click();
  await expect(sender.getByTestId('answered')).toBeVisible();
  // Chunk 0 is not sent again; chunk 1 answers 404 (already in), chunk 2 goes up.
  expect(sent).toEqual(['1', '2']);

  const saved = await openAndSave(await freshPage(browser), inboxLink);
  expect(saved.contents.equals(fileContents())).toBe(true);
});

test('a file deposit whose upload broke is finished by a retry', async ({ page, browser }) => {
  // The connection drops before chunk 2 reaches the relay.
  await page.route('**/chunks/2', (route) => route.abort('connectionreset'), { times: 1 });
  await page.goto('/');
  await page.getByTestId('kind-file').check();
  await page.getByTestId('file').setInputFiles({ name: 'Bilancio 2026 è pronto.xlsx', mimeType: 'text/html', buffer: fileContents() });
  await page.getByTestId('seal').click();
  await expect(page.getByTestId('seal-error')).toHaveText(catalogs.it.errNetwork);
  await page.getByTestId('retry-upload').click();
  await expect(page.getByTestId('sent')).toBeVisible();
  const saved = await openAndSave(await freshPage(browser), await page.getByTestId('secret-link').inputValue());
  expect(saved.contents.equals(fileContents())).toBe(true);
});
