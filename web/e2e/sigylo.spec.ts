import { expect, test, type Browser, type Page, type Request } from '@playwright/test';
import { catalogs } from '../src/lib/i18n';
import { legal } from '../src/lib/legal';

const SECRET = 'password del DB: cavallo-corretto-batteria-graffetta 🔐';

async function freshPage(browser: Browser): Promise<Page> {
  const context = await browser.newContext();
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
