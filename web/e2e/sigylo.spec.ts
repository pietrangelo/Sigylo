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

test('request mode: sealed to the recipient’s post-quantum key', async ({ page, browser }) => {
  await page.goto('/');
  await page.getByTestId('tab-receive').click();
  await page.getByTestId('create-request').click();
  const requestLink = await page.getByTestId('request-link').inputValue();
  const inboxLink = await page.getByTestId('inbox-link').inputValue();

  const sender = await freshPage(browser);
  await sender.goto(requestLink);
  await sender.getByTestId('secret').fill(SECRET);
  await sender.getByTestId('answer').click();
  await expect(sender.getByTestId('answered')).toBeVisible();

  const recipient = await freshPage(browser);
  await recipient.goto(inboxLink);
  await recipient.getByTestId('reveal').click();
  await expect(recipient.getByTestId('plaintext')).toHaveValue(SECRET);
});

test.describe('adversary', () => {
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

// Argon2id (64 MiB) runs on every sign-up and sign-in: give it time on a busy runner.
const ARGON = { timeout: 30_000 };

test('account: sign up, keep seals across devices, destroy one, close the account', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const name = `e2e-${Date.now().toString(36)}`;
  const password = 'una password lunga e mia 🔑';
  const wire: string[] = [];
  page.on('request', (r: Request) => wire.push(`${r.url()} ${r.postData() ?? ''} ${JSON.stringify(r.headers())}`));

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
  const laptop = await freshPage(browser);
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

  const reader = await freshPage(browser);
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
