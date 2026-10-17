<script lang="ts">
  import { parseFragment, type Route } from './lib/links';
  import { t } from './lib/i18n';
  import Compose from './components/Compose.svelte';
  import Opener from './components/Opener.svelte';
  import Answer from './components/Answer.svelte';
  import Revoke from './components/Revoke.svelte';
  import Legal from './components/Legal.svelte';
  import Account from './components/Account.svelte';
  import { signedIn } from './lib/session.svelte';
  import Me from './components/Me.svelte';
  import PasteLink from './components/PasteLink.svelte';
  import { isApp, openLegal } from './lib/platform';

  let route: Route = $state(parseFragment(location.hash));

  $effect(() => {
    const onHash = () => (route = parseFragment(location.hash));
    addEventListener('hashchange', onHash);
    return () => removeEventListener('hashchange', onHash);
  });
</script>

<main>
  <header>
    <a class="brand" href="#/">
      <svg viewBox="0 0 64 64" aria-hidden="true">
        <circle cx="32" cy="32" r="28" class="wax" />
        <circle cx="32" cy="32" r="22" class="ring" />
        <path d="M38 24c-2-3-11-3-12 2s12 5 12 10-10 6-13 2" class="mark" />
      </svg>
      <span>{t.home}</span>
    </a>
    <a class="account" href="#/account" data-testid="account-link">{signedIn.session ? t.accountMine : t.accountLink}</a>
    <p class="muted">{t.tagline}</p>
  </header>

  {#key route}
    {#if route.kind === 'compose'}
      {#if isApp}<PasteLink />{/if}
      <Compose />
    {:else if route.kind === 'secret'}
      <Opener mode="link" id={route.id} secret={route.key} expectsPassphrase={route.passphrase} />
    {:else if route.kind === 'inbox'}
      <Opener mode="inbox" id={route.id} secret={route.seed} expectsPassphrase={false} expectedSender={route.expectedSender} />
    {:else if route.kind === 'answer'}
      <Answer id={route.id} fingerprint={route.fingerprint} expectedSender={route.expectedSender} />
    {:else if route.kind === 'me'}
      <Me />
    {:else if route.kind === 'revoke'}
      <Revoke id={route.id} token={route.token} />
    {:else if route.kind === 'account'}
      <Account />
    {:else if route.kind === 'terms' || route.kind === 'privacy'}
      <Legal kind={route.kind} />
    {:else}
      <section class="card"><p class="error">{t.invalidLink}</p></section>
    {/if}
  {/key}

  <footer class="muted small">
    <p>{t.footer}</p>
    <!-- A new tab, so a secret link open in this one keeps its fragment; in the app, the system browser. -->
    <nav>
      {#if isApp}
        <button class="link" onclick={() => openLegal('terms')}>{t.termsLink}</button>
        <button class="link" onclick={() => openLegal('privacy')}>{t.privacyLink}</button>
        <!-- The sender identity lives in the app's own storage, so its code is shown here. -->
        <a href="#/me" data-testid="me-link">{t.myCodeLink}</a>
      {:else}
        <a href="#/terms" target="_blank" rel="noopener noreferrer" data-testid="terms-link">{t.termsLink}</a>
        <a href="#/privacy" target="_blank" rel="noopener noreferrer" data-testid="privacy-link">{t.privacyLink}</a>
        <a href="#/me" target="_blank" rel="noopener noreferrer" data-testid="me-link">{t.myCodeLink}</a>
      {/if}
    </nav>
  </footer>
</main>

<style>
  main {
    max-width: var(--column);
    margin: 0 auto;
    padding: var(--s6) var(--s5) var(--s7);
  }

  header {
    margin-bottom: var(--s6);
  }

  .brand {
    display: inline-flex;
    align-items: center;
    gap: var(--s4);
    color: var(--text);
    text-decoration: none;
    font-size: var(--t-display);
    font-weight: 700;
    letter-spacing: -0.02em;
  }

  .account {
    float: right;
    margin-top: var(--s4);
    color: var(--muted);
  }

  .brand svg {
    width: var(--s7);
    height: var(--s7);
  }

  .wax {
    fill: var(--wax);
  }

  .ring {
    fill: none;
    stroke: var(--seal-mark);
    stroke-width: 2.5; /* the S's stroke / φ */
  }

  .mark {
    fill: none;
    stroke: var(--seal-mark);
    stroke-width: 4;
    stroke-linecap: round;
  }

  footer {
    margin-top: var(--s6);
  }

  footer p {
    margin: 0 0 var(--s3);
  }

  footer nav {
    display: flex;
    gap: var(--s4);
  }

  footer a,
  footer .link {
    color: var(--muted);
  }

  footer .link {
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    text-decoration: underline;
    cursor: pointer;
  }
</style>
