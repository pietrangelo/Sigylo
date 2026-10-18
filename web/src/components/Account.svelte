<script lang="ts">
  import { Accounts } from '../lib/account';
  import { engine, loadEngine } from '../lib/crypto';
  import { decodeExact } from '../lib/base64url';
  import { t } from '../lib/i18n';
  import { removeSeal, type Seal } from '../lib/keyring';
  import { accountMessage, formatExpiry, relayMessage } from '../lib/messages';
  import { relayFetch } from '../lib/platform';
  import { Relay } from '../lib/relay';
  import { currentSession, signedIn } from '../lib/session.svelte';

  const relay = new Relay(relayFetch);
  const accounts = new Accounts(engine, relay);

  let mode: 'signIn' | 'signUp' = $state('signIn');
  let username = $state('');
  let password = $state('');
  let busy = $state(false);
  let error = $state('');
  let notice = $state('');
  let seals: Seal[] = $state([]);
  let confirmingClose = $state(false);

  const session = $derived(signedIn.session);

  $effect(() => {
    if (session !== null) void refresh();
  });

  async function refresh() {
    const live = currentSession();
    if (live === null) return;
    const result = await accounts.keyring(live);
    if (result.ok) {
      const now = Math.floor(Date.now() / 1000);
      seals = result.value.data.seals.filter((s) => s.expires > now);
    } else {
      fail(result.error);
    }
  }

  function fail(code: Parameters<typeof accountMessage>[0]) {
    error = accountMessage(code);
    if (code === 'Unauthorized') signedIn.session = null;
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = '';
    notice = '';
    try {
      await loadEngine();
      const result = mode === 'signUp' ? await accounts.register(username, password) : await accounts.signIn(username, password);
      password = '';
      if (result.ok) {
        signedIn.session = result.value;
        username = '';
      } else {
        fail(result.error);
      }
    } finally {
      busy = false;
    }
  }

  async function destroy(seal: Seal) {
    const live = currentSession();
    const id = decodeExact(seal.id, 16);
    const token = decodeExact(seal.token, 32);
    if (live === null || id === null || token === null) return;
    error = '';
    const revoked = await relay.revoke(id, token);
    // Gone already (read, expired or destroyed elsewhere) is as good as destroyed.
    if (!revoked.ok && revoked.error !== 'NotFound') {
      error = relayMessage(revoked.error);
      return;
    }
    const updated = await accounts.update(live, (k) => removeSeal(k, seal.id));
    if (updated.ok) seals = updated.value.seals;
    else fail(updated.error);
  }

  async function signOut() {
    const live = signedIn.session;
    signedIn.session = null;
    seals = [];
    if (live !== null) await accounts.signOut(live);
  }

  async function signOutEverywhere() {
    const live = currentSession();
    if (live === null) return;
    busy = true;
    const result = await accounts.signOutEverywhere(live);
    busy = false;
    if (result.ok) {
      signedIn.session = null;
      seals = [];
      notice = t.signedOutEverywhere;
    } else {
      fail(result.error);
    }
  }

  async function close() {
    const live = currentSession();
    if (live === null) return;
    busy = true;
    const result = await accounts.close(live);
    busy = false;
    confirmingClose = false;
    if (result.ok) {
      signedIn.session = null;
      seals = [];
      notice = t.closed;
    } else {
      fail(result.error);
    }
  }
</script>

<section class="card stack" data-testid="account">
  <h2>{t.accountTitle}</h2>
  {#if session === null}
    <p class="muted">{t.accountIntro}</p>
    {#if notice}<p class="success" data-testid="account-notice">{notice}</p>{/if}
    <div class="tabs" role="tablist">
      <button role="tab" aria-selected={mode === 'signIn'} class:active={mode === 'signIn'} onclick={() => (mode = 'signIn')}>{t.signIn}</button>
      <button role="tab" aria-selected={mode === 'signUp'} class:active={mode === 'signUp'} onclick={() => (mode = 'signUp')} data-testid="tab-sign-up">{t.signUp}</button>
    </div>
    <form class="stack" onsubmit={submit}>
      <div>
        <label for="username">{t.username}</label>
        <input id="username" bind:value={username} autocomplete="username" autocapitalize="none" spellcheck="false" required minlength="3" maxlength="64" data-testid="username" />
      </div>
      <div>
        <label for="password">{t.password}</label>
        <input id="password" type="password" bind:value={password} autocomplete={mode === 'signUp' ? 'new-password' : 'current-password'} required minlength="8" data-testid="password" />
        {#if mode === 'signUp'}<p class="muted small">{t.passwordHint}</p>{/if}
      </div>
      {#if error}<p class="error" role="alert">{error}</p>{/if}
      <button class="primary" type="submit" disabled={busy} data-testid="account-submit">
        {#if busy}{mode === 'signUp' ? t.signingUp : t.signingIn}{:else}{mode === 'signUp' ? t.signUp : t.signIn}{/if}
      </button>
      <p class="muted small">{t.sessionNote}</p>
    </form>
  {:else}
    <p data-testid="signed-in">{t.signedInAs} <strong>{session.username}</strong></p>
    <h3>{t.mySeals}</h3>
    {#if seals.length === 0}
      <p class="muted" data-testid="no-seals">{t.noSeals}</p>
    {:else}
      <ul class="seals" data-testid="seals">
        {#each seals as seal (seal.id)}
          <li>
            <span class="small">{t.sealedOn} {formatExpiry(seal.sealed)} · {t.expiresAt} {formatExpiry(seal.expires)}</span>
            <button class="secondary" onclick={() => destroy(seal)} data-testid="destroy-seal">{t.destroy}</button>
          </li>
        {/each}
      </ul>
    {/if}
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <div class="row">
      <button class="secondary" onclick={signOut} data-testid="sign-out">{t.signOut}</button>
      <button class="secondary" onclick={signOutEverywhere} disabled={busy} data-testid="sign-out-everywhere">{t.signOutEverywhere}</button>
      {#if !confirmingClose}
        <button class="secondary" onclick={() => (confirmingClose = true)} data-testid="close-account">{t.closeAccount}</button>
      {/if}
    </div>
    {#if confirmingClose}
      <p class="error">{t.closeWarning}</p>
      <button class="primary" onclick={close} disabled={busy} data-testid="confirm-close">{t.closeConfirm}</button>
    {/if}
  {/if}
</section>

<style>
  .tabs {
    display: flex;
    gap: var(--s3);
    border-bottom: 1px solid var(--line);
    padding-bottom: var(--s3);
  }

  .tabs button {
    background: none;
    color: var(--muted);
    padding: var(--s3) var(--s4);
  }

  .tabs button.active {
    color: var(--text);
    background: var(--raised);
    border-color: var(--line);
  }

  h3 {
    margin-bottom: 0;
  }

  .seals {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--s3);
  }

  .seals li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--s4);
    padding: var(--s3) 0;
    border-bottom: 1px solid var(--line);
  }

  .row {
    display: flex;
    gap: var(--s4);
    flex-wrap: wrap;
  }
</style>
