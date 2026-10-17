<script lang="ts">
  // Only in the app: a link someone sent opens here, with the engine that
  // ships with the app, instead of the code a server would hand a browser.
  import { t } from '../lib/i18n';
  import { linkFragment } from '../lib/links';

  let text = $state('');
  let invalid = $state(false);

  function open(event: SubmitEvent) {
    event.preventDefault();
    const fragment = linkFragment(text);
    invalid = fragment === null;
    if (fragment === null) return;
    text = '';
    location.hash = fragment;
  }
</script>

<form class="card stack" onsubmit={open} data-testid="paste-link">
  <label for="paste">{t.pasteLink}</label>
  <div class="row">
    <input id="paste" bind:value={text} autocomplete="off" spellcheck="false" placeholder="https://sigylo.net/#/…" />
    <button class="secondary" type="submit">{t.pasteOpen}</button>
  </div>
  {#if invalid}<p class="error" role="alert">{t.pasteInvalid}</p>{/if}
</form>

<style>
  form {
    margin-bottom: var(--s5);
  }

  .row {
    display: flex;
    gap: var(--s3);
  }
</style>
