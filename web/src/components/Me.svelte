<script lang="ts">
  // This browser's sender code, to hand over before a request is made for it.
  import { engine, loadEngine, randomBytes } from '../lib/crypto';
  import { t } from '../lib/i18n';
  import { SEED_LEN, browserStore, loadOrCreateSeed } from '../lib/identity';

  let code = $state('');

  $effect(() => {
    const seed = loadOrCreateSeed(browserStore(), () => randomBytes(SEED_LEN));
    loadEngine().then(() => (code = engine.senderCode(seed)));
  });
</script>

<section class="card stack">
  <h2>{t.myCodeTitle}</h2>
  <div class="sender">
    <p class="code" data-testid="sender-code">{code || '…'}</p>
  </div>
  <p class="muted">{t.myCodeIntro}</p>
</section>
