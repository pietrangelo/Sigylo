<script lang="ts">
  import { language, t } from '../lib/i18n';
  import { LEGAL_UPDATED, legal } from '../lib/legal';

  let { kind }: { kind: 'terms' | 'privacy' } = $props();

  const doc = $derived(legal[language][kind]);
  const updated = new Date(`${LEGAL_UPDATED}T00:00:00Z`).toLocaleDateString(language, { dateStyle: 'long', timeZone: 'UTC' });
</script>

<article class="card stack" data-testid="legal">
  <h2>{doc.title}</h2>
  <p class="muted small">{t.legalUpdated} {updated}</p>
  {#each doc.sections as section (section.heading)}
    <section>
      <h3>{section.heading}</h3>
      {#each section.body as paragraph, i (i)}
        <p>{paragraph}</p>
      {/each}
    </section>
  {/each}
  <p><a href="#/">{t.back}</a></p>
</article>

<style>
  h3 {
    font-size: var(--t-body);
    margin: 0 0 var(--s3);
  }

  section p {
    margin: 0 0 var(--s3);
  }
</style>
