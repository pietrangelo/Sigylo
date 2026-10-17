import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  GOLDEN_ANGLE,
  PHI,
  SPACING,
  TOKENS,
  contrast,
  darkPalette,
  hue,
  lightPalette,
  toHex,
  typeScale,
  type Palette,
  type Token,
} from '../src/lib/golden';

const read = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');
const css = read('../src/app.css');
const components = readdirSync(new URL('../src/components/', import.meta.url)).map((f) => read(`../src/components/${f}`));
const app = read('../src/App.svelte');
const favicon = read('../public/favicon.svg');

/** The custom properties declared in one CSS block. */
function props(block: string): Record<string, string> {
  return Object.fromEntries([...block.matchAll(/--([\w-]+):\s*([^;]+);/g)].map((m) => [m[1]!, m[2]!.trim()]));
}

const darkBlock = css.slice(css.indexOf(':root {'), css.indexOf('@media (prefers-color-scheme: light)'));
const lightBlock = css.slice(css.indexOf('@media (prefers-color-scheme: light)'), css.indexOf('* {'));
const dark = props(darkBlock);
const light = props(lightBlock);
const styles = [app, ...components].map((s) => s.slice(s.indexOf('<style>'))).join('\n');

describe('proportions', () => {
  it('spaces are consecutive Fibonacci numbers around the 8px base', () => {
    for (let i = 2; i < SPACING.length; i++) expect(SPACING[i]).toBe(SPACING[i - 1]! + SPACING[i - 2]!);
    expect(SPACING).toContain(8);
    expect(SPACING.at(-1)! / SPACING.at(-2)!).toBeCloseTo(PHI, 2);
  });

  it('app.css pins exactly that spacing scale', () => {
    SPACING.forEach((px, i) => expect(dark[`s${i + 1}`]).toBe(`${px}px`));
  });

  it('type sizes are φ steps from the body, with a √φ half step for small print', () => {
    expect(typeScale()).toEqual({ caption: 10, small: 13, body: 16, title: 26, display: 42 });
    for (const [name, px] of Object.entries(typeScale())) expect(dark[`t-${name}`]).toBe(`${px}px`);
  });

  it('line heights are φ for text and √φ for headings', () => {
    expect(Number(dark.phi)).toBeCloseTo(PHI, 3);
    expect(Number(dark['phi-half'])).toBeCloseTo(Math.sqrt(PHI), 3);
    expect(css).toMatch(/h2\s*\{\s*line-height:\s*var\(--phi-half\)/);
  });

  it('the column is a Fibonacci number, 377 × φ', () => {
    expect(dark.column).toBe(`${Math.round(377 * PHI)}px`);
  });

  it('radii come from the spacing scale, the card one φ step rounder', () => {
    expect(dark.radius).toBe('var(--s3)');
    expect(dark['radius-card']).toBe('var(--s4)');
  });

  it('outside the tokens, no length is a magic number: only hairlines', () => {
    const rules = css.slice(css.indexOf('* {')) + styles;
    const lengths = [...rules.matchAll(/(\d+(?:\.\d+)?)px/g)].map((m) => m[1]);
    expect(lengths.filter((n) => n !== '1' && n !== '2')).toEqual([]);
  });

  it('the seal ring encloses 1/φ of the seal: radii in a √φ ratio, in page and favicon', () => {
    for (const svg of [app, favicon]) {
      const radii = [...svg.matchAll(/<circle[^>]*\br="([\d.]+)"/g)].map((m) => Number(m[1]));
      expect(radii).toHaveLength(2);
      expect((radii[0]! / radii[1]!) ** 2).toBeCloseTo(PHI, 2);
    }
  });
});

describe('palette', () => {
  it('hues turn by the golden angle from the sealing wax', () => {
    expect(GOLDEN_ANGLE).toBeCloseTo(137.508, 3);
    expect(hue(0)).toBe(27);
    expect(hue(1) - hue(0)).toBeCloseTo(GOLDEN_ANGLE, 9);
    expect(hue(3)).toBeCloseTo((27 + 3 * GOLDEN_ANGLE) % 360, 9);
  });

  it('converts OKLCH to sRGB like the reference', () => {
    expect(toHex({ l: 1, c: 0, h: 0 })).toBe('#ffffff');
    expect(toHex({ l: 0, c: 0, h: 0 })).toBe('#000000');
    // oklch(62.8% 0.2577 29.23) is sRGB red.
    expect(toHex({ l: 0.62796, c: 0.25768, h: 29.2339 })).toBe('#ff0000');
  });

  it('brings an out-of-gamut color into sRGB by lowering chroma only', () => {
    expect(toHex({ l: 0.9, c: 0.4, h: 27 })).toMatch(/^#[0-9a-f]{6}$/);
  });

  it('measures WCAG contrast', () => {
    expect(contrast('#000000', '#ffffff')).toBeCloseTo(21, 5);
    expect(contrast('#777777', '#777777')).toBe(1);
  });

  it('app.css pins exactly the computed palettes', () => {
    for (const token of TOKENS) {
      expect(dark[token], `dark ${token}`).toBe(darkPalette()[token]);
      expect(light[token], `light ${token}`).toBe(lightPalette()[token]);
    }
  });

  it('every color comes from a token: no hex outside the palette blocks', () => {
    const rules = css.slice(css.indexOf('* {')) + styles;
    expect(rules.match(/#[0-9a-f]{3,8}\b/gi)).toBeNull();
  });

  it('the favicon wears the dark palette', () => {
    expect(favicon).toContain(`fill="${darkPalette().wax}"`);
    expect(favicon).toContain(`stroke="${darkPalette().text}"`);
  });

  for (const [theme, palette] of [
    ['dark', darkPalette()],
    ['light', lightPalette()],
  ] as [string, Palette][]) {
    const ratio = (a: Token, b: Token) => contrast(palette[a], palette[b]);

    it(`${theme}: body text passes AAA (7:1) on every background`, () => {
      for (const bg of ['ink', 'surface', 'raised'] as const) expect(ratio('text', bg)).toBeGreaterThanOrEqual(7);
    });

    it(`${theme}: muted text, errors and statuses pass AA (4.5:1)`, () => {
      for (const bg of ['ink', 'surface', 'raised'] as const) {
        expect(ratio('muted', bg), `muted on ${bg}`).toBeGreaterThanOrEqual(4.5);
        expect(ratio('alert', bg), `alert on ${bg}`).toBeGreaterThanOrEqual(4.5);
      }
      expect(ratio('ok', 'surface')).toBeGreaterThanOrEqual(4.5);
      expect(ratio('warn', 'surface')).toBeGreaterThanOrEqual(4.5);
    });

    it(`${theme}: the seal button reads at rest and on hover`, () => {
      expect(ratio('on-wax', 'wax')).toBeGreaterThanOrEqual(4.5);
      expect(ratio('on-wax', 'wax-strong')).toBeGreaterThanOrEqual(4.5);
    });

    it(`${theme}: the wax and the focus ring stand out from the page (3:1)`, () => {
      for (const bg of ['ink', 'surface'] as const) {
        expect(ratio('wax', bg)).toBeGreaterThanOrEqual(3);
        expect(ratio('alert', bg)).toBeGreaterThanOrEqual(3);
      }
      expect(ratio('seal-mark', 'wax')).toBeGreaterThanOrEqual(3);
    });

    it(`${theme}: surfaces climb in order`, () => {
      const order: Token[] = theme === 'dark' ? ['ink', 'surface', 'raised', 'line'] : ['surface', 'ink', 'raised', 'line'];
      for (let i = 1; i < order.length; i++) expect(contrast(palette[order[i]!], palette.text)).toBeLessThan(contrast(palette[order[i - 1]!], palette.text));
    });
  }
});
