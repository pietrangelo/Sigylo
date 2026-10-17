// The golden ratio behind Sigylo's look. Nothing here ships to the browser:
// app.css pins the values this module computes, and tests/golden.test.ts
// fails if the two drift apart or a pair of colors loses its WCAG contrast.

/** φ = (1 + √5) / 2. */
export const PHI = (1 + Math.sqrt(5)) / 2;

/** The golden angle, 360° / φ² ≈ 137.5°: the turn between sunflower seeds. */
export const GOLDEN_ANGLE = 360 / PHI ** 2;

/** Spacing: the Fibonacci numbers around the 8px base, so each step is the sum
 *  of the two before it and the ratio between neighbours tends to φ. */
export const SPACING = [3, 5, 8, 13, 21, 34, 55, 89] as const;

/** Type sizes in px from the 16px body: one φ step up and down, and a √φ
 *  half step for small print, rounded to whole pixels. */
export function typeScale(body = 16) {
  return {
    caption: Math.round(body / PHI),
    small: Math.round(body / Math.sqrt(PHI)),
    body,
    title: Math.round(body * PHI),
    display: Math.round(body * PHI ** 2),
  };
}

// ---- Color --------------------------------------------------------------
//
// Colors are built in OKLCH, where lightness is perceptual, then pinned as
// sRGB hex (oklch() is missing from older webviews).
//
// * Hue: sealing-wax red, and every other hue a golden angle further on the
//   wheel: 1 turn gives the green of "done", 2 the ink, 3 the amber of a
//   warning and of parchment.
// * Lightness: a ladder of φ powers. Dark theme: L = L_text / φ^k, half a
//   step apart. Light theme the same on darkness (1 − L).
// * Chroma: the wax at full chroma, status colors one φ step lower, neutrals
//   barely tinted (φ⁵ and φ⁶ lower).

export const WAX_HUE = 27;
const WAX_CHROMA = 0.17;

export const hue = (turns: number) => (WAX_HUE + turns * GOLDEN_ANGLE) % 360;

export interface Oklch {
  l: number;
  c: number;
  h: number;
}

/** OKLCH to linear sRGB (Björn Ottosson's matrices). */
function linearSrgb({ l, c, h }: Oklch): [number, number, number] {
  const a = c * Math.cos((h * Math.PI) / 180);
  const b = c * Math.sin((h * Math.PI) / 180);
  const l_ = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m_ = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s_ = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;
  return [
    4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
    -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
    -0.0041960863 * l_ - 0.7034186147 * m_ + 1.707614701 * s_,
  ];
}

const inGamut = (rgb: number[]) => rgb.every((v) => v >= -1e-4 && v <= 1 + 1e-4);

const encode = (v: number) => {
  const x = Math.min(1, Math.max(0, v));
  return x <= 0.0031308 ? 12.92 * x : 1.055 * x ** (1 / 2.4) - 0.055;
};

/** An OKLCH color as #rrggbb, lowering chroma (never lightness or hue) until
 *  it fits in sRGB. */
export function toHex(color: Oklch): string {
  let c = color.c;
  let rgb = linearSrgb({ ...color, c });
  while (!inGamut(rgb) && c > 0) {
    c = Math.max(0, c - 0.001);
    rgb = linearSrgb({ ...color, c });
  }
  return `#${rgb.map((v) => Math.round(encode(v) * 255).toString(16).padStart(2, '0')).join('')}`;
}

/** WCAG 2 relative luminance of #rrggbb. */
export function luminance(hex: string): number {
  const channel = (i: number) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

/** WCAG 2 contrast ratio, from 1 to 21. */
export function contrast(a: string, b: string): number {
  const [x, y] = [luminance(a), luminance(b)];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

export const TOKENS = ['ink', 'surface', 'raised', 'line', 'text', 'muted', 'wax', 'wax-strong', 'on-wax', 'seal-mark', 'alert', 'ok', 'warn'] as const;
export type Token = (typeof TOKENS)[number];
export type Palette = Record<Token, string>;

const INK = hue(2);
const PARCHMENT = hue(3);
const TOP = 0.95;

/** The parchment-colored S pressed into the seal, the same in both themes. */
const SEAL_MARK = toHex({ l: TOP, c: WAX_CHROMA / PHI ** 5, h: PARCHMENT });

/** Dark theme: lightness L_text / φ^k, from the ink up to the text. */
export function darkPalette(): Palette {
  const step = (k: number) => TOP / PHI ** k;
  const neutral = (k: number) => toHex({ l: step(k), c: WAX_CHROMA / PHI ** 6, h: INK });
  return {
    ink: neutral(4),
    surface: neutral(3.5),
    raised: neutral(3),
    line: neutral(2.5),
    muted: neutral(0.5),
    text: SEAL_MARK,
    wax: toHex({ l: step(1.25), c: WAX_CHROMA, h: WAX_HUE }),
    'wax-strong': toHex({ l: step(1.5), c: WAX_CHROMA, h: WAX_HUE }),
    'on-wax': '#ffffff',
    'seal-mark': SEAL_MARK,
    alert: toHex({ l: step(0.75), c: WAX_CHROMA, h: WAX_HUE }),
    ok: toHex({ l: step(0.5), c: WAX_CHROMA / PHI, h: hue(1) }),
    warn: toHex({ l: step(0.5), c: WAX_CHROMA / PHI, h: hue(3) }),
  };
}

/** Light theme: the same ladder on darkness, D = D_text / φ^k, a whole
 *  step apart (light surfaces need wider steps to stay apart). */
export function lightPalette(): Palette {
  const bottom = 0.8;
  const step = (k: number) => 1 - bottom / PHI ** k;
  const parchment = (k: number) => toHex({ l: step(k), c: WAX_CHROMA / PHI ** 5, h: PARCHMENT });
  return {
    ink: parchment(6),
    surface: parchment(8),
    raised: parchment(5),
    line: parchment(3),
    muted: toHex({ l: step(1), c: WAX_CHROMA / PHI ** 6, h: INK }),
    text: toHex({ l: step(0), c: WAX_CHROMA / PHI ** 6, h: INK }),
    wax: toHex({ l: step(1), c: WAX_CHROMA, h: WAX_HUE }),
    'wax-strong': toHex({ l: step(0.75), c: WAX_CHROMA, h: WAX_HUE }),
    'on-wax': '#ffffff',
    'seal-mark': SEAL_MARK,
    alert: toHex({ l: step(0.75), c: WAX_CHROMA, h: WAX_HUE }),
    ok: toHex({ l: step(1), c: WAX_CHROMA / PHI, h: hue(1) }),
    warn: toHex({ l: step(1), c: WAX_CHROMA / PHI, h: hue(3) }),
  };
}
