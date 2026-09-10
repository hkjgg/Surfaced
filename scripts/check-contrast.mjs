/**
 * Asserts every Surfaced colour token pair clears its WCAG target against the
 * dark base. The design system claims AA; this is what makes that claim true
 * rather than aspirational. Run with `npm run check:contrast`.
 *
 * Text and meaningful icons need 4.5:1. Focus rings and control boundaries
 * need 3:1 (WCAG 2.1 non-text contrast).
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const css = readFileSync(join(root, "app", "globals.css"), "utf8");
const tokens = {};
for (const m of css.matchAll(/--color-([a-z-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) {
  tokens[m[1]] = m[2];
}

const lin = (c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const lum = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
};
const ratio = (a, b) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

const surfaces = ["bg", "surface", "raised", "overlay"];
const text = ["fg", "fg-muted", "fg-subtle"];
const signal = ["accent", "critical", "high", "medium", "low", "pass"];

let fail = 0;
const check = (name, r, min) => {
  const ok = r >= min;
  if (!ok) fail++;
  console.log(
    `${ok ? "PASS" : "FAIL"}  ${name.padEnd(34)} ${r.toFixed(2).padStart(6)}:1  (min ${min})`
  );
};

console.log("--- text tokens on every surface (min 4.5) ---");
for (const s of surfaces) for (const t of text) check(`${t} on ${s}`, ratio(tokens[t], tokens[s]), 4.5);

console.log("\n--- accent + severity as text on every surface (min 4.5) ---");
for (const s of surfaces) for (const t of signal) check(`${t} on ${s}`, ratio(tokens[t], tokens[s]), 4.5);

console.log("\n--- non-text: focus ring / borders (min 3.0) ---");
for (const s of surfaces) check(`accent ring on ${s}`, ratio(tokens.accent, tokens[s]), 3);
check("border-strong on bg", ratio(tokens["border-strong"], tokens.bg), 1.4);

console.log("\n--- fills: fg-invert text on accent/severity fill (min 4.5) ---");
for (const t of signal) check(`fg-invert on ${t} fill`, ratio(tokens["fg-invert"], tokens[t]), 4.5);

// The score gauge draws its arc in a severity colour on top of the gauge
// track, which is --color-border. That arc is a meaningful graphic, not
// decoration — it is how the verdict reads at a glance — so WCAG 1.4.11
// applies to it at 3:1, both against the track it sits on and against the
// page behind it.
// The finding tiers introduced two surfaces that are not plain tokens: the
// "loud" tier sits on --color-raised, and the "quiet" (pass) tier sits on
// --color-surface at 60% over --color-bg. Dimming a pass finding is a
// deliberate de-emphasis, and it is exactly the kind of change that quietly
// walks text under AA, so both are asserted rather than eyeballed.
const over = (fg, bg, alpha) => {
  const mix = (i) => {
    const f = parseInt(fg.slice(i, i + 2), 16);
    const b = parseInt(bg.slice(i, i + 2), 16);
    return Math.round(f * alpha + b * (1 - alpha));
  };
  return `#${[1, 3, 5].map((i) => mix(i).toString(16).padStart(2, "0")).join("")}`;
};

const quietSurface = over(tokens.surface, tokens.bg, 0.6);

console.log("\n--- finding tiers: text on the weighted surfaces (min 4.5) ---");
for (const t of text) {
  check(`${t} on raised (loud tier)`, ratio(tokens[t], tokens.raised), 4.5);
}
check("fg-muted on quiet tier (pass title)", ratio(tokens["fg-muted"], quietSurface), 4.5);
check("fg-subtle on quiet tier (pass observed)", ratio(tokens["fg-subtle"], quietSurface), 4.5);
for (const t of signal) {
  check(`${t} badge text on quiet tier`, ratio(tokens[t], quietSurface), 4.5);
}

console.log("\n--- non-text: score gauge arc vs its track and the page (min 3.0) ---");
for (const t of ["critical", "high", "medium", "low", "pass"]) {
  check(`${t} arc on gauge track`, ratio(tokens[t], tokens.border), 3);
  check(`${t} arc on surface`, ratio(tokens[t], tokens.surface), 3);
}

console.log(fail === 0 ? "\nALL CONTRAST CHECKS PASS" : `\n${fail} FAILURE(S)`);
process.exit(fail === 0 ? 0 : 1);
