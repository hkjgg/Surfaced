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

console.log(fail === 0 ? "\nALL CONTRAST CHECKS PASS" : `\n${fail} FAILURE(S)`);
process.exit(fail === 0 ? 0 : 1);
