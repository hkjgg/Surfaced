/**
 * Screenshots of the report UI, at the two reference widths.
 *
 * Playwright is NOT a dependency of this project — the app does not need it,
 * and a browser download does not belong in a cold CI install. Point the
 * script at an existing install instead (NODE_PATH does not work for ESM, so
 * this takes an explicit path):
 *
 *   PLAYWRIGHT_PATH=/path/to/node_modules/playwright-core \
 *     node scripts/screenshot-report.mjs …
 *
 * Modes:
 *
 *   live     <domain>        run a real scan and shoot the finished report
 *   loading  <domain>        run a real scan and shoot it mid-flight
 *   replay   --from a.json   shoot a report captured elsewhere
 *   error    <domain>        shoot a rejected scan (e.g. a private address)
 *   empty                    shoot the home page
 *   notfound                 shoot the 404
 *   layout   <domain>        assert the sticky column pins and stays reachable
 *
 * Flags: --only <375|1280>  one width per run (the loading state needs it, so
 *                           the second viewport does not replay a cached scan)
 *        --grayscale        desaturate, to prove severity reads without colour
 *        --reduced          emulate prefers-reduced-motion
 *
 * `replay` exists because some domains cannot be scanned from every network —
 * apex TXT records that need TCP/53, or a blocked crt.sh. It intercepts the
 * API call and serves a report body you captured on a network that could, so
 * the screenshot shows real scanner output rather than an invention. It never
 * touches application code: the app has no fixture path.
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const BASE = process.env.BASE_URL ?? "http://127.0.0.1:3000";
const OUT = process.env.OUT_DIR ?? "screenshots";
const WIDTHS = [
  { name: "375", width: 375, height: 900 },
  { name: "1280", width: 1280, height: 1000 },
];

const playwrightSpecifier = process.env.PLAYWRIGHT_PATH
  ? pathToFileURL(path.join(process.env.PLAYWRIGHT_PATH, "index.js")).href
  : "playwright-core";

const playwright = await import(playwrightSpecifier).catch((error) => {
  console.error(
    `Could not load playwright-core from ${playwrightSpecifier}: ${error.message}\n` +
      "Set PLAYWRIGHT_PATH to a playwright-core install.",
  );
  process.exit(2);
});

// playwright-core is CommonJS, so a file-URL import lands the exports on
// `default` while a bare specifier resolves them at the top level.
const chromium = playwright.chromium ?? playwright.default?.chromium;
if (!chromium) {
  console.error("playwright-core loaded but exposed no chromium export.");
  process.exit(2);
}

const EXECUTABLE =
  process.env.CHROMIUM_PATH ?? "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";

const args = process.argv.slice(2);
const mode = args[0];
const positional = args[1] && !args[1].startsWith("--") ? args[1] : null;

function flag(name) {
  const index = args.indexOf(`--${name}`);
  return index === -1 ? null : args[index + 1];
}

/** The SSE frames a captured report would have produced. Mirrors replayEvents. */
function toEventStream(report) {
  const frames = [
    [
      "start",
      {
        type: "start",
        hostname: report.hostname,
        scannedAt: report.scannedAt,
        checks: report.checks.map((check) => check.check),
        cached: false,
      },
    ],
  ];

  for (const check of report.checks) {
    frames.push([
      "check",
      {
        type: "check",
        check: check.check,
        status: check.status,
        findingCount: check.findings.length,
        durationMs: check.durationMs,
        elapsedMs: check.durationMs,
        ...(check.reason === undefined ? {} : { reason: check.reason }),
      },
    ]);
  }

  frames.push(["report", { type: "report", report }]);

  return frames
    .map(([name, data]) => `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`)
    .join("");
}

async function shoot(page, label, size) {
  await mkdir(OUT, { recursive: true });
  const file = path.join(OUT, `${label}-${size.name}.png`);
  await page.screenshot({ path: file, fullPage: true });

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  if (overflow > 0) {
    console.error(`  ✗ ${file} — horizontal overflow of ${overflow}px`);
    process.exitCode = 1;
  } else {
    console.log(`  ✓ ${file}`);
  }
}

const browser = await chromium.launch({ executablePath: EXECUTABLE });

try {
  // --only lets one width be captured per run. The loading state needs it:
  // the report cache is shared across viewports, so a second viewport in the
  // same run would replay a cached scan and never show a scan in progress.
  const only = flag("only");
  const sizes = only ? WIDTHS.filter((size) => size.name === only) : WIDTHS;

  for (const size of sizes) {
    const context = await browser.newContext({
      viewport: { width: size.width, height: size.height },
      deviceScaleFactor: 2,
      colorScheme: "dark",
      reducedMotion: flag("reduced") !== null ? "reduce" : "no-preference",
    });
    const page = await context.newPage();

    // --grayscale proves severity survives without colour. The rank meter and
    // the uppercase label have to carry the whole message here.
    if (flag("grayscale") !== null) {
      await page.addStyleTag({ content: "html { filter: grayscale(1); }" }).catch(() => {});
      page.on("load", () => {
        page.addStyleTag({ content: "html { filter: grayscale(1); }" }).catch(() => {});
      });
    }

    if (mode === "replay") {
      const source = flag("from");
      if (!source) throw new Error("replay needs --from <report.json>");

      const report = JSON.parse(await readFile(source, "utf8"));
      const body = toEventStream(report);

      await page.route("**/api/scan", (route) =>
        route.fulfill({
          status: 200,
          headers: { "content-type": "text/event-stream; charset=utf-8" },
          body,
        }),
      );

      await page.goto(`${BASE}/scan/${encodeURIComponent(report.hostname)}`);
      await page.waitForSelector("#findings-heading", { timeout: 20_000 });
      await page.waitForTimeout(1200);
      await shoot(page, flag("label") ?? report.hostname, size);
    }

    if (mode === "live") {
      await page.goto(`${BASE}/scan/${encodeURIComponent(positional)}`);
      await page.waitForSelector("#findings-heading", { timeout: 40_000 });
      if (flag("grayscale") !== null) {
        await page.addStyleTag({ content: "html { filter: grayscale(1); }" });
      }
      await page.waitForTimeout(1200);
      await shoot(page, flag("label") ?? positional, size);
    }

    if (mode === "loading") {
      await page.goto(`${BASE}/scan/${encodeURIComponent(positional)}`, {
        waitUntil: "commit",
      });
      // Caught mid-scan on purpose: some checks have settled, others have not.
      await page.waitForTimeout(Number(flag("at") ?? 900));
      await shoot(page, flag("label") ?? "loading", size);
    }

    if (mode === "error") {
      await page.goto(`${BASE}/scan/${encodeURIComponent(positional)}`);
      await page.waitForSelector("text=/Scan failed/", { timeout: 20_000 });
      await shoot(page, flag("label") ?? "error", size);
    }

    if (mode === "layout") {
      // The sticky column is only correct if it pins AND nothing in it becomes
      // unreachable. A column taller than the viewport that merely sticks has
      // hidden its own bottom; one that scrolls internally but drifts is not
      // sticky at all. Both halves are asserted.
      await page.goto(`${BASE}/scan/${encodeURIComponent(positional)}`);
      await page.waitForSelector("#findings-heading", { timeout: 40_000 });
      await page.waitForTimeout(600);

      const column = page
        .locator("#coverage-heading")
        .locator("xpath=ancestor::div[contains(@class,'lg:sticky')][1]");

      if (size.width < 1024) {
        console.log(`  --   ${size.name}px: single column, nothing to pin`);
      } else {
        // A sticky column can only stay pinned while its container is taller
        // than it is; past that the container's bottom catches up and the
        // column travels with the page. That is correct behaviour, so the
        // assertion has to run inside the real range rather than at arbitrary
        // scroll positions — a short report simply has less of one.
        const range = await column.evaluate((el) => {
          const grid = el.parentElement;
          const top = grid.getBoundingClientRect().top + window.scrollY;
          const offset = Number.parseFloat(getComputedStyle(el).top) || 0;
          return {
            start: top,
            offset,
            // The column unpins once the container's bottom reaches it, which
            // happens `offset` earlier than the raw height difference — the
            // sticky top inset counts against the range.
            span: Math.max(0, grid.offsetHeight - el.offsetHeight - offset),
          };
        });

        if (range.span < 40) {
          console.log(
            `  --   ${size.name}px: report too short to pin (${Math.round(range.span)}px of range)`,
          );
          await context.close();
          continue;
        }

        const tops = [];
        for (const fraction of [0.15, 0.5, 0.9]) {
          const y = range.start + range.span * fraction;
          await page.evaluate((to) => window.scrollTo(0, to), y);
          await page.waitForTimeout(200);
          tops.push(Math.round((await column.boundingBox()).y));
        }

        // The offset is --spacing-sticky (4.5rem), clearing the 3.5rem header.
        const pinned = tops.every((top) => Math.abs(top - range.offset) <= 1);
        const reachable = await column.evaluate((el) => {
          if (el.scrollHeight <= el.clientHeight + 1) return true;
          el.scrollTop = el.scrollHeight;
          return el.scrollHeight - el.scrollTop - el.clientHeight < 2;
        });

        for (const [label, ok] of [
          [
            `pins at ${range.offset}px across its ${Math.round(range.span)}px range (${tops.join(", ")})`,
            pinned,
          ],
          ["its own overflow scrolls to the end", reachable],
        ]) {
          console.log(`  ${ok ? "✓" : "✗"} ${size.name}px: ${label}`);
          if (!ok) process.exitCode = 1;
        }
      }
    }

    if (mode === "empty") {
      await page.goto(BASE);
      await page.waitForSelector("form");
      await shoot(page, "home", size);
    }

    if (mode === "notfound") {
      // Any route that does not exist; the 404 offers the scanner rather than
      // just apologising, so it has a form to wait for like the home page.
      await page.goto(`${BASE}/no-such-page`);
      await page.waitForSelector("form");
      await shoot(page, "404", size);
    }

    await context.close();
  }
} finally {
  await browser.close();
}

if (mode === "replay" && flag("save-events")) {
  const report = JSON.parse(await readFile(flag("from"), "utf8"));
  await writeFile(flag("save-events"), toEventStream(report));
}
