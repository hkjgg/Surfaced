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

    if (mode === "empty") {
      await page.goto(BASE);
      await page.waitForSelector("form");
      await shoot(page, "empty", size);
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
