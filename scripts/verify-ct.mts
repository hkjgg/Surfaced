/**
 * The crt.sh retry, exercised through the injected fetcher.
 *
 *   npm run verify:ct
 *
 * No network is touched. `checkCt` takes a `CtFetcher` parameter precisely so
 * the failure modes that matter — a 502, a dropped connection, a 403, and a
 * deadline with no room left — can be reproduced deterministically instead of
 * waited for.
 *
 * The behaviour being pinned here is as much about what does NOT happen: a 4xx
 * is not retried, a retry that cannot finish is not started, and neither
 * failure path ever produces an empty hostname list. An empty CT result would
 * read as "this domain has published no certificates", which is a claim about
 * the domain made from a fact about crt.sh.
 */

import { checkCt, type CtFetcher } from "../lib/scanner/ct.js";

let failures = 0;

function check(label: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);

  if (a === b) {
    console.log(`  ok   ${label}`);
  } else {
    failures += 1;
    console.error(`  FAIL ${label}\n       expected ${b}\n       actual   ${a}`);
  }
}

/** A fetcher that replays a scripted sequence and counts how often it is called. */
function scripted(
  steps: ReadonlyArray<{ status?: number; body?: string; throws?: string }>,
): { fetcher: CtFetcher; calls: () => number } {
  let calls = 0;

  const fetcher: CtFetcher = async () => {
    const step = steps[Math.min(calls, steps.length - 1)];
    calls += 1;

    if (!step) throw new Error("no scripted step");
    if (step.throws) throw new TypeError(step.throws);

    return new Response(step.body ?? "[]", {
      status: step.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  };

  return { fetcher, calls: () => calls };
}

/** One crt.sh entry, enough to parse into a real result. */
const ONE_ENTRY = JSON.stringify([
  { name_value: "dev.example.com", common_name: "dev.example.com" },
]);

console.log("\ncrt.sh retry");

{
  const { fetcher, calls } = scripted([{ status: 502 }, { body: ONE_ENTRY }]);
  const result = await checkCt("example.com", new AbortController().signal, fetcher);

  check("502 then 200 → two calls", calls(), 2);
  check("502 then 200 → status ok", result.status, "ok");
  check("502 then 200 → the real data survives", result.data?.hostnameCount, 1);
}

{
  const { fetcher, calls } = scripted([{ status: 502 }, { status: 502 }]);
  let status = "unthrown";
  try {
    await checkCt("example.com", new AbortController().signal, fetcher);
  } catch (error) {
    status = error instanceof Error ? error.message : "unknown";
  }

  check("two 502s → exactly two calls, no third", calls(), 2);
  check("two 502s → throws, so the check reports error", status, "crt.sh returned HTTP 502");
}

{
  const { fetcher, calls } = scripted([{ throws: "socket hang up" }, { body: ONE_ENTRY }]);
  const result = await checkCt("example.com", new AbortController().signal, fetcher);

  check("network error then 200 → two calls", calls(), 2);
  check("network error then 200 → status ok", result.status, "ok");
}

console.log("\ncrt.sh failures that must NOT be retried");

{
  const { fetcher, calls } = scripted([{ status: 403 }, { body: ONE_ENTRY }]);
  let message = "unthrown";
  try {
    await checkCt("example.com", new AbortController().signal, fetcher);
  } catch (error) {
    message = error instanceof Error ? error.message : "unknown";
  }

  // A 403 is a decision crt.sh made on purpose. Repeating the request gets the
  // same answer and spends budget the rest of the scan could use.
  check("403 → one call only", calls(), 1);
  check("403 → reported verbatim", message, "crt.sh returned HTTP 403");
}

{
  const { fetcher, calls } = scripted([{ status: 500, body: "[]" }, { body: ONE_ENTRY }]);
  const controller = new AbortController();
  controller.abort();

  let message = "unthrown";
  try {
    await checkCt("example.com", controller.signal, fetcher);
  } catch (error) {
    message = error instanceof Error ? error.name : "unknown";
  }

  check("an already-aborted scan → no calls at all", calls(), 0);
  check("an already-aborted scan → aborts", message !== "unthrown", true);
}

console.log("\nthe retry is skipped when the deadline cannot fit it");

{
  // checkCt's budget runs from the moment it is called, so a fetcher that
  // burns almost all of it leaves no room for a backoff plus a real attempt.
  // The retry must be skipped and the 502 reported as-is.
  const CT_BUDGET_MS = 20_000;
  const LEAVE_MS = 1_000;

  let calls = 0;
  const fetcher: CtFetcher = async () => {
    calls += 1;
    if (calls === 1) {
      await new Promise((resolve) => setTimeout(resolve, CT_BUDGET_MS - LEAVE_MS));
      return new Response("", { status: 502 });
    }
    return new Response(ONE_ENTRY, { status: 200 });
  };

  const started = Date.now();
  let message = "unthrown";
  try {
    await checkCt("example.com", new AbortController().signal, fetcher);
  } catch (error) {
    message = error instanceof Error ? error.message : "unknown";
  }
  const elapsed = Date.now() - started;

  check("slow 502 with ~1s left → retry skipped, one call", calls, 1);
  check("slow 502 with ~1s left → the 502 is reported", message, "crt.sh returned HTTP 502");
  check(
    `slow 502 → returned before the budget expired (${elapsed}ms)`,
    elapsed < CT_BUDGET_MS,
    true,
  );
}

console.log(
  failures === 0 ? "\nAll CT assertions passed.\n" : `\n${failures} assertion(s) FAILED.\n`,
);
process.exit(failures === 0 ? 0 : 1);
