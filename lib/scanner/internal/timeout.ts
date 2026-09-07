/** Timeout and deadline helpers shared by every check. */

export class TimeoutError extends Error {
  constructor(label: string, ms: number) {
    super(`${label} timed out after ${ms}ms`);
    this.name = "TimeoutError";
  }
}

/**
 * Race a promise against a timeout.
 *
 * The underlying work is not cancelled — a DNS query in flight will still
 * settle — so callers that own a socket should also pass an AbortSignal. This
 * exists to bound wall time, not to free resources.
 */
export async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  label: string,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;

  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new TimeoutError(label, ms)), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * An AbortSignal that fires after `ms`, also aborting if `parent` aborts.
 *
 * `AbortSignal.any` plus `AbortSignal.timeout` would be shorter, but this
 * form returns the cleanup function needed to avoid leaking a timer for the
 * full duration on every fast check.
 */
export function deadlineSignal(
  ms: number,
  parent?: AbortSignal,
): { signal: AbortSignal; cancel: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new TimeoutError("check", ms)), ms);

  const onParentAbort = () => controller.abort(parent?.reason);
  if (parent) {
    if (parent.aborted) controller.abort(parent.reason);
    else parent.addEventListener("abort", onParentAbort, { once: true });
  }

  return {
    signal: controller.signal,
    cancel: () => {
      clearTimeout(timer);
      parent?.removeEventListener("abort", onParentAbort);
    },
  };
}

/** Milliseconds remaining until `deadline`, never negative. */
export function remainingMs(deadline: number): number {
  return Math.max(0, deadline - Date.now());
}
