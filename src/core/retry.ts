/**
 * @file retry.ts
 * @description Shared retry utility with exponential backoff and jitter
 * for transient Firestore / network errors.
 */

/**
 * Firestore error codes that indicate a transient failure safe to retry.
 */
const TRANSIENT_CODES = new Set([
  'unavailable',
  'deadline-exceeded',
  'resource-exhausted',
  'aborted',
  'internal',
  'cancelled'
]);

export interface RetryOptions {
  /** Maximum number of attempts (including the first). Default: 3. */
  maxAttempts?: number;
  /** Base delay in milliseconds before the first retry. Default: 200. */
  baseDelayMs?: number;
  /** Maximum delay cap in milliseconds. Default: 5000. */
  maxDelayMs?: number;
  /** If provided, only errors matching these codes will be retried. Default: TRANSIENT_CODES. */
  retryableCodes?: Set<string>;
}

/**
 * Returns true if the given error looks like a transient Firestore / network
 * error that is safe to retry.
 */
export function isTransientError(error: any, retryableCodes: Set<string> = TRANSIENT_CODES): boolean {
  if (!error) return false;
  // Firestore SDK attaches a `code` property (e.g. 'unavailable')
  if (typeof error.code === 'string' && retryableCodes.has(error.code)) return true;
  // Some environments surface the code inside the message
  if (typeof error.message === 'string') {
    for (const code of retryableCodes) {
      if (error.message.includes(code)) return true;
    }
  }
  // Fetch / network-level failures
  if (error.name === 'TypeError' && error.message?.includes('Failed to fetch')) return true;
  if (error.name === 'TypeError' && error.message?.includes('NetworkError')) return true;
  return false;
}

/**
 * Executes `fn` with automatic retry on transient errors.
 * Uses exponential backoff with full jitter.
 *
 * @example
 * ```ts
 * await withRetry(() => setDoc(ref, data));
 * await withRetry(() => batch.commit(), { maxAttempts: 5 });
 * ```
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const {
    maxAttempts = 3,
    baseDelayMs = 200,
    maxDelayMs = 5000,
    retryableCodes = TRANSIENT_CODES
  } = options;

  let lastError: any;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error: any) {
      lastError = error;

      if (attempt >= maxAttempts || !isTransientError(error, retryableCodes)) {
        throw error;
      }

      // Exponential backoff with full jitter: delay ∈ [0, min(cap, base * 2^attempt))
      const exponentialDelay = baseDelayMs * Math.pow(2, attempt - 1);
      const cappedDelay = Math.min(exponentialDelay, maxDelayMs);
      const jitteredDelay = Math.random() * cappedDelay;

      console.warn(
        `[charproof] Transient error (attempt ${attempt}/${maxAttempts}, code: ${error.code || 'unknown'}). ` +
        `Retrying in ${Math.round(jitteredDelay)}ms...`,
        error.message
      );

      await new Promise(resolve => setTimeout(resolve, jitteredDelay));
    }
  }

  throw lastError;
}
