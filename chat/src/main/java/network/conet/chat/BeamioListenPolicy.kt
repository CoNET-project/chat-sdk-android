package network.conet.chat

/**
 * When the mailbox listen runs and how fast it retries. Pure JVM (unit-tested).
 *
 * Rule: the app does not run in the background. The listen stays up only while
 * the app is in the foreground, or a call rings, dials or is up. In the
 * background it is paused, so nothing retries there.
 */
internal object BeamioListenPolicy {
    /** First retry after a failed listen. */
    const val RETRY_BASE_MS = 2_000L
    /** Longest wait between retries (network down for a while). */
    const val RETRY_MAX_MS = 30_000L
    /** Wait before reopening a listen that worked and then dropped. */
    const val RELISTEN_MS = 500L

    /**
     * Wait before the next try after [failures] failed tries in a row (1 = the
     * first failure): 2 s, 4 s, 8 s, 16 s, then 30 s. [jitter] in [0, 1) spreads
     * it by ±20 % so many phones do not retry in step; never above [RETRY_MAX_MS].
     */
    fun retryDelayMs(failures: Int, jitter: Double): Long {
        val n = failures.coerceIn(1, 16)
        val base = minOf(RETRY_MAX_MS, RETRY_BASE_MS shl (n - 1))
        val j = jitter.coerceIn(0.0, 1.0)
        return (base * (0.8 + 0.4 * j)).toLong().coerceIn(RETRY_BASE_MS / 2, RETRY_MAX_MS)
    }

    /**
     * Whether an owed or requested pause applies now. The shell reports the app
     * state ([lifecycleKnown]); an app in the foreground keeps its listen. A
     * shell that never reports keeps the old rule (the page decides).
     */
    fun pauseApplies(lifecycleKnown: Boolean, inForeground: Boolean, callInProgress: Boolean): Boolean {
        if (callInProgress) return false
        return !(lifecycleKnown && inForeground)
    }

    /** Whether the page's `resume` may open the listen (not in the background, unless a call needs it). */
    fun pageResumeApplies(lifecycleKnown: Boolean, inForeground: Boolean, callInProgress: Boolean): Boolean =
        !lifecycleKnown || inForeground || callInProgress
}
