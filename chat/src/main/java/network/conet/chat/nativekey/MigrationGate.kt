package network.conet.chat.nativekey

/**
 * Once-per-process gate for a legacy adoption (hotfix for the S25 ANR, 2026-11-17). The adoption ran on every command, each time reading the
 * keystore under the wallet monitors. The gate runs the attempt until it is resolved, then never again in this process.
 *
 *  - [Outcome.RESOLVED_ADOPTED] and [Outcome.RESOLVED_NOTHING] are definitive: the attempt is not repeated in this process.
 *  - [Outcome.UNKNOWN] (a read fault, a write that did not finish, a state not yet readable) is not remembered: the next attempt waits
 *    [retryMillis] after it, so a command never reads the keystore again within that window.
 *  - An attempt that throws is unknown.
 * Nothing is deleted by the gate; the attempt decides what it writes or clears.
 */
internal class MigrationGate(
    private val now: () -> Long,
    private val retryMillis: Long = 30_000L,
) {
    enum class Outcome { RESOLVED_ADOPTED, RESOLVED_NOTHING, UNKNOWN }

    private var resolved = false
    private var nextAttemptAt = 0L

    /** Runs [attempt] unless it is resolved or within the retry window. Returns true only when the attempt adopted something. */
    @Synchronized
    fun run(attempt: () -> Outcome): Boolean {
        if (resolved) return false
        if (now() < nextAttemptAt) return false
        val outcome = try {
            attempt()
        } catch (_: Exception) {
            Outcome.UNKNOWN
        }
        return when (outcome) {
            Outcome.RESOLVED_ADOPTED -> {
                resolved = true
                true
            }
            Outcome.RESOLVED_NOTHING -> {
                resolved = true
                false
            }
            Outcome.UNKNOWN -> {
                nextAttemptAt = now() + retryMillis
                false
            }
        }
    }

    /** Test and diagnosis: whether the gate has a definitive result. */
    @Synchronized
    fun isResolved(): Boolean = resolved
}
