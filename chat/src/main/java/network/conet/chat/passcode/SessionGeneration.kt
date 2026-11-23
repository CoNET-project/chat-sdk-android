package network.conet.chat.passcode

/**
 * The per-account session generation (`gen`; 2026-11-20). The SDK counts it internally: it only increases, it is
 * never decreased, and it is never sent in an online event. A call captures the generation when it is answered (gen0) and checks it again
 * before signing; a change means the session that answered it has ended.
 *
 * Only three things advance it, and they are the only [Reason]s this type accepts: a lock of an unlocked account, a logout, and a switch
 * away from an account (the old account). Unlock, passcode change and passcode disable never advance it, so they have no reason to pass here.
 *
 * Kept in memory. The generation a call captured lives only in memory too, so a process restart ends that call and nothing compares across it.
 */
internal class SessionGeneration {
    /** What ended the session. A closed set, so a caller cannot advance the generation for any other reason. */
    enum class Reason { LOCK, LOGOUT, ACCOUNT_SWITCH }

    private val counts = HashMap<String, Long>()

    /** The current generation of [account]. Zero until the account first ends a session. */
    @Synchronized
    fun current(account: String): Long = counts[key(account)] ?: 0L

    /**
     * Advances the generation of [account] for [reason] and returns the new value. Callers do this inside the same critical section that
     * changes the session state (E-24), so no call can observe the old session with the new state.
     */
    @Synchronized
    @Suppress("UNUSED_PARAMETER")
    fun advance(account: String, reason: Reason): Long {
        val k = key(account)
        val next = (counts[k] ?: 0L) + 1L
        check(next > 0L) { "session generation overflow" }
        counts[k] = next
        return next
    }

    private fun key(account: String): String = account.lowercase()
}
