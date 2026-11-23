package network.conet.chat.nativekey

/**
 * The native session (spec 25.26.4c; supplement 2026-11-20, native unlock persists until a cold start). True only after a successful unlock whose
 * EOA equals the native record, and it records that EOA. It is held in process memory only: a cold start (a new native process) begins locked and
 * never inherits it. A UI lock does not clear it; a hot restore (a page reload, a return to the foreground) is not a cold start and keeps it.
 * It is cleared when the account changes (a different account is initialised), by identity clear, and by the end of the process.
 *
 * Threat note: the unlocked key material is in process memory until the process ends. A UI lock does not shorten that window. The record itself is
 * not affected by any of this.
 *
 * The shell reads it through `BeamioConetChatModule.isNativeSessionReady()` (read-only) to tell G1 (`not_ready`) from G2. Only the module sets it.
 */
object NativeSessionState {
    @Volatile
    private var readyEoa: String? = null

    /** `true` when the native session is unlocked (G2) for some account. */
    fun isReady(): Boolean = readyEoa != null

    /** The lower-case EOA the native session is unlocked for, or null when it is locked. */
    fun readyEoa(): String? = readyEoa

    /** `true` when the native session is unlocked for [account] (case-insensitive). */
    fun isReadyFor(account: String): Boolean = readyEoa?.let { it == account.lowercase() } == true

    internal fun markReady(eoa: String) {
        val next = eoa.lowercase()
        if (readyEoa != null && readyEoa != next) SessionKeyHolder.clear()
        readyEoa = next
    }

    /**
     * The one unlock entry: the session is marked ready first (which clears the held key of any other account),
     * and only then is the key of [eoa] held. The order is fixed here, so the new account's key is never cleared by its own ready mark.
     */
    internal fun unlockWith(eoa: String, privateKey: ByteArray) {
        markReady(eoa)
        SessionKeyHolder.put(eoa, privateKey)
    }

    internal fun reset() {
        readyEoa = null
        SessionKeyHolder.clear()
    }
}
