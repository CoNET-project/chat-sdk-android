package network.conet.chat.nativekey

/**
 * `pwaEmptySignal` (r2.5.2 53): the PWA's read state, sent by the shell with a transaction sequence. Only `explicit_empty` is an empty
 * PWA side; `valid`, `unknown` and any other value are unknown (53(3)). A signal older than the newest accepted signal or sync sequence is
 * stale (53(5)). The ledger is in memory: it is the newest accepted signal of this process. Nothing here logs a phrase or a key.
 */
internal object PwaEmptySignal {
    const val EXPLICIT_EMPTY = "explicit_empty"
    const val UNKNOWN = "unknown"
    private val lock = Any()
    private var lastSeq: Long = 0L
    private var lastState: String? = null

    /** The PWA state of a request value: the three named values, anything else is unknown. */
    fun stateOf(raw: String?): String = when (raw) {
        "valid", EXPLICIT_EMPTY, UNKNOWN -> raw
        else -> UNKNOWN
    }

    /**
     * Accepts a signal with [seq] on the shared ledger with `pwaWalletSync` (the newer of the two is the bar; an older or equal one is stale).
     * Records the state when accepted. A signal does not move the pre-read epoch.
     */
    fun accept(seq: Long, state: String): Boolean = synchronized(lock) {
        if (!MnemonicPreread.acceptTransaction(seq, sync = false)) return false
        lastSeq = seq
        lastState = state
        true
    }

    /** The log line of a narrow discard run from the signal: the outcome name only. */
    fun discardLogLine(outcome: NativeWalletVault.DiscardOutcome): String = "pwaEmptySignal discard=${outcome.name}"

    /** The PWA state of the newest accepted signal, or null when none has been accepted. */
    fun latestState(): String? = synchronized(lock) { lastState }

    /** Test hook. */
    internal fun resetForTests() = synchronized(lock) {
        lastSeq = 0L
        lastState = null
    }
}
