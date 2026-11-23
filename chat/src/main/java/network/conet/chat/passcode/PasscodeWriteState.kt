package network.conet.chat.passcode

/**
 * Process-scoped state for the passcode records (v205 225.2, v207 227): the wall-clock start of this process, and the accounts with a passcode write in
 * progress in this process. Nothing here is persisted.
 *
 * The start is provable only as a bound from the platform: Process.getStartElapsedRealtime() (the process start on the elapsed clock, API 24) converted to
 * wall-clock time with the current wall and elapsed clocks, then moved EARLIER by [SAFETY_MARGIN_MS]. An earlier start only keeps more files. When the start
 * cannot be read, it is null, and every `<eoa>.new` is kept (the time condition is not proved).
 *
 * Limit (recorded): the estimate converts the elapsed clock to wall-clock time with the current wall clock. If the user changes the wall clock while the process
 * runs, the conversion is wrong, and the 60 s margin does not cover a large change. The start is read once per cleanup scan. minSdk is 24, the API level of
 * Process.getStartElapsedRealtime.
 */
internal object PasscodeWriteState {
    /** Moves the estimated start earlier, so the estimate is never later than the real start (a conservative bound). */
    const val SAFETY_MARGIN_MS = 60_000L

    /** The start provider. The default reads the platform; tests replace it. */
    @Volatile
    var startProvider: () -> Long? = { platformProcessStartMs() }

    /** The wall-clock start of this process, earlier than or equal to the real start, or null when it cannot be proved. */
    fun processStartMs(): Long? = startProvider()

    private val inProgress = HashSet<String>()

    @Synchronized
    fun begin(eoa: String) {
        inProgress.add(eoa.lowercase())
    }

    @Synchronized
    fun end(eoa: String) {
        inProgress.remove(eoa.lowercase())
    }

    @Synchronized
    fun isInProgress(eoa: String): Boolean = inProgress.contains(eoa.lowercase())

    /**
     * Runs [block] (the removal of one `<eoa>.new`) only when the file is older than this process and no passcode write for [account] is in progress. The check
     * and [block] run under the same monitor that [begin] takes, so a write that starts meanwhile waits until the removal is decided (v207 227). Returns null
     * when the condition does not hold or the start cannot be proved.
     */
    fun <T> whenStaleAndIdle(account: String, file: java.io.File, block: () -> T): T? = synchronized(this) {
        // The start is read again at removal (v209 229.1): the removal judges with a fresh reading, not the scan's value.
        val start = processStartMs() ?: return null
        if (inProgress.contains(account.lowercase()) || file.lastModified() >= start) return null
        block()
    }

    /** The platform estimate: now minus the time since the process started (both on the elapsed clock), then earlier by the margin; null on any failure. */
    private fun platformProcessStartMs(): Long? = try {
        val nowWall = System.currentTimeMillis()
        val elapsedNow = android.os.SystemClock.elapsedRealtime()
        val startElapsed = android.os.Process.getStartElapsedRealtime()
        val sinceStart = elapsedNow - startElapsed
        if (sinceStart < 0) null else nowWall - sinceStart - SAFETY_MARGIN_MS
    } catch (_: Throwable) {
        null
    }
}
