package network.conet.chat

/** Which history log lines are forwarded to the page as `event:log` (all go to logcat). */
internal object HistoryLogPolicy {
    /** Only problems: routine info lines (synced, pointer updated, head adopted …) stay native. */
    fun reachesPage(level: String): Boolean = when (level.lowercase()) {
        "warn", "warning", "error" -> true
        else -> false
    }
}
