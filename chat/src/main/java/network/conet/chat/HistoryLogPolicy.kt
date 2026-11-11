package network.conet.chat

/** Which history log lines are forwarded to the page as `event:log` (all go to logcat). */
internal object HistoryLogPolicy {
    /**
     * Lines the page reads to track the history key (SilentPassUI nativeConetChatTransport
     * `_noteLog`): `[history] ready` (logged at info) and the prepare failures.
     */
    private val pageLifecycle = Regex(
        """\[history] (ready\b|prepare failed|domain sign failed|selfSign failed|keccak master failed|hkdf failed)""",
    )

    /** Problems and the lifecycle lines above; routine info (synced, pointer updated …) stays native. */
    fun reachesPage(level: String, message: String): Boolean = when (level.lowercase()) {
        "warn", "warning", "error" -> true
        else -> pageLifecycle.containsMatchIn(message)
    }
}
