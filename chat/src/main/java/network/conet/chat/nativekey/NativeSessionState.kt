package network.conet.chat.nativekey

/**
 * The G2 flag (spec 25.26.4c): true only after a successful `init` whose EOA equals the native record. It is cleared
 * when the session is replaced, destroyed or cleared. The native record itself is not affected.
 *
 * The shell reads it through `BeamioConetChatModule.isNativeSessionReady()` (read-only) to tell G1 (`not_ready`) from
 * G2. Only the module sets it.
 */
object NativeSessionState {
    @Volatile
    private var ready = false

    /** `true` when this session has initialised for the native record (G2). */
    fun isReady(): Boolean = ready

    internal fun markReady() {
        ready = true
    }

    internal fun reset() {
        ready = false
    }
}
