package network.conet.chat.nativekey

import java.util.concurrent.atomic.AtomicBoolean

/**
 * At most one reply per request (25.52Y.84: every reqId gets exactly one answer). [once] runs the reply for the first caller only. A failure inside the
 * reply is swallowed here, so it can never become a second reply from the caller's catch path: the one reply was attempted, and it is not repeated.
 */
internal class SingleReply {
    private val sent = AtomicBoolean(false)

    /** True once a reply was attempted. */
    val answered: Boolean get() = sent.get()

    /** Runs [send] when no reply was attempted before; returns false, and runs nothing, for any later call. */
    fun once(send: () -> Unit): Boolean {
        if (!sent.compareAndSet(false, true)) return false
        try {
            send()
        } catch (_: Exception) {
            // The single reply was attempted and failed; it is not sent again (no second answer).
        }
        return true
    }
}
