package network.conet.chat

import android.os.Handler
import android.os.Looper

/**
 * The poster the module uses for work on the main thread. Production posts to the main Looper exactly as before. A test seam: [runner], when set,
 * runs the work inline on the calling thread, so the module's answers reach the caller in a plain JVM test (no Robolectric in this module).
 * [runner] is null in production and is only set by tests, which clear it again.
 */
internal object MainPoster {
    private val handler: Handler by lazy { Handler(Looper.getMainLooper()) }

    @Volatile
    var runner: ((Runnable) -> Unit)? = null

    fun post(task: Runnable): Boolean {
        val inline = runner
        if (inline != null) {
            inline(task)
            return true
        }
        return handler.post(task)
    }

    fun postDelayed(task: Runnable, delayMillis: Long): Boolean {
        val inline = runner
        if (inline != null) {
            inline(task)
            return true
        }
        return handler.postDelayed(task, delayMillis)
    }
}
