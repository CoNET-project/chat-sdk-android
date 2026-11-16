package network.conet.chat.nativekey

import android.content.Context
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Computes the vault snapshot on its own io thread (25.52Y.75). At most one computation is pending. A failed computation backs off for [BACKOFF_MS]
 * before the next attempt, so a command storm does not reopen the keystore on every call. Callers never wait for it.
 */
internal object VaultSnapshotRefresh {
    const val BACKOFF_MS = 30_000L

    /** The backoff after [failures] consecutive failures (project ruling 2026-11-16): 1 s, 2 s, 4 s, …, capped at [BACKOFF_MS]. 0 when none. */
    internal fun backoffMs(failures: Int): Long = when {
        failures <= 0 -> 0L
        failures > 6 -> BACKOFF_MS
        else -> minOf(1_000L shl (failures - 1), BACKOFF_MS)
    }

    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "conet-vault-snapshot").apply { isDaemon = true } }
    private val pending = AtomicBoolean(false)
    @Volatile private var notBefore = 0L
    @Volatile private var failures = 0

    /** Schedules one computation unless one is pending or the backoff has not passed. Never blocks. */
    fun schedule(app: Context) {
        if (System.currentTimeMillis() < notBefore) {
            DiagTiming.log("snapshotRefresh:backoff", DiagTiming.now(), "skip")
            return
        }
        if (!pending.compareAndSet(false, true)) return
        executor.execute {
            // diag3 (logging only): start, end, result with the thread, milliseconds and a code. No content.
            val t0 = DiagTiming.now()
            try {
                NativeWallet.vault(app).state()
                failures = 0
                notBefore = 0L
                DiagTiming.log("snapshotRefresh", t0, "ok")
            } catch (e: Exception) {
                failures++
                notBefore = System.currentTimeMillis() + backoffMs(failures)
                DiagTiming.log("snapshotRefresh", t0, "fail:" + e.javaClass.simpleName)
            } finally {
                pending.set(false)
            }
        }
    }
}
