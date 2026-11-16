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

    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "conet-vault-snapshot").apply { isDaemon = true } }
    private val pending = AtomicBoolean(false)
    @Volatile private var notBefore = 0L

    /** Schedules one computation unless one is pending or the backoff has not passed. Never blocks. */
    fun schedule(app: Context) {
        if (System.currentTimeMillis() < notBefore) return
        if (!pending.compareAndSet(false, true)) return
        executor.execute {
            try {
                NativeWallet.vault(app).state()
            } catch (_: Exception) {
                notBefore = System.currentTimeMillis() + BACKOFF_MS
            } finally {
                pending.set(false)
            }
        }
    }
}
