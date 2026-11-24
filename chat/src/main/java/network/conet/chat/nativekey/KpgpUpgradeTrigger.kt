package network.conet.chat.nativekey

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * When the K_pgp upgrade runs: after the account exists and its key can be read (a Ready vault, or a store account of a vault with no record), once
 * per account in a process unless it is waiting for a retry, asynchronously. A locked keychain or a v3 set that is not unlocked never runs it; it runs
 * after the unlock. The page is not blocked and the wallet is not affected by the result.
 *
 * One request per account at a time ([claimFor] refuses a second while one is in flight). A run that ended in a state the next start would
 * try again (`pgp_migration_retry`, an unreadable chain) is released with a growing delay ([release]), so a command does not repeat the chain read
 * at once; a run that settled is not repeated in this process. Nothing is kept across a restart: the state is the device's own (K_pgp present or
 * not), so a restart after an interrupted run starts the same upgrade again and finds what was already written.
 */
internal object KpgpUpgradeTrigger {
    private val ran = AtomicBoolean(false)

    private val inFlight: MutableSet<String> = ConcurrentHashMap.newKeySet()
    private val settled: MutableSet<String> = ConcurrentHashMap.newKeySet()
    private val retryAtMs = ConcurrentHashMap<String, Long>()
    private val attempts = ConcurrentHashMap<String, Int>()

    /** The delay before a released account may run again: 60 s, doubling, at most 30 minutes. */
    internal fun delayMs(attempt: Int): Long = minOf(60_000L shl (attempt - 1).coerceIn(0, 10), 30L * 60_000L)

    /**
     * The vault state for the trigger, from the snapshot only: never the vault's monitor, never a Keystore read on the caller's thread. With
     * no snapshot yet, [schedule] asks for one and the answer is null (the caller leaves; the trigger stays pending and the next command asks again).
     */
    internal fun snapshotOrSchedule(vault: NativeWalletVault, schedule: () -> Unit): NativeWalletVault.State? {
        val s = vault.snapshotState()
        if (s == null) schedule()
        return s
    }

    /** True when the upgrade should start now: the vault is Ready (unlocked) and the upgrade has not run in this process. Claims the run. */
    fun claim(vault: NativeWalletVault.State?): Boolean {
        if (vault !is NativeWalletVault.State.Ready) return false
        return ran.compareAndSet(false, true)
    }

    /**
     * True when the account [eoa] may run now: it has not settled, no request for it is in flight, and its retry delay (if any) has passed. Claims the
     * request; the caller must [release] or [settle] it. [nowMs] is the clock (milliseconds).
     */
    fun claimFor(eoa: String, nowMs: Long): Boolean {
        val account = eoa.lowercase()
        if (account in settled) return false
        if (nowMs < (retryAtMs[account] ?: Long.MIN_VALUE)) return false
        return inFlight.add(account)
    }

    /**
     * A user-requested retry of [eoa]: it ignores the retry delay and an earlier settle (the upgrade then answers `keep_existing` if K_pgp is
     * there), but never runs beside another request for the same account. Claims the request; the caller must [release] or [settle] it.
     */
    fun claimForUserRetry(eoa: String): Boolean = inFlight.add(eoa.lowercase())

    /** The account's upgrade reached a state this process does not repeat. */
    fun settle(eoa: String) {
        val account = eoa.lowercase()
        settled.add(account)
        retryAtMs.remove(account)
        attempts.remove(account)
        inFlight.remove(account)
        ran.set(true)
    }

    /** The account's upgrade ended in a retry state: it may run again after a delay. */
    fun release(eoa: String, nowMs: Long) {
        val account = eoa.lowercase()
        val n = (attempts[account] ?: 0) + 1
        attempts[account] = n
        retryAtMs[account] = nowMs + delayMs(n)
        inFlight.remove(account)
    }

    /** True while the upgrade may still be wanted: no account has settled, or an account waits for its retry. Reads no vault state, so it is safe on any thread. */
    fun pending(): Boolean = !ran.get() || retryAtMs.isNotEmpty()

    /** Tests only: forgets every claim, as a restart does. */
    internal fun resetForTests() {
        ran.set(false)
        inFlight.clear()
        settled.clear()
        retryAtMs.clear()
        attempts.clear()
    }
}
