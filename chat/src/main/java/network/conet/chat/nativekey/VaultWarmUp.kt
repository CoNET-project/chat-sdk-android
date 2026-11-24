package network.conet.chat.nativekey

import android.content.Context
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The warm-up of what the first page commands need. The StrongBox serves one operation at a time and each takes seconds on the S25, so
 * the work is ordered instead of being started by three callers at once:
 *
 *  1. the wallet snapshot ([VaultSnapshotRefresh.computeWalletSnapshot]);
 *  2. the public identity snapshot of the account ([PublicIdentitySnapshot], one decrypt);
 *  3. then, and only then, the K_pgp upgrade trigger, which is handed to its own executor so that its chain reads never hold this thread.
 *
 * Everything runs on the one `conet-vault-snapshot` thread. Nothing here waits for the caller, takes the vault's monitor on a command's thread, or
 * writes anything but the two in-memory snapshots. It can start at `Application.onCreate` ([start] with no trigger) and again at the first command
 * (with the trigger); a second start while a run is waiting is not repeated, and a trigger asked for during a run is not lost.
 */
internal object VaultWarmUp {
    enum class Step { WALLET_SNAPSHOT, PUBLIC_IDENTITY, K_TRIGGER }

    /** The three steps, as seams. Production builds them from a context ([androidSteps]); tests pass fakes. */
    internal class Steps(
        val walletSnapshot: () -> Unit,
        val publicIdentity: () -> Unit,
    )

    /**
     * One warm-up queue. [execute] runs a task on the warm-up thread. [kTrigger] is read when step 3 comes (the module sets it at the first command).
     * A run catches the failure of a step and goes on with the next one: a failed wallet snapshot has its own backoff, and step 2 and 3 each look at
     * what they find.
     */
    internal class Engine(private val steps: Steps, private val execute: (Runnable) -> Unit) {
        private val running = AtomicBoolean(false)
        private val kWanted = AtomicBoolean(false)

        @Volatile
        var kTrigger: (() -> Unit)? = null

        /** Test hook: every step as it starts. */
        @Volatile
        var trace: (Step) -> Unit = {}

        /** Asks for a run. With [withTrigger] the K trigger runs as the last step of it. Never blocks. */
        fun start(withTrigger: (() -> Unit)?) {
            if (withTrigger != null) {
                kTrigger = withTrigger
                kWanted.set(true)
            }
            if (!running.compareAndSet(false, true)) return
            execute(Runnable { runOnce() })
        }

        private fun runOnce() {
            try {
                step(Step.WALLET_SNAPSHOT) { steps.walletSnapshot() }
                step(Step.PUBLIC_IDENTITY) { steps.publicIdentity() }
                if (kWanted.getAndSet(false)) {
                    val k = kTrigger
                    if (k != null) step(Step.K_TRIGGER) { k() }
                }
            } finally {
                running.set(false)
            }
            // A trigger asked for after step 3 had been looked at: one more run, not a lost request.
            if (kWanted.get()) start(null)
        }

        private fun step(s: Step, body: () -> Unit) {
            trace(s)
            try {
                body()
            } catch (_: Throwable) {
                DiagTiming.log("warmup.step", DiagTiming.now(), "fail:${s.name}")
            }
        }
    }

    /**
     * Step 2 as a function of what step 1 found. The account is the vault's (Ready), or the store's account of a vault with no record; any other
     * state has no account to read. A valid entry for the account is left as it is, so a repeated warm-up opens nothing. Returns the account that
     * was refreshed, or null when none was read.
     */
    internal fun publicIdentityStep(
        state: NativeWalletVault.State?,
        storeEoa: () -> String?,
        vaultFor: (String) -> NativePgpVault,
    ): String? {
        val eoa = when (state) {
            is NativeWalletVault.State.Ready -> state.eoa
            is NativeWalletVault.State.NoKey -> storeEoa()
            else -> null
        }?.lowercase()?.takeIf { it.isNotEmpty() } ?: return null
        return refreshIdentity(eoa, vaultFor)
    }

    /** Reads the public identity of [eoa] unless a valid entry exists. Returns [eoa] when it read. */
    internal fun refreshIdentity(eoa: String, vaultFor: (String) -> NativePgpVault): String? {
        val vault = vaultFor(eoa)
        if (PublicIdentitySnapshot.lookup(eoa, vault.fileSignature()) is PublicIdentitySnapshot.Lookup.Hit) return null
        val t0 = DiagTiming.now()
        val kind = PublicIdentitySnapshot.refresh(vault)
        DiagTiming.log("publicIdentity.refresh", t0, "kind=${kind.name}")
        return eoa
    }

    private fun androidSteps(app: Context) = Steps(
        walletSnapshot = {
            if (!VaultSnapshotRefresh.inBackoff() && NativeWallet.vault(app).snapshotState() == null) VaultSnapshotRefresh.computeWalletSnapshot(app)
        },
        publicIdentity = {
            publicIdentityStep(
                NativeWallet.vault(app).snapshotState(),
                { (StoreAwareAccount.resolveOnDevice(app) as? StoreAwareAccount.Resolution.Account)?.eoa },
            ) { NativeWallet.pgpFor(app, it) }
        },
    )

    @Volatile
    private var engine: Engine? = null

    private fun engineFor(app: Context): Engine = engine ?: synchronized(this) {
        engine ?: Engine(androidSteps(app.applicationContext)) { VaultSnapshotRefresh.executor.execute(it) }.also { engine = it }
    }

    /**
     * Starts the warm-up. `Application.onCreate` calls it with no trigger (steps 1 and 2); the first command calls it with the trigger.
     * Never blocks.
     */
    fun start(app: Context, kTrigger: (() -> Unit)? = null) {
        engineFor(app).start(kTrigger)
    }

    private val identityPending: MutableSet<String> = ConcurrentHashMap.newKeySet()

    /**
     * The public identity of [eoa] was asked for and is not in the snapshot (the session's account differs from the one step 2 found, or the entry
     * was dropped by a write): one refresh on the warm-up thread, one per account at a time. Never blocks.
     */
    fun warmIdentity(app: Context, eoa: String) {
        warmIdentityOn({ VaultSnapshotRefresh.executor.execute(it) }, eoa) { NativeWallet.pgpFor(app.applicationContext, it) }
    }

    /**
     * [warmIdentity] with its executor and vault as seams. A refresh that fails (the vault cannot be built, the read throws) stores nothing and
     * releases the account, so the next miss asks again: the page is never left on `not_ready` with no later read.
     */
    internal fun warmIdentityOn(execute: (Runnable) -> Unit, eoa: String, vaultFor: (String) -> NativePgpVault) {
        val key = eoa.lowercase()
        if (key.isEmpty() || !identityPending.add(key)) return
        execute(Runnable {
            try {
                refreshIdentity(key, vaultFor)
            } catch (_: Throwable) {
                DiagTiming.log("warmup.step", DiagTiming.now(), "fail:PUBLIC_IDENTITY")
            } finally {
                identityPending.remove(key)
            }
        })
    }

    internal fun resetForTests() {
        identityPending.clear()
    }
}
