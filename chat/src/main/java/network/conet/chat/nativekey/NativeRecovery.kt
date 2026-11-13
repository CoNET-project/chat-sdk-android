package network.conet.chat.nativekey

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * The native recovery screen and the PWA's result event (spec 25.26.4e.2). The shell registers [launcher] to show its
 * screen. The PWA gets `nativeRecoveryResult {reqId, code, eoa?}` and nothing else: no code, phrase, PIN or key.
 */
object NativeRecoveryHost {
    /** The shell opens its native recovery screen here. Returns `false` when there is no screen. */
    @Volatile
    var launcher: (() -> Boolean)? = null

    /** Set by the module, so the result goes out as an event. */
    @Volatile
    internal var events: ((JSONObject) -> Unit)? = null

    @Volatile
    private var pendingReqId: Any? = null

    /** Opens the screen for a `nativeRecoveryOpen` with this [reqId]. The result is then sent for this reqId. */
    internal fun open(reqId: Any): Boolean {
        val show = launcher ?: return false
        pendingReqId = reqId
        val opened = try {
            show()
        } catch (_: Exception) {
            false
        }
        if (!opened) pendingReqId = null
        return opened
    }

    /** The user dismissed the native screen. */
    fun cancel() {
        finish(RecoveryOutcome.fail("cancelled"))
    }

    /** Sends the result to the PWA for the pending `nativeRecoveryOpen`, if there is one. */
    internal fun finish(outcome: RecoveryOutcome) {
        val id = pendingReqId ?: return
        pendingReqId = null
        val payload = JSONObject()
            .put("type", "nativeRecoveryResult")
            .put("reqId", id)
            .put("code", outcome.code)
        outcome.eoa?.let { payload.put("eoa", it) }
        events?.invoke(payload)
    }
}

/** Path A, restore by recovery code (spec 25.26.4e.3). Native to native: the code never reaches a WebView. */
object NativeRecovery {
    private const val TAG = "NativeRecovery"
    private val worker = Executors.newSingleThreadExecutor()

    /**
     * Runs the restore off the main thread. [recoveryCode] is copied and the copy is zeroed after use; the caller should
     * zero its own array. [onResult] runs on the worker thread: switch to the main thread before touching UI. The
     * outcome is also sent to the PWA when a `nativeRecoveryOpen` is pending. Only the result code is logged.
     */
    fun restoreWithRecoveryCode(context: Context, recoveryCode: ByteArray, onResult: (RecoveryOutcome) -> Unit) {
        val app = context.applicationContext
        val code = recoveryCode.copyOf()
        worker.execute {
            val outcome = try {
                val cfg = AccountRegistryRead.config
                val rpc = AddressPgpRead.HttpRpc(cfg.rpcUrl)
                RecoveryRestore.run(code, NativeWallet.vault(app)) { index ->
                    AccountRegistryRead.getBase64ByNameHash(rpc, cfg, index)
                }
            } catch (_: Exception) {
                RecoveryOutcome.fail("network_error")
            } finally {
                code.fill(0)
            }
            Log.i(TAG, "native recovery result=${outcome.code}")
            NativeRecoveryHost.finish(outcome)
            onResult(outcome)
        }
    }
}
