package network.conet.chat.nativekey

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * The native recovery page and its result events (§25.41.3, §25.42.8). The shell registers [launcher] to show its page.
 * One page has one `reqId`. Each submission sends exactly one `nativeRecoveryResult`. A failure keeps the page open for a
 * retry. `ok` ends the page. Closing the page with no result sent yet sends `cancelled`.
 */
object NativeRecoveryHost {
    /** The shell opens its native recovery page here. Returns `true` when the page is open. */
    @Volatile
    var launcher: (() -> Boolean)? = null

    /** Set by the module, so the results go out through the chat module event envelope. */
    @Volatile
    internal var events: ((JSONObject) -> Unit)? = null

    @Volatile
    private var pageReqId: Any? = null

    @Volatile
    private var resultSent = false

    internal enum class OpenAnswer { NOT_SUPPORTED, NOT_AVAILABLE, OPENED }

    /** `nativeRecoveryOpen` (§25.41.3): not registered is `not_supported`; registered but refused is `not_available`. */
    internal fun open(reqId: Any): OpenAnswer {
        val show = launcher ?: return OpenAnswer.NOT_SUPPORTED
        pageReqId = reqId
        resultSent = false
        val opened = try {
            show()
        } catch (_: Exception) {
            false
        }
        if (!opened) {
            pageReqId = null
            return OpenAnswer.NOT_AVAILABLE
        }
        return OpenAnswer.OPENED
    }

    /** The `reqId` of the open page, if any. */
    internal fun currentReqId(): Any? = pageReqId

    /** The page was closed by the user or the system. Sends `cancelled` when no result was sent for this page. */
    fun pageClosed() {
        val id = pageReqId ?: return
        if (!resultSent) emit(id, RecoveryOutcome.fail("cancelled"))
        pageReqId = null
        resultSent = false
    }

    /** Same as [pageClosed]. */
    fun cancel() {
        pageClosed()
    }

    /** One submission's result, for the open page. `ok` ends the page; any other result keeps it open. */
    internal fun finish(outcome: RecoveryOutcome) {
        val id = pageReqId ?: return
        emit(id, outcome)
        resultSent = true
        if (outcome.code == "ok") {
            pageReqId = null
            resultSent = false
        }
    }

    private fun emit(id: Any, outcome: RecoveryOutcome) {
        val payload = JSONObject()
            .put("type", "nativeRecoveryResult")
            .put("reqId", id)
            .put("code", outcome.code)
        outcome.eoa?.let { payload.put("eoa", it) }
        outcome.cooldownSec?.let { payload.put("cooldownSec", it) }
        events?.invoke(payload)
    }
}

/**
 * Path A (recovery code) and path B (account name and password), §25.42. Native to native: the secrets are read only in the
 * native layer and never reach a WebView. Submissions run one at a time on a worker thread. The logs hold the result code only.
 */
object NativeRecovery {
    private const val TAG = "NativeRecovery"
    private val worker = Executors.newSingleThreadExecutor()

    /** Path A. [recoveryCode] is copied and the copy is cleared after use; the caller clears its own array. */
    fun restoreWithRecoveryCode(context: Context, recoveryCode: ByteArray, onResult: (RecoveryOutcome) -> Unit) {
        val app = context.applicationContext
        val code = recoveryCode.copyOf()
        worker.execute {
            val outcome = try {
                engine(app).restoreWithCode(code)
            } catch (e: Exception) {
                Log.w(TAG, "native recovery failed: ${e.javaClass.simpleName}")
                RecoveryOutcome.fail("network_error")
            } finally {
                code.fill(0)
            }
            deliver(outcome, onResult)
        }
    }

    /**
     * Path B. [password] is copied and the copy is cleared after use; the caller clears its own array. The account name is
     * trimmed by the engine and is not logged.
     */
    fun restoreWithAccountPassword(
        context: Context,
        accountName: String,
        password: CharArray,
        onResult: (RecoveryOutcome) -> Unit,
    ) {
        val app = context.applicationContext
        val pw = password.copyOf()
        worker.execute {
            val outcome = try {
                engine(app).restoreWithAccountPassword(accountName, pw)
            } catch (e: Exception) {
                Log.w(TAG, "native recovery failed: ${e.javaClass.simpleName}")
                RecoveryOutcome.fail("network_error")
            } finally {
                pw.fill('\u0000')
            }
            deliver(outcome, onResult)
        }
    }

    private fun deliver(outcome: RecoveryOutcome, onResult: (RecoveryOutcome) -> Unit) {
        Log.i(TAG, "native recovery result=${outcome.code}")
        NativeRecoveryHost.finish(outcome)
        onResult(outcome)
    }

    private fun engine(app: Context): RecoveryEngine = RecoveryEngine(
        vault = NativeWallet.vault(app),
        registry = EndpointRegistryReader { ep -> AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs) },
        failures = SharedPreferencesFailureStore(app),
        clock = RecoveryClock { System.currentTimeMillis() },
    )
}

/** Path B's failure count and last-failure time, on the device (§25.42.7). Counts and times only. */
internal class SharedPreferencesFailureStore(context: Context) : RecoveryFailureStore {
    private val prefs = context.getSharedPreferences("beamio_native_recovery", Context.MODE_PRIVATE)

    override fun failures(): Int = prefs.getInt(KEY_FAILURES, 0)

    override fun lastFailureAtMs(): Long = prefs.getLong(KEY_LAST_AT, 0L)

    override fun save(failures: Int, atMs: Long) {
        prefs.edit().putInt(KEY_FAILURES, failures).putLong(KEY_LAST_AT, atMs).commit()
    }

    override fun clear() {
        prefs.edit().remove(KEY_FAILURES).remove(KEY_LAST_AT).commit()
    }

    private companion object {
        const val KEY_FAILURES = "path_b_failures"
        const val KEY_LAST_AT = "path_b_last_failure_ms"
    }
}
