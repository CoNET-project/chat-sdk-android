package network.conet.chat.nativekey

import android.content.Context
import android.os.Looper
import android.util.Log
import network.conet.chat.BeamioConetChatModule
import network.conet.chat.identity.IdentityProvisionContract
import network.conet.chat.swapWebEmit
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * QA-only tools (spec r3bw §25.52AA.5, HK-01 to HK-03). They are compiled only into the QA build (`-PchatQaHooks`), never into the production
 * AAR, and they are reachable from no bridge: no page message, no `window.BeamioShellRecord`, no chat-module command. Only the shell's native QA
 * page calls them.
 *
 * - [dropEoaKeyOfAccount]: its one effect makes the state "the record has no EOA private key" (needs_native_recovery, AK-20) for the account.
 * - [runCommand] (R591, device evidence for A5): runs a fixed list of native commands through the same [BeamioConetChatModule.handleCommand]
 *   the bridge uses, without the WebView, and declares no capability. It refuses key names at any depth, removes key names from every reply,
 *   and logs only the command name and the outcome.
 */
object NativeQaHooks {
    private const val TAG = "BeamioNativeQa"

    /** The wait for one ack, in milliseconds, when the caller gives none. */
    const val DEFAULT_TIMEOUT_MS: Long = 15_000L

    /** The commands the QA page may run: the A5 device-evidence set. Any other command is refused as `not_allowed`. */
    internal val ALLOWED_COMMANDS: Set<String> =
        setOf("identityPublic", "walletStatus", "init", "provisionIdentity", "pgpRestore", "pgpRestoreEvaluate")

    /**
     * The event types that answer a command: an `ack` for most commands, and `ready` for a successful `init` (the module's finishInit emits
     * `ready` with the reqId; init's failures are acks). Only events with the reqId of this call count.
     */
    internal val ANSWER_TYPES: Set<String> = setOf("ack", "ready")

    /** The module seam of [runWith]. Tests replace it; production uses [moduleSink]. */
    internal interface Sink {
        /** Replaces the web emit and returns the one it replaces. */
        fun swapEmit(emit: ((JSONObject) -> Unit)?): ((JSONObject) -> Unit)?

        /** Delivers one command the way the bridge does. The replies go to [emit]. */
        fun handle(body: JSONObject, emit: (JSONObject) -> Unit)
    }

    private fun moduleSink(context: Context): Sink = object : Sink {
        override fun swapEmit(emit: ((JSONObject) -> Unit)?): ((JSONObject) -> Unit)? = BeamioConetChatModule.swapWebEmit(emit)
        override fun handle(body: JSONObject, emit: (JSONObject) -> Unit) = BeamioConetChatModule.handleCommand(context, body, emit)
    }

    /** Removes `privateKeyArmor` from the profile of [eoa] and keeps the rest of the record, its revision, and the device flags. */
    fun dropEoaKeyOfAccount(context: Context, eoa: String) {
        val account = eoa.lowercase()
        val store = BeamioShellRecordImport.storeFor(context.applicationContext, account)
        dropEoaKey(store, account)
    }

    /** The record change of [dropEoaKeyOfAccount], on a store (no Context), so the behaviour test can run without Android. */
    internal fun dropEoaKey(store: SealedPageRecordStore, account: String) {
        val record = store.read() ?: return
        val profiles = record.optJSONArray("profiles") ?: return
        for (i in 0 until profiles.length()) {
            val profile = profiles.optJSONObject(i) ?: continue
            if (profile.optString("keyID", "").equals(account, ignoreCase = true)) profile.remove("privateKeyArmor")
        }
        store.write(record)
    }

    /**
     * Runs one native command for the shell's QA page and returns its ack, with key names removed. The command goes through the module's own
     * [BeamioConetChatModule.handleCommand] without the WebView, and declares no capability. `reqId` must be a non-negative integer.
     * Blocking: call it from a background thread. On the main thread it returns `main_thread` at once, because the ack is posted to the main
     * thread and would never arrive.
     */
    fun runCommand(context: Context, command: String, body: JSONObject, timeoutMs: Long = DEFAULT_TIMEOUT_MS): JSONObject {
        val reqId = (body.opt("reqId") as? Int)?.takeIf { it >= 0 }
        val reply = if (Looper.myLooper() == Looper.getMainLooper()) {
            refusal(reqId, "main_thread")
        } else {
            runWith(moduleSink(context.applicationContext), command, body, timeoutMs)
        }
        val shown = if (command in ALLOWED_COMMANDS) command else "(refused)"
        Log.i(TAG, "qa command=$shown ok=${reply.optBoolean("ok")} code=${reply.optString("error", "none")}")
        return reply
    }

    /**
     * The QA entry's rules on a [Sink], so they can be tested without Android: the allowlist, the reqId, the refusal of key names at any depth,
     * the wait for the ack of this reqId, the removal of key names from the reply, and the restore of the web emit.
     */
    internal fun runWith(sink: Sink, command: String, body: JSONObject, timeoutMs: Long): JSONObject {
        if (command !in ALLOWED_COMMANDS) return refusal(null, "not_allowed")
        val reqId = (body.opt("reqId") as? Int)?.takeIf { it >= 0 } ?: return refusal(null, "bad_request")
        if (containsForbiddenKey(body)) return refusal(reqId, "key_over_bridge_refused")
        // The module reads `type` from the body. A copy carries the command, so the caller's object is not changed.
        val call = JSONObject(body.toString()).put("type", command)
        val answer = AtomicReference<JSONObject?>(null)
        val answered = CountDownLatch(1)
        val capture: (JSONObject) -> Unit = { out ->
            val event = out.optJSONObject("event")
            val isOurAck = event != null && out.optString("action") == "chatModuleEvent" &&
                event.optString("type") in ANSWER_TYPES && event.opt("reqId")?.toString() == reqId.toString()
            if (isOurAck && answer.compareAndSet(null, event)) answered.countDown()
        }
        val previous = sink.swapEmit(capture)
        return try {
            sink.handle(call, capture)
            val arrived = answered.await(timeoutMs, TimeUnit.MILLISECONDS)
            val ack = answer.get()
            if (arrived && ack != null) redact(ack) else refusal(reqId, "timeout")
        } catch (e: RuntimeException) {
            refusal(reqId, "module_error")
        } finally {
            sink.swapEmit(previous)
        }
    }

    /** True when any key name at any depth (objects and arrays) is one of the forbidden key names. */
    internal fun containsForbiddenKey(node: Any?): Boolean = when (node) {
        is JSONObject -> node.keys().asSequence().any { isForbiddenName(it) || containsForbiddenKey(node.opt(it)) }
        is JSONArray -> (0 until node.length()).any { containsForbiddenKey(node.opt(it)) }
        else -> false
    }

    /** A copy of [node] without any forbidden key name, at any depth. Other values are kept as they are. */
    internal fun redact(node: JSONObject): JSONObject = JSONObject().also { out ->
        node.keys().asSequence().filterNot { isForbiddenName(it) }.forEach { out.put(it, redactValue(node.opt(it))) }
    }

    private fun redactValue(node: Any?): Any? = when (node) {
        is JSONObject -> redact(node)
        is JSONArray -> JSONArray().also { out -> for (i in 0 until node.length()) out.put(redactValue(node.opt(i))) }
        else -> node
    }

    /** The forbidden names, compared without case and without separators, so `privateKeyHex`, `PRIVATE_KEY_HEX` and `private-key-hex` match. */
    private val FORBIDDEN_NAMES: Set<String> = IdentityProvisionContract.FORBIDDEN_KEYS.map { nameKey(it) }.toSet()

    private fun nameKey(name: String): String = name.filter { it.isLetterOrDigit() }.lowercase()

    internal fun isForbiddenName(name: String): Boolean = nameKey(name) in FORBIDDEN_NAMES

    /** A refusal from this entry. `qaRefusal` tells it apart from an error the module itself reports. */
    private fun refusal(reqId: Int?, code: String): JSONObject =
        JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", false).put("error", code).put("qaRefusal", true)
}
