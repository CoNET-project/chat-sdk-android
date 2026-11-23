package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The shellRecord answers for a passcode-protected account (v286 SRP v1). The shell holds no passcode,
 * so it does not read or write such an account: the read is ok with result {code:not_ready, notReadyReason:passcode_not_provided,
 * retryable:true}; the write is ok:false with error not_ready, the same notReadyReason and retryable, and writes nothing. It is not
 * storage_locked and not write_failed. A real storage fault keeps its own answer (record_unreadable for a read, write_failed for a write).
 */
internal object ShellPasscodeAnswer {
    const val NOT_READY = "not_ready"
    const val REASON = "passcode_not_provided"
    const val UNREADABLE = "unreadable"

    /** A passcode-protected account: the current set of the store is a v3 envelope. Any other state is not a passcode account here. */
    fun isPasscodeAccount(current: MnemonicSetStore.Current): Boolean =
        current is MnemonicSetStore.Current.Found && current.kind == MnemonicSetStore.Kind.V3

    fun readAck(reqId: Any): JSONObject = JSONObject()
        .put("type", "ack").put("reqId", reqId).put("ok", true)
        .put("result", JSONObject().put("code", NOT_READY).put("notReadyReason", REASON).put("retryable", true))

    fun writeAck(reqId: Any): JSONObject = JSONObject()
        .put("type", "ack").put("reqId", reqId).put("ok", false)
        .put("error", NOT_READY).put("notReadyReason", REASON).put("retryable", true)

    /**
     * The state of the store cannot be determined (a corrupt pointer or a missing set): not_ready with notReadyReason unreadable, retryable.
     * It is never taken for an absent or a plain account, and the ordinary read or write path does not run (SRP v2 SRP-05).
     */
    fun readUnknownAck(reqId: Any): JSONObject = JSONObject()
        .put("type", "ack").put("reqId", reqId).put("ok", true)
        .put("result", JSONObject().put("code", NOT_READY).put("notReadyReason", UNREADABLE).put("retryable", true))

    fun writeUnknownAck(reqId: Any): JSONObject = JSONObject()
        .put("type", "ack").put("reqId", reqId).put("ok", false)
        .put("error", NOT_READY).put("notReadyReason", UNREADABLE).put("retryable", true)

    /** The state is unknown: nothing is read or written, and the answer is the unreadable one. */
    fun isUnknownState(current: MnemonicSetStore.Current): Boolean = current is MnemonicSetStore.Current.Unknown
}
