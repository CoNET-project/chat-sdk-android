package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * One run of `accountCleanupOld`: the payload's field names, its accountKey and idempotencyKey, the native new account and whether it is
 * readable. The module passes the [AccountCleanupRun] it builds; a test passes one built the same way.
 */
internal typealias CleanupRun = (
    fields: List<String>,
    accountKey: String?,
    idempotencyKey: String?,
    newAccountKey: String?,
    newAccountReadable: Boolean,
) -> AccountCleanupOld.Outcome

/**
 * The `accountCleanupOld` entry (25.52Y.91, Y.103 第 2 条): the bridge's dispatch calls [handle] off the caller's thread. It reads the payload's
 * field names (without `type` and `reqId`), the native new account, runs the given [CleanupRun] (the same run the bridge builds), and returns the
 * one ack for the reqId. No run means not_ready (no context); a run that throws is clear_incomplete with cleanupPending true, never ok.
 */
internal object AccountCleanupDispatch {
    fun handle(
        reqId: Any?,
        body: JSONObject,
        nativeNewAccount: () -> String?,
        runFor: () -> CleanupRun?,
    ): JSONObject {
        val run = runFor() ?: return accountCleanupAck(reqId, AccountCleanupOld.Outcome(AccountCleanupOld.NOT_READY, emptyList(), emptyList(), false))
        val fields = body.keys().asSequence().map { it.toString() }.filter { it != "type" && it != "reqId" }.toList()
        val newKey = try {
            nativeNewAccount()
        } catch (_: Exception) {
            null
        }
        val outcome = try {
            run(
                fields,
                body.optString("accountKey", "").ifEmpty { null },
                body.optString("idempotencyKey", "").ifEmpty { null },
                newKey,
                newKey != null,
            )
        } catch (_: Exception) {
            AccountCleanupOld.Outcome(AccountCleanupOld.CLEAR_INCOMPLETE, emptyList(), emptyList(), cleanupPending = true)
        }
        return accountCleanupAck(reqId, outcome)
    }
}
