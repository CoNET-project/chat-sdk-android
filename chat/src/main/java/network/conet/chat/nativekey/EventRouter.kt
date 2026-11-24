package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * Where a payload the module emits goes.
 *
 * The module used to keep ONE global emit, replaced by every command with the emit that command was called with, and later events read it. The page
 * sync commands (`pwaWalletSync`, `nativeMnemonicPreread`, the passcode commands ...) come in on the shell's window channel with a lambda that keeps only
 * the first ack and drops the rest, so a page sync command that ran while `init` was still unlocking took over the emit, and `init`'s `ready` (and any
 * inbound message or listen status after it) went into that lambda and vanished: the page waited its 180 s for a ready that was never delivered.
 *
 * Now:
 *  - [events]: the emit of the latest NON reply-only command (the chat commands). Every asynchronous event goes there: `ready`, inbound messages,
 *    listen status, logs.
 *  - A reply-only command (answers once, with an ack, on the caller's own channel) does not touch [events]. The ack it emits on the calling thread, during
 *    the call, with its own request id, goes to the emit it was called with; that registration is consumed by that ack and gone when the call returns.
 *
 * The registration is bound to the CALLING THREAD and to the request id, not to the request id alone, so a chat command that happens to use the same
 * request id (ids are not unique across channels) can never take it, and a reply-only command's ack can never be taken by another command. An ack
 * emitted from another thread, with another id, after the first ack, or after the call returned is an ordinary event: it goes to [events].
 */
internal class EventRouter {
    /** The emit of the latest chat (non reply-only) command. Asynchronous events go here. */
    @Volatile
    var events: ((JSONObject) -> Unit)? = null

    private class Reply(val key: String?, val emit: (JSONObject) -> Unit)

    private val reply = ThreadLocal<Reply?>()

    /** Runs one command. A chat command becomes the event sink; a reply-only command registers its own reply for the duration of [block]. */
    fun <T> command(replyOnly: Boolean, emit: (JSONObject) -> Unit, reqId: Any?, block: () -> T): T {
        if (!replyOnly) {
            events = emit
            return block()
        }
        val previous = reply.get()
        reply.set(Reply(CommandAnswerGuard.keyOf(reqId), emit))
        try {
            return block()
        } finally {
            reply.set(previous)
        }
    }

    /**
     * [command] with the failure answer INSIDE its scope. An exception that escapes the handler is caught here, while a reply-only command's
     * registration still stands, so [onException] (which emits the one `not_ready` ack of the request) reaches the caller's own emit and not the chat
     * emit. A catch outside [command] would run after the registration was gone and the page sync caller would wait for an answer that went elsewhere.
     * An Error is not caught: the registration is removed on the way out and the Error goes on (an Error is never turned into an answer).
     */
    fun <T> commandGuarded(replyOnly: Boolean, emit: (JSONObject) -> Unit, reqId: Any?, onException: (Exception) -> Unit, block: () -> T): T? =
        command(replyOnly, emit, reqId) {
            try {
                block()
            } catch (e: Exception) {
                onException(e)
                null
            }
        }

    /**
     * The sink of [payload], asked on the thread that emits it: the reply-only command's own emit for its first ack with its own request id (the
     * registration is then consumed), otherwise null, which means [events].
     */
    fun replyFor(payload: JSONObject): ((JSONObject) -> Unit)? {
        val r = reply.get() ?: return null
        if (payload.optString("type") != "ack") return null
        if (CommandAnswerGuard.keyOf(payload.opt("reqId")) != r.key) return null
        reply.set(null)
        return r.emit
    }
}
