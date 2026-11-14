package network.conet.chat

import org.json.JSONObject

/**
 * QA only (chatQaHooks; spec §25.52AX.3, AN.2). Replaces the web emit used by [BeamioConetChatModule.handleCommand] and returns the one it
 * replaces. Only the QA native entry (`NativeQaHooks`) calls it: it captures the ack of one native command and puts the previous emit back.
 * This file is compiled only with `-PchatQaHooks`, so the release has no `swapWebEmit` symbol.
 */
internal fun BeamioConetChatModule.swapWebEmit(emit: ((JSONObject) -> Unit)?): ((JSONObject) -> Unit)? {
    val previous = emitFn
    emitFn = emit
    return previous
}
