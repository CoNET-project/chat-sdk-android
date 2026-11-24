package network.conet.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source guards on how the module wires the sender receipt (comments stripped, so a comment cannot satisfy a guard): the receipt goes through the
 * session's pipeline only, after the mailbox ACK; `setRoutes` is always answered and init no longer fills routes; the session's receipt state is
 * cleared when it ends or is replaced; and the module's own send answers nobody, carries beamioNoPush and stops once its session is gone.
 */
class ReceiptWiringGuardTest {
    private val module = stripComments(File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8))

    private fun stripComments(src: String): String =
        src.replace(Regex("/\\*[\\s\\S]*?\\*/"), "").lines().joinToString("\n") { it.replace(Regex("//.*$"), "") }

    /** The text of `private fun [name](` up to the next function at the same indentation. */
    private fun body(name: String): String {
        val start = module.indexOf("    private fun $name(")
        assertTrue("$name exists", start >= 0)
        val end = module.indexOf("\n    private fun ", start + 10).let { if (it < 0) module.length else it }
        return module.substring(start, end)
    }

    @Test
    fun theMailboxAckComesFirstAndTheReceiptGoesOnlyThroughThePipeline() {
        val b = body("emitDualReceipts")
        val ack = b.indexOf("gossip_delivery_ack")
        val receipt = b.indexOf("s.receipts.onAcked(plaintext, armorHash, from)")
        assertTrue("mailbox ack present", ack >= 0)
        assertTrue("receipt call present", receipt > ack)
        assertFalse("no handleSend on the command thread", b.contains("handleSend("))
        assertFalse("no route lookup of its own", b.contains("routes"))
    }

    @Test
    fun thePipelineIsBuiltWithTheSessionCheckTheWorkerAndTheBoundSend() {
        val start = module.indexOf("internal val receipts: SenderReceipt.Pipeline = SenderReceipt.Pipeline(")
        assertTrue(start > 0)
        val cfg = module.substring(start, module.indexOf("clearReceiptState", start))
        assertTrue(cfg.contains("execute = { io.execute(it) }"))
        assertTrue(cfg.contains("alive = { !destroyed && currentSession() === this }"))
        assertTrue(cfg.contains("ownEoa = { eoa }"))
        val send = body("receiptSend")
        assertTrue(send.contains(".put(\"beamioNoPush\", true)"))
        assertTrue(send.contains("bound = s"))
        assertTrue(send.contains("done = done"))
    }

    @Test
    fun setRoutesIsAlwaysAnsweredAndInitNoLongerFillsRoutes() {
        assertTrue(module.contains("\"setRoutes\" -> handleSetRoutes(body)"))
        val b = body("handleSetRoutes")
        assertTrue(b.contains("ack(reqId, false, error = r.code)"))
        assertTrue(b.contains("ack(reqId, true, result = JSONObject().put(\"accepted\", r.accepted).put(\"dropped\", r.dropped))"))
        assertTrue(b.contains("SenderReceipt.setRoutes(body, s?.eoa)"))
        assertFalse("the old unvalidated replacement is gone", module.contains("s.routes"))
        assertFalse("init does not read routes", module.contains("optJSONArray(\"routes\")"))
        // the log has counts only
        assertFalse(b.contains("userPublicKeyArmored"))
    }

    @Test
    fun theSessionClearsItsReceiptStateWhenItEndsOrIsReplaced() {
        assertTrue(body("endPageSession").contains("session?.clearReceiptState()"))
        val replace = module.indexOf("session?.history?.destroy()\n                session = s")
        assertTrue("the replacement site exists", replace > 0)
        assertTrue(module.substring(maxOf(0, replace - 200), replace).contains("session?.clearReceiptState()"))
        assertEquals(2, Regex("""session\?\.clearReceiptState\(\)""").findAll(module).count())
    }

    @Test
    fun theClearEmptiesThePipelineAndPendingAcks() {
        val m = module.substring(module.indexOf("fun clearReceiptState()"))
        val fn = m.substring(0, m.indexOf("\n        }") + 10)
        assertTrue(fn.contains("receipts.clear()"))
        assertTrue(fn.contains("pendingAcks.clear()"))
    }

    @Test
    fun theModulesOwnSendAnswersNobodyAndStopsWhenItsSessionIsGone() {
        val b = body("handleSend")
        assertTrue(b.contains("bound: Session? = null, done: (() -> Unit)? = null"))
        assertTrue("a bound send fails to the log and frees its slot", b.contains("Log.i(TAG, \"[send] kind=receipt ok=0 error=\$code\")\n                done?.invoke()"))
        assertTrue(b.contains("bound != null && (bound.destroyed || currentSession() !== bound)"))
        assertTrue("it refuses to run under another session", b.contains("(bound != null && s !== bound)"))
        // the stale check sits before the sign result is used, and again before the POST
        assertEquals(2, Regex("""\bstale\(\)""").findAll(b.replace("fun stale()", "")).count())
        assertTrue("the slot is freed after the POST too", b.contains("Log.i(TAG, \"[send] kind=receipt ok=\${if (ok) 1 else 0}\")\n                                done?.invoke()"))
        assertFalse("every failure goes through fail()", Regex("""\n\s+ack\(reqId, false""").containsMatchIn(b.replace("else ack(reqId, false, error = code)", "").replace("ack(reqId, false, error = code)", "")))
    }
}
