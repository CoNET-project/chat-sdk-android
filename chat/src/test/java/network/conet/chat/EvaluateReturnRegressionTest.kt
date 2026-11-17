package network.conet.chat

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression for the consumer 171 emulator `encrypt_fail` (Android review 2026-11-17): Chromium 124 returns `{}` from
 * `evaluateJavascript` for an async IIFE, and 0.2.6 completed the host call from that return value.
 *
 * The 0.2.6 decision is not in this tree any more, so [oldReturnRule] replays it verbatim for a `{}` return
 * (`parseJsJsonResult` in 3a8e601: `ok` false, `error` empty, delivered as the call's answer). The current decision is
 * [BridgeResultRule]. The WebView path itself is not reachable on the JVM: the end-to-end check is on the device, not here.
 */
class EvaluateReturnRegressionTest {

    /** 0.2.6 `parseJsJsonResult` for a plain JSON object return, delivered as the call's answer. */
    private data class OldDelivered(val ok: Boolean, val error: String)

    private fun oldReturnRule(raw: String): OldDelivered {
        val obj = JSONObject(raw)
        return OldDelivered(ok = obj.optBoolean("ok", false), error = obj.optString("error", ""))
    }

    @Test
    fun the0Point2Point6RuleTurnsAnEmptyReturnIntoAFailedAnswer() {
        // The precondition of encrypt_fail: the return completed the call as ok=false with no error text.
        val delivered = oldReturnRule("{}")
        assertFalse(delivered.ok)
        assertEquals("", delivered.error)
    }

    @Test
    fun anEmptyReturnIsNotAnAnswerSoTheCallKeepsWaiting() {
        assertFalse(BridgeResultRule.isAnswer("{}"))
    }

    @Test
    fun aPostResultWithOkOrErrorIsTheAnswer() {
        assertTrue(BridgeResultRule.isAnswer("""{"ok":true,"armor":"-----BEGIN PGP MESSAGE-----"}"""))
        assertTrue(BridgeResultRule.isAnswer("""{"ok":false,"error":"encrypt_fail"}"""))
        assertTrue(BridgeResultRule.isAnswer("""{"error":"js_bridge_timeout"}"""))
    }

    @Test
    fun aNonObjectOrBrokenMessageIsNotAnAnswer() {
        assertFalse(BridgeResultRule.isAnswer(""))
        assertFalse(BridgeResultRule.isAnswer("undefined"))
        assertFalse(BridgeResultRule.isAnswer("""{"armor":"x"}"""))
        assertFalse(BridgeResultRule.isAnswer("""{"ok":"""))
    }
}
