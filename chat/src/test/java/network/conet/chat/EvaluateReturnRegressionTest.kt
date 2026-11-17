package network.conet.chat

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression and race reproduction for the consumer 171 emulator `encrypt_fail` and the send failure that
 * `wrapArmorToEntryRoute` turned into an unwrapped send (Android review 2026-11-17). Chromium 124 returns `{}` from
 * `evaluateJavascript` for an async IIFE.
 *
 * The 0.2.6 decisions are not in this tree any more, so [oldReturnRule] and [oldWrapRule] replay them verbatim for a `{}`
 * return. The current decisions are [JsResultRouter] and [EntryWrapPolicy]. The WebView itself is not reachable on the JVM:
 * the end-to-end check belongs on the device.
 */
class EvaluateReturnRegressionTest {

    /** Stands in for the main-thread Handler: a task runs only when the test fires it. */
    private class FakeTimers {
        private val tasks = LinkedHashMap<Int, () -> Unit>()
        private var seq = 0
        var cancelled = 0
            private set

        fun schedule(@Suppress("UNUSED_PARAMETER") delayMs: Long, task: () -> Unit): () -> Unit {
            val id = ++seq
            tasks[id] = task
            return {
                if (tasks.remove(id) != null) cancelled++
            }
        }

        val pendingCount: Int get() = tasks.size

        fun fireAll() {
            val now = tasks.values.toList()
            tasks.clear()
            now.forEach { it() }
        }
    }

    /** 0.2.6 `parseJsJsonResult` for a plain JSON object return, delivered as the call's answer (encrypt_fail). */
    private data class OldDelivered(val ok: Boolean, val error: String)

    private fun oldReturnRule(raw: String): OldDelivered {
        val obj = JSONObject(raw)
        return OldDelivered(ok = obj.optBoolean("ok", false), error = obj.optString("error", ""))
    }

    /** 0.2.6 `wrapArmorToEntryRoute` callback for a `{}` return: the unwrapped inner armor is reported as success. */
    private fun oldWrapRule(raw: String, innerArmor: String): Result<String> {
        val armor = if (raw.contains("BEGIN PGP MESSAGE")) raw else ""
        return Result.success(if (armor.contains("BEGIN PGP MESSAGE")) armor else innerArmor)
    }

    private fun router(timers: FakeTimers, onTimeout: (String) -> Unit) =
        JsResultRouter(timeoutMs = 25_000L, schedule = timers::schedule, onTimeout = onTimeout)

    @Test
    fun the0Point2Point6RuleTurnsAnEmptyReturnIntoAFailedAnswer() {
        // The precondition of encrypt_fail: the return completed the call as ok=false with no error text.
        val delivered = oldReturnRule("{}")
        assertFalse(delivered.ok)
        assertEquals("", delivered.error)
    }

    @Test
    fun the0Point2Point6WrapTurnsAnEmptyReturnIntoTheUnwrappedArmor() {
        // The send leak: the callers post the inner armor when the wrap "succeeds" with it.
        val inner = "-----BEGIN PGP MESSAGE-----\ninner\n-----END PGP MESSAGE-----"
        assertEquals(inner, oldWrapRule("{}", inner).getOrNull())
    }

    @Test
    fun anEmptyReturnNeitherCompletesACallNorReachesTheTimeout() {
        val timers = FakeTimers()
        var completed: JsJsonResult? = null
        var timeouts = 0
        val r = router(timers) { timeouts++ }
        r.register("pgp_1") { completed = it }
        assertFalse(r.onBridgeMessage("pgp_1", "{}"))
        assertNull(completed)
        assertEquals(listOf("pgp_1"), r.pendingIds())
        assertEquals(0, timeouts)
    }

    @Test
    fun aWrapWithAnEmptyReturnThenAFailedPostResultIsAFailureNotTheInnerArmor() {
        val inner = "-----BEGIN PGP MESSAGE-----\ninner\n-----END PGP MESSAGE-----"
        val timers = FakeTimers()
        var outcome: Result<String>? = null
        val r = router(timers) { }
        r.register("pgp_2") { outcome = EntryWrapPolicy.outcome(it, inner) }

        assertFalse(r.onBridgeMessage("pgp_2", "{}"))
        assertNull(outcome)
        assertTrue(r.onBridgeMessage("pgp_2", """{"ok":false,"error":"wrap_no_armor"}"""))
        assertTrue(outcome!!.isFailure)
        assertEquals("wrap_no_armor", outcome!!.exceptionOrNull()?.message)
    }

    @Test
    fun raceEmptyReturnThenPostResultSucceedsOnce() {
        val timers = FakeTimers()
        var callbacks = 0
        var got: JsJsonResult? = null
        var timeouts = 0
        val r = router(timers) { timeouts++ }
        r.register("pgp_3") {
            callbacks++
            got = it
        }
        assertFalse(r.onBridgeMessage("pgp_3", "{}"))
        assertTrue(r.onBridgeMessage("pgp_3", """{"ok":true,"armor":"-----BEGIN PGP MESSAGE-----"}"""))
        // The timer was cancelled by the answer: firing it now does nothing, and a repeated answer is ignored.
        timers.fireAll()
        assertFalse(r.onBridgeMessage("pgp_3", """{"ok":false,"error":"late"}"""))
        assertEquals(1, callbacks)
        assertEquals(true, got?.ok)
        assertEquals(0, timeouts)
        assertEquals(1, timers.cancelled)
    }

    @Test
    fun raceTimeoutFiresFirstThenALateAnswerIsIgnored() {
        val timers = FakeTimers()
        var callbacks = 0
        var got: JsJsonResult? = null
        var timeouts = 0
        val r = router(timers) { timeouts++ }
        r.register("pgp_4") {
            callbacks++
            got = it
        }
        assertFalse(r.onBridgeMessage("pgp_4", "{}"))
        // The timer fires before the real answer arrives: the call fails once, with the reset hook run first.
        timers.fireAll()
        assertEquals(1, timeouts)
        assertEquals(1, callbacks)
        assertEquals("js_bridge_timeout", got?.error)
        // The late postResult must not complete the call a second time.
        assertFalse(r.onBridgeMessage("pgp_4", """{"ok":true,"armor":"-----BEGIN PGP MESSAGE-----"}"""))
        assertEquals(1, callbacks)
        assertEquals(false, got?.ok)
    }
}
