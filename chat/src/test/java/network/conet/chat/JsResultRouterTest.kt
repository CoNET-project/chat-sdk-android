package network.conet.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host WebView call routing on the JVM (no WebView). A call completes only from its `postResult` message or from its
 * timeout. The `evaluateJavascript` return value is not an input to the router at all. Synthetic messages only.
 */
class JsResultRouterTest {
    /** Stands in for the main-thread Handler: tasks run only when the test fires them. */
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

        /** Runs every task still scheduled, as if its delay had passed. */
        fun fireAll() {
            val now = tasks.values.toList()
            tasks.clear()
            now.forEach { it() }
        }
    }

    private fun router(timers: FakeTimers, onTimeout: (String) -> Unit = {}) =
        JsResultRouter(timeoutMs = 25_000L, schedule = timers::schedule, onTimeout = onTimeout)

    @Test
    fun emptyObjectReturnDoesNotCompleteACall() {
        val timers = FakeTimers()
        val r = router(timers)
        var got: JsJsonResult? = null
        r.register("pgp_1") { got = it }
        assertFalse(r.onBridgeMessage("pgp_1", "{}"))
        assertNull(got)
        assertEquals(listOf("pgp_1"), r.pendingIds())
        assertEquals(0, timers.cancelled)
    }

    @Test
    fun postResultCompletesTheCallAndCancelsItsTimer() {
        val timers = FakeTimers()
        val r = router(timers)
        var got: JsJsonResult? = null
        r.register("pgp_2") { got = it }
        assertTrue(r.onBridgeMessage("pgp_2", """{"ok":true,"armor":"-----BEGIN PGP MESSAGE-----"}"""))
        assertTrue(got!!.ok)
        assertEquals("-----BEGIN PGP MESSAGE-----", got!!.armor)
        assertEquals(1, timers.cancelled)
        assertEquals(0, timers.pendingCount)
        assertTrue(r.pendingIds().isEmpty())
    }

    @Test
    fun errorOnlyObjectCompletesAsFailureWithItsError() {
        val r = router(FakeTimers())
        var got: JsJsonResult? = null
        r.register("pgp_3") { got = it }
        assertTrue(r.onBridgeMessage("pgp_3", """{"error":"encrypt_produced_no_armor"}"""))
        assertFalse(got!!.ok)
        assertEquals("encrypt_produced_no_armor", got!!.error)
    }

    @Test
    fun messagesThatAreNotAnswersAreIgnoredAndTheCallKeepsWaiting() {
        val r = router(FakeTimers())
        r.register("pgp_4") { error("a non-answer must not complete the call") }
        val notAnswers = listOf("", "null", "[]", "\"text\"", "ERROR:boom", "-----BEGIN PGP MESSAGE-----", """{"value":1}""", "{not json")
        for (m in notAnswers) {
            assertFalse("message=${m.take(12)}", r.onBridgeMessage("pgp_4", m))
        }
        assertEquals(listOf("pgp_4"), r.pendingIds())
    }

    @Test
    fun timeoutRunsTheResetHookFirstThenCompletesWithJsBridgeTimeout() {
        val timers = FakeTimers()
        val order = mutableListOf<String>()
        val r = router(timers) { id -> order.add("hook:$id") }
        var got: JsJsonResult? = null
        r.register("pgp_5") {
            got = it
            order.add("callback")
        }
        timers.fireAll()
        assertEquals(listOf("hook:pgp_5", "callback"), order)
        assertFalse(got!!.ok)
        assertEquals("js_bridge_timeout", got!!.error)
        assertTrue(r.pendingIds().isEmpty())
    }

    @Test
    fun aLateAnswerAfterTheTimeoutIsIgnored() {
        val timers = FakeTimers()
        var calls = 0
        val r = router(timers)
        r.register("pgp_6") { calls++ }
        timers.fireAll()
        assertFalse(r.onBridgeMessage("pgp_6", """{"ok":true,"armor":"x"}"""))
        assertEquals(1, calls)
    }

    @Test
    fun aSecondAnswerForTheSameCallIsIgnored() {
        val r = router(FakeTimers())
        var calls = 0
        r.register("pgp_7") { calls++ }
        assertTrue(r.onBridgeMessage("pgp_7", """{"ok":true,"armor":"first"}"""))
        assertFalse(r.onBridgeMessage("pgp_7", """{"ok":true,"armor":"second"}"""))
        assertEquals(1, calls)
    }

    @Test
    fun aHostResetFailsEveryWaitingCall() {
        val r = router(FakeTimers())
        val seen = mutableListOf<String>()
        r.register("a") { seen.add(it.error) }
        r.register("b") { seen.add(it.error) }
        for (id in r.pendingIds()) r.complete(id, JsJsonResult(ok = false, error = "host_reset"))
        assertEquals(listOf("host_reset", "host_reset"), seen)
        assertTrue(r.pendingIds().isEmpty())
    }

    @Test
    fun parseBridgeResultReadsEveryField() {
        val p = parseBridgeResult("""{"ok":true,"armor":"A","text":"T","armorHash":"H","error":"","value":"V"}""")
        assertEquals(JsJsonResult(ok = true, armor = "A", text = "T", armorHash = "H", error = "", value = "V"), p)
    }
}
