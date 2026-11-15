package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * `spec/native-open-vectors.v1.json` (spec r3t §25.41, r3x §25.46.10): the 28 cases for `nativeImportOpen`,
 * `nativeRecoveryOpen` and `nativeAccountCreateOpen`. Each case sets the three page hosts (absent, refuse or open) on the
 * real host objects, runs its steps through the shared decision [NativeOpenRules] and the real recovery host, and compares
 * the events with the vector. The channel is not a decision input: the module sends the same payload on iOS and Android.
 */
class NativeOpenVectorsTest {
    private val bytes = File(System.getenv("NATIVE_OPEN_VECTORS") ?: "../spec/native-open-vectors.v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))
    private val cases = v.getJSONArray("cases")
    private val opens = mutableMapOf<String, Int>()

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    @Before
    fun resetHosts() {
        NativeRecoveryHost.events = null
        NativeRecoveryHost.pageClosed()
        NativeImportHost.launcher = null
        NativeRecoveryHost.launcher = null
        NativeAccountCreateHost.launcher = null
        opens.clear()
    }

    @After
    fun clearHosts() = resetHosts()

    private fun caseOf(id: String): JSONObject {
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("id") == id) return c
        }
        error("no case $id")
    }

    /** A host that is absent (null), refuses, or opens. Each call is counted, so the test can see whether it ran. */
    private fun hostFor(type: String, state: String): (() -> Boolean)? {
        val answer = when (state) {
            "absent" -> return null
            "refuse" -> false
            "open" -> true
            else -> error("unknown host state $state")
        }
        return {
            opens[type] = (opens[type] ?: 0) + 1
            answer
        }
    }

    private fun install(env: JSONObject) {
        NativeImportHost.launcher = hostFor("nativeImportOpen", env.optString("importHost", "absent"))
        NativeRecoveryHost.launcher = hostFor("nativeRecoveryOpen", env.optString("recoveryHost", "absent"))
        NativeAccountCreateHost.launcher = hostFor("nativeAccountCreateOpen", env.optString("accountHost", "absent"))
    }

    /** The ack for one `open` step, from the shared decision. */
    private fun ackFor(req: JSONObject, gate: NoKeyGate.Gate?): JSONObject {
        val type = req.getString("type")
        val fields = req.keys().asSequence().map { it.toString() }.toList()
        val reqId = PgpDecryptInbound.reqIdOf(req)
        val reply = when (type) {
            "nativeImportOpen" -> NativeOpenRules.importOpen(fields, reqId, NativeOpenRules.importHost)
            "nativeRecoveryOpen" -> NativeOpenRules.recoveryOpen(fields, reqId, NativeOpenRules.recoveryHost)
            "nativeAccountCreateOpen" -> NativeOpenRules.accountCreateOpen(
                fields,
                reqId,
                req.opt("account"),
                checkNotNull(gate) { "the account create case has no keyState" },
                NativeOpenRules.accountHost,
            )
            else -> error("not a page-open command: $type")
        }
        return NativeOpenRules.ackPayload(reqId, reply)
    }

    /** The result of one recovery submission, sent by the recovery host for the open page. */
    private fun finishRecovery(step: JSONObject) {
        assertEquals(step.getString("reqId"), NativeRecoveryHost.currentReqId())
        when (val code = step.getString("code")) {
            "ok" -> NativeRecoveryHost.finish(RecoveryOutcome.ok(step.getString("eoa")))
            "backoff" -> NativeRecoveryHost.finish(RecoveryOutcome.backoff(step.getInt("cooldownSec")))
            "cancelled" -> NativeRecoveryHost.pageClosed()
            else -> error("unknown recovery result $code")
        }
    }

    /** Runs one case: installs its hosts, runs its steps in order, and returns every event it produced. */
    private fun run(c: JSONObject): List<JSONObject> {
        val env = c.getJSONObject("env")
        install(env)
        val gate = env.optString("keyState", "").takeIf { it.isNotEmpty() }?.let { NoKeyGate.Gate.valueOf(it) }
        val events = mutableListOf<JSONObject>()
        NativeRecoveryHost.events = { events += it }
        val steps = c.getJSONArray("steps")
        for (i in 0 until steps.length()) {
            val step = steps.getJSONObject(i)
            when (step.getString("op")) {
                "open" -> events += ackFor(step.getJSONObject("req"), gate)
                "recoveryResult" -> finishRecovery(step)
                else -> error("unknown op ${step.getString("op")}")
            }
        }
        return events
    }

    private fun assertSameEvent(id: String, want: JSONObject, got: JSONObject) {
        val wantKeys = want.keys().asSequence().map { it.toString() }.toSet()
        val gotKeys = got.keys().asSequence().map { it.toString() }.toSet()
        assertEquals("$id keys", wantKeys, gotKeys)
        for (k in wantKeys) assertEquals("$id $k", want.get(k).toString(), got.get(k).toString())
    }

    @Test
    fun vectorFileIsTheCanonicalOne() {
        // r3x (spec §25.46.10): N-20 to N-28 added to the r3t cases N-01 to N-19.
        assertEquals("8dc1afafd964e4cd8f20f16039732486f7fc58df58ce4cd08d2643e55163108e", sha256Hex(bytes))
    }

    @Test
    fun caseCountsMatchTheVector() {
        assertEquals(42, cases.length())
        assertEquals(42, v.getJSONObject("counts").getInt("cases"))
        assertEquals(23, (0 until cases.length()).count { cases.getJSONObject(it).getString("group") == "E" })
    }

    @Test
    fun everyCaseMatchesTheVector() {
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            resetHosts()
            val got = run(c)
            val want = c.getJSONArray("expect")
            assertEquals("$id event count", want.length(), got.size)
            for (k in 0 until want.length()) {
                assertSameEvent(id, want.getJSONObject(k).getJSONObject("detail").getJSONObject("event"), got[k])
            }
            c.optJSONArray("forbiddenKeys")?.let { forbidden ->
                for (e in got) {
                    for (f in 0 until forbidden.length()) {
                        assertFalse("$id carries ${forbidden.getString(f)}", e.has(forbidden.getString(f)))
                    }
                }
            }
            // The three names are never `no_key` or `not_ready`, and the gate passes them to their own handler.
            val error = got.first().optString("error", "")
            assertFalse(id, error == NoKeyGate.NO_KEY || error == NoKeyGate.NOT_READY)
            for (s in 0 until c.getJSONArray("steps").length()) {
                val step = c.getJSONArray("steps").getJSONObject(s)
                if (step.getString("op") == "open") {
                    assertEquals(id, NoKeyGate.Route.PASS, NoKeyGate.route(step.getJSONObject("req").getString("type")))
                }
            }
        }
    }

    @Test
    fun aHostIsCalledOnlyWhenTheDecisionNeedsIt() {
        val import = mapOf("nativeImportOpen" to 1)
        val recovery = mapOf("nativeRecoveryOpen" to 1)
        val account = mapOf("nativeAccountCreateOpen" to 1)
        val none = emptyMap<String, Int>()
        // Opened or refused by the host: called once. Unregistered, refused input, or G1/G2: never called.
        val expected = mapOf(
            "N-01" to import, "N-05" to import, "N-18" to import,
            "N-02" to recovery, "N-08" to recovery, "N-16" to recovery, "N-17" to recovery, "N-19" to recovery,
            "N-20" to account, "N-22" to account,
            "N-03" to none, "N-04" to none, "N-06" to none, "N-07" to none, "N-09" to none,
            "N-11" to none, "N-12" to none, "N-13" to none, "N-14" to none, "N-15" to none,
            "N-21" to none, "N-23" to none, "N-24" to none, "N-25" to none, "N-26" to none,
            "N-27" to none, "N-28" to none, "N-29" to none, "N-30" to none,
            "N-10" to (import + recovery),
        )
        assertEquals(30, expected.size)
        for ((id, want) in expected) {
            resetHosts()
            run(caseOf(id))
            assertEquals(id, want, opens.toMap())
        }
    }

    @Test
    fun theVectorStatesMatchTheHostAnswersTheTestRuns() {
        // G0 with an open page host opens it (N-20), but G1 and G2 with the same open host never reach it (N-23, N-24).
        resetHosts()
        val g1 = run(caseOf("N-23"))
        assertEquals("not_available", g1.single().getString("error"))
        assertEquals(0, opens["nativeAccountCreateOpen"] ?: 0)
        resetHosts()
        val g0 = run(caseOf("N-20"))
        assertEquals(true, g0.single().getBoolean("ok"))
        assertEquals(1, opens["nativeAccountCreateOpen"])
    }
}
