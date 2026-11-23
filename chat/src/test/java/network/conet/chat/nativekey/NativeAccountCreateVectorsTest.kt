package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * SDK side of the native account-create result events (spec r3ap §25.50.3, §25.50.5; T-249). Runs the group A cases NC-01 to
 * NC-16 of `native-account-create-vectors.v1.json`, through the same entry points the shell uses: [NativeAccountCreateHost.open],
 * [NativeAccountCreateHost.report] and [NativeAccountCreateHost.pageClosed].
 *
 * Group B (NC-17 to NC-25) is the PWA's and is not run here (T-250). `keyAfter` describes the device, not the SDK's forwarding,
 * so it is not checked here; T-239 and the device evidence cover the key itself.
 */
class NativeAccountCreateVectorsTest {
    private val bytes = File(
        System.getenv("NATIVE_ACCOUNT_CREATE_VECTORS") ?: "../spec/native-account-create-vectors.v1.json",
    ).readBytes()
    private val cases: JSONArray = JSONObject(String(bytes, Charsets.UTF_8)).getJSONArray("cases")
    private val forwarded = mutableListOf<JSONObject>()

    @Before
    fun setUp() {
        forwarded.clear()
        NativeAccountCreateHost.launcher = { true }
        NativeAccountCreateHost.events = { forwarded.add(it) }
    }

    @After
    fun tearDown() {
        NativeAccountCreateHost.events = null
        NativeAccountCreateHost.pageClosed()
        NativeAccountCreateHost.launcher = null
    }

    @Test
    fun theVectorFileIsThePinnedOne() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals(PINNED_SHA256, sha)
    }

    @Test
    fun groupAHasSixteenCasesAndEachMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        var count = 0
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("group") != "A") continue
            count++
            failures += run(c).map { "${c.getString("id")}: $it" }
        }
        assertEquals(16, count)
        assertEquals(emptyList<String>(), failures)
    }

    /** Runs one case and returns the mismatches. Empty when the case matches its expectation. */
    private fun run(c: JSONObject): List<String> {
        forwarded.clear()
        val drops = mutableListOf<NativeAccountCreateHost.Drop>()
        val steps = c.getJSONObject("input").getJSONArray("steps")
        for (i in 0 until steps.length()) {
            val s = steps.getJSONObject(i)
            when (s.getString("op")) {
                "open" -> assertTrue("open refused", NativeAccountCreateHost.open(s.getString("reqId")))
                "native" -> NativeAccountCreateHost.report(JSONObject(s.getJSONObject("ev").toString()))?.let { drops += it }
                "close" -> NativeAccountCreateHost.pageClosed()
                else -> throw IllegalStateException("unknown op ${s.getString("op")}")
            }
        }
        val expect = c.getJSONObject("expect")
        val out = mutableListOf<String>()

        val wantForwarded = expect.getJSONArray("forwarded")
        if (wantForwarded.length() != forwarded.size) {
            out += "forwarded count ${forwarded.size}, want ${wantForwarded.length()}"
        } else {
            for (i in 0 until wantForwarded.length()) {
                if (!sameObject(forwarded[i], wantForwarded.getJSONObject(i))) {
                    out += "forwarded[$i] ${forwarded[i]} != ${wantForwarded.getJSONObject(i)}"
                }
            }
        }

        val wantDropped = expect.getJSONArray("dropped")
        if (wantDropped.length() != drops.size) {
            out += "dropped count ${drops.size}, want ${wantDropped.length()}"
        } else {
            for (i in 0 until wantDropped.length()) {
                val w = wantDropped.getJSONObject(i)
                if (w.getString("reason") != drops[i].reason) out += "dropped[$i] reason ${drops[i].reason}, want ${w.getString("reason")}"
                if (w.has("fields") && w.getJSONArray("fields").toList().sorted() != drops[i].fields) {
                    out += "dropped[$i] fields ${drops[i].fields}, want ${w.getJSONArray("fields")}"
                }
            }
        }

        val wantOpen = expect.getBoolean("pageOpenAfter")
        if (wantOpen != NativeAccountCreateHost.isPageOpen()) out += "pageOpenAfter ${NativeAccountCreateHost.isPageOpen()}, want $wantOpen"
        return out
    }

    private fun JSONArray.toList(): List<String> = (0 until length()).map { getString(it) }

    private fun sameObject(a: JSONObject, b: JSONObject): Boolean {
        val ka = a.keys().asSequence().map { it.toString() }.toSet()
        val kb = b.keys().asSequence().map { it.toString() }.toSet()
        return ka == kb && ka.all { a.get(it).toString() == b.get(it).toString() }
    }

    companion object {
        /** sha256 of `spec/native-account-create-vectors.v1.json` as published with r3ap (§25.50.5). */
        const val PINNED_SHA256 = "d6fbdce3c71f50a2d71718a008942f0b6358a0cd21488dc03e7c515c238f8dea"
    }
}
