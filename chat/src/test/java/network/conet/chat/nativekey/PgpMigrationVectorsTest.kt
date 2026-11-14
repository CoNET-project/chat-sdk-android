package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import network.conet.chat.nativekey.PgpMigrationKeys.OTHER
import network.conet.chat.nativekey.PgpMigrationKeys.WORKSPACE
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/**
 * The SDK side of the PGP migration vectors (spec r3av §25.52C.8; earlier §25.52A.8, §25.52.17; T-251 to T-255, T-267, T-269).
 *
 * The state cases run through the bridge decision ([PgpMigrationBridge.ackFor]) and the pipeline ([PgpMigrationEngine.run]). Each
 * case starts from a fresh store and each step from a fresh engine, so every step is a restart. The unregister cases run
 * [PgpMigrationEngine.unregister]. Not run here: the 6 PWA event cases (T-256, the page's), the 8 page-record cases (PR-01 to
 * PR-08, T-262 to T-264) and the 7 source-selection cases (SR-01 to SR-07, T-265), which need the native readers still pending
 * (r3aw) and are not part of this change.
 *
 * The vectors name fingerprints by label (`A`, `B`). `A` is the no-passphrase key of `pgp-native-vectors.v1.json`, `B` is a
 * second generated key. Only codes, labels and presence flags are compared; no key material leaves the test.
 */
class PgpMigrationVectorsTest {
    private val bytes = File(
        System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json",
    ).readBytes()
    private val doc = JSONObject(String(bytes, Charsets.UTF_8))
    private val cases: JSONArray = doc.getJSONArray("cases")
    private val unregisterCases: JSONArray = doc.getJSONArray("unregisterCases")

    @Test
    fun theVectorFileIsThePinnedOne() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals(PINNED_SHA256, sha)
    }

    @Test
    fun theCountsAreThoseOfTheSpec() {
        // r3av: 36 state cases (42 steps), 6 PWA event cases, 8 page-record cases, 7 source cases, 6 unregister cases (7 steps).
        assertEquals(36, cases.length())
        assertEquals(42, (0 until cases.length()).sumOf { cases.getJSONObject(it).getJSONArray("steps").length() })
        assertEquals(6, doc.getJSONArray("pwaEventCases").length())
        assertEquals(8, doc.getJSONArray("pageRecordCases").length())
        assertEquals(7, doc.getJSONArray("sourceCases").length())
        assertEquals(6, unregisterCases.length())
        assertEquals(7, (0 until unregisterCases.length()).sumOf { unregisterCases.getJSONObject(it).getJSONArray("steps").length() })
    }

    @Test
    fun everyStateCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            failures += runCase(c).map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun everyUnregisterCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        for (i in 0 until unregisterCases.length()) {
            val c = unregisterCases.getJSONObject(i)
            failures += runUnregisterCase(c).map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }

    private fun runCase(c: JSONObject): List<String> {
        val given = c.getJSONObject("given")
        val gateName = given.getString("gate")
        val running = given.getBoolean("busy")
        val legacyJson = given.optJSONObject("L")
        val legacy = legacyJson?.let { legacyRecordOf(it) }
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        seed(given, wrap, files)

        // The chain reports the account's registered key: the legacy public key when there is one, else the staged key.
        val chainLabel = legacyJson?.getString("pubFp") ?: given.optJSONObject("N")?.getString("fp") ?: "A"

        val failures = mutableListOf<String>()
        val steps = c.getJSONArray("steps")
        for (i in 0 until steps.length()) {
            failures += runStep(steps.getJSONObject(i), gateName, running, legacy, wrap, files, chainLabel, c.getString("id"))
        }
        return failures
    }

    private fun seed(given: JSONObject, wrap: NativeTestWrap, files: NativeTestFiles) {
        given.optJSONObject("N")?.let { n ->
            val k = PgpMigrationKeys.byLabel(n.getString("fp"))
            SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE).write(StagedItem(ACCOUNT, k.fp, k.priv))
        }
        given.optJSONObject("M")?.let { m ->
            val k = PgpMigrationKeys.byLabel(m.getString("fp"))
            SealedMarkerStore(wrap, files, ACCOUNT, WORKSPACE).write(MarkerItem(k.fp, "legacyPwa", 1L))
        }
    }

    private fun runStep(
        step: JSONObject,
        gateName: String,
        running: Boolean,
        legacy: LegacyRecord?,
        wrap: NativeTestWrap,
        files: NativeTestFiles,
        chainLabel: String,
        caseId: String,
    ): List<String> {
        val out = mutableListOf<String>()
        val request = JSONObject(step.getJSONObject("req").toString())
        val f = step.getJSONObject("faults")
        val faults = MigrationFaults(
            writeN = f.optBoolean("writeN"),
            rereadN = f.optBoolean("rereadN"),
            challenge = f.optBoolean("challenge"),
            writeM = f.optBoolean("writeM"),
            chainMode = f.optString("chain").ifEmpty { null },
            approved = f.optBoolean("x19Approved", true),
            interrupt = f.optString("interrupt").ifEmpty { null },
        )

        val gate = when (gateName) {
            "G0" -> NoKeyGate.Gate.G0
            "G1" -> NoKeyGate.Gate.G1
            else -> NoKeyGate.Gate.G2
        }
        val locked = gateName == "G2locked"

        var ackWire: String
        var fields: List<String> = emptyList()
        var result: MigrationResult? = null
        var interrupted = false
        when (val ack = PgpMigrationBridge.ackFor(request, gate, locked, running)) {
            is PgpMigrationBridge.Ack.Refused -> {
                ackWire = ack.code
                fields = ack.fields
            }
            is PgpMigrationBridge.Ack.Busy -> ackWire = "busy"
            is PgpMigrationBridge.Ack.Accepted -> {
                ackWire = "ok"
                val engine = migrationEngine(files, wrap, legacy, chainAnswer(faults.chainMode, chainLabel), faults)
                try {
                    result = engine.run(checkpointFor(faults))
                } catch (_: PgpMigrationInterrupted) {
                    interrupted = true
                }
            }
        }

        val expect = step.getJSONObject("expect")
        val wantAck = expect.getString("ack")
        if (ackWire != wantAck) out += "ack $ackWire != $wantAck"
        if (expect.has("fields")) {
            val want = expect.getJSONArray("fields").toList().sorted()
            if (fields != want) out += "fields $fields != $want"
        }

        val wantEvent = expect.opt("event") as? String
        val gotEvent = result?.code?.wire
        if (gotEvent != wantEvent) out += "event $gotEvent != $wantEvent"
        val wantFp = expect.opt("fp") as? String
        val gotFp = PgpMigrationKeys.labelOf(result?.fp)
        if (gotFp != wantFp) out += "fp $gotFp != $wantFp"
        if (interrupted != expect.getBoolean("interrupted")) out += "interrupted $interrupted"

        out += stateMismatches(expect.getJSONObject("state"), legacy != null, wrap, files)
        if (out.isNotEmpty()) out.add(0, "step ${request.getString("reqId")} of $caseId")
        return out
    }

    private fun runUnregisterCase(c: JSONObject): List<String> {
        val given = c.getJSONObject("given")
        val legacy = given.optJSONObject("L")?.let { legacyRecordOf(it) }
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        seed(given, wrap, files)

        val failures = mutableListOf<String>()
        val steps = c.getJSONArray("steps")
        for (i in 0 until steps.length()) {
            val step = steps.getJSONObject(i)
            val f = step.getJSONObject("faults")
            val faults = MigrationFaults(interrupt = f.optString("interrupt").ifEmpty { null })
            val recovery = FixedRecovery(p = f.optBoolean("pReadable"), chain = f.optBoolean("chainRegistered"))
            val engine = migrationEngine(files, wrap, legacy, ChainAnswer.Unavailable, faults, recovery)
            var result: MigrationResult? = null
            var interrupted = false
            try {
                result = engine.unregister(checkpointFor(faults))
            } catch (_: PgpMigrationInterrupted) {
                interrupted = true
            }
            val expect = step.getJSONObject("expect")
            val stepFailures = mutableListOf<String>()
            val wantCode = expect.opt("code") as? String
            val gotCode = result?.code?.wire
            if (gotCode != wantCode) stepFailures += "code $gotCode != $wantCode"
            if (interrupted != expect.getBoolean("interrupted")) stepFailures += "interrupted $interrupted"
            stepFailures += stateMismatches(expect.getJSONObject("state"), legacy != null, wrap, files)
            if (stepFailures.isNotEmpty()) failures += "step ${i + 1}: " + stepFailures.joinToString("; ")
        }
        return failures
    }

    private fun stateMismatches(state: JSONObject, hasLegacy: Boolean, wrap: NativeTestWrap, files: NativeTestFiles): List<String> {
        val out = mutableListOf<String>()
        if (hasLegacy != state.getBoolean("L")) out += "L presence $hasLegacy != ${state.getBoolean("L")}"
        val gotN = storedLabel(wrap, files, staged = true)
        val wantN = state.opt("N") as? String
        if (gotN != wantN) out += "N $gotN != $wantN"
        val gotM = storedLabel(wrap, files, staged = false)
        val wantM = state.opt("M") as? String
        if (gotM != wantM) out += "M $gotM != $wantM"
        return out
    }

    private fun legacyRecordOf(l: JSONObject): LegacyRecord {
        val account = if (l.getString("eoa") == "ok") ACCOUNT else OTHER
        val priv = when (l.getString("armor")) {
            "ok" -> PgpMigrationKeys.byLabel(l.getString("fp")).priv
            "bad" -> "not a pgp key"
            "encrypted" -> PgpMigrationKeys.encrypted
            else -> throw IllegalArgumentException("unknown armor case")
        }
        return LegacyRecord(account, priv, PgpMigrationKeys.byLabel(l.getString("pubFp")).pub)
    }

    private fun chainAnswer(mode: String?, label: String): ChainAnswer = when (mode) {
        "unavailable" -> ChainAnswer.Unavailable
        "unregistered" -> ChainAnswer.Absent
        "mismatch" -> ChainAnswer.Found((if (label == "A") PgpMigrationKeys.b else PgpMigrationKeys.a).fp)
        else -> ChainAnswer.Found(PgpMigrationKeys.byLabel(label).fp)
    }

    /** The label of the stored N or M, read with the production store, or `unreadable`. */
    private fun storedLabel(wrap: NativeTestWrap, files: NativeTestFiles, staged: Boolean): String? {
        val fp = try {
            if (staged) SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE).read()?.fp
            else SealedMarkerStore(wrap, files, ACCOUNT, WORKSPACE).read()?.fp
        } catch (_: IOException) {
            return "unreadable"
        }
        return PgpMigrationKeys.labelOf(fp)
    }

    private fun JSONArray.toList(): List<String> = (0 until length()).map { getString(it) }

    companion object {
        /** sha256 of `spec/pgp-migration-vectors.v1.json` as published with r3av (§25.52C.8). */
        const val PINNED_SHA256 = "6b99d868cc4f8f87590acc9001a68d2d5d11762d41f0b7ca557d3d7e0867fe8c"
    }
}
