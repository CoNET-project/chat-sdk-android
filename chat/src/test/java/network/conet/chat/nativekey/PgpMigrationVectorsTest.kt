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
 * The SDK side of the PGP migration vectors (spec r3ay §25.52D.14, §25.52E.8; earlier §25.52C.8, §25.52A.8; T-251 to T-255,
 * T-267, T-269, T-276, T-277, T-279).
 *
 * Run here: the 36 state cases (42 steps) through the bridge decision ([PgpMigrationBridge.ackFor]) and the pipeline
 * ([PgpMigrationEngine.run]); the 6 unregister cases (7 steps) through [PgpMigrationEngine.unregister]; the 6 migration-state cases
 * (SS-01 to SS-06) through [PgpMigrationEngine.state]; and the 5 source-selection cases whose inputs the SDK receives (SR-01,
 * SR-02, SR-03, SR-06, SR-07). Each case starts from a fresh store and each step from a fresh engine, so every step is a restart.
 *
 * Not run here, by design: the 6 PWA event cases (P-01 to P-06, the page's), the 13 page-bridge cases (TR), the 6 page-read cases
 * (RD), the 2 page-write cases (WR) and the 3 page-refusal cases (PW), which belong to the shell's page store; and SR-04 and SR-05,
 * whose inputs (account match and the measured layout of P) are decided by the shell before it calls the SDK.
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
    private val migrationStateCases: JSONArray = doc.getJSONArray("migrationStateCases")
    private val sourceCases: JSONArray = doc.getJSONArray("sourceCases")

    @Test
    fun theVectorFileIsThePinnedOne() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals(PINNED_SHA256, sha)
    }

    @Test
    fun theCountsAreThoseOfTheSpec() {
        // r3bb: 36 state cases (42 steps), 6 PWA event cases, 14 shell-record cases, 7 read, 2 write, 3 refusal, 6 wallet merge,
        // 7 source, 6 unregister cases (7 steps), 6 migration-state cases. The shell-record and merge groups run in ShellRecordVectorsTest.
        assertEquals(36, cases.length())
        assertEquals(42, (0 until cases.length()).sumOf { cases.getJSONObject(it).getJSONArray("steps").length() })
        assertEquals(6, doc.getJSONArray("pwaEventCases").length())
        assertEquals(47, doc.getJSONArray("shellRecordCases").length())  // r3cj: TR-47 added
        assertEquals(12, doc.getJSONArray("pageReadCases").length())
        assertEquals(2, doc.getJSONArray("pageWriteCases").length())
        assertEquals(5, doc.getJSONArray("pageRefuseCases").length())
        assertEquals(13, doc.getJSONArray("walletMergeCases").length())
        assertEquals(7, sourceCases.length())
        // r3bg (§25.52I.10): 8 unregister cases (9 steps), 7 migration-state cases, and 8 import cases (in ShellRecordVectorsTest).
        assertEquals(12, unregisterCases.length())
        assertEquals(13, (0 until unregisterCases.length()).sumOf { unregisterCases.getJSONObject(it).getJSONArray("steps").length() })
        assertEquals(7, migrationStateCases.length())
        assertEquals(11, doc.getJSONArray("importCases").length())  // r3cj: IM-10 added
        // r3bz (§25.52AD.7): GX-01 to GX-10b (11 cases). r3by (§25.52AC.8): DL-01 to DL-09 (9 cases) and DL-10a, DL-10b (2 cases).
        assertEquals(11, doc.getJSONArray("gateExceptionCases").length())
        assertEquals(9, doc.getJSONArray("nativeDeleteCases").length())
        // Y.100: DL-10a and DL-10b are back in pageRecordDeleteCases; the upgrade-retry cases PR-01..08 are in pgpUpgradeRetryCases.
        assertEquals(2, doc.getJSONArray("pageRecordDeleteCases").length())
        // r3cf (25.52AH): the self-check has 259 steps (it had 254 before the r3cf vectors).
        assertEquals(440, doc.getJSONObject("selfCheck").getInt("runs"))
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

    @Test
    fun everyMigrationStateCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        for (i in 0 until migrationStateCases.length()) {
            val c = migrationStateCases.getJSONObject(i)
            val got = runMigrationState(c)
            val want = c.getString("expect")
            if (got != want) failures += "${c.getString("id")}: state $got != $want"
        }
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun theSourceCasesTheSdkReceivesMatchTheirExpectation() {
        val failures = mutableListOf<String>()
        val ran = mutableListOf<String>()
        val skipped = mutableListOf<String>()
        for (i in 0 until sourceCases.length()) {
            val c = sourceCases.getJSONObject(i)
            val id = c.getString("id")
            val p = c.getJSONObject("input").optJSONObject("P")
            // SR-04 (account match) and SR-05 (measured layout) are decided by the shell before the SDK is called.
            val shellSide = p != null && (p.optString("layout") != "measured" || !p.optBoolean("matched", false))
            if (shellSide) {
                skipped += id
                continue
            }
            ran += id
            failures += runSourceCase(c).map { "$id: $it" }
        }
        assertEquals("the SDK-side source cases", listOf("SR-01", "SR-02", "SR-03", "SR-06", "SR-07"), ran)
        assertEquals("shell-side source cases", listOf("SR-04", "SR-05"), skipped)
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

    /** The page copy of the vector's `W` (UG-09 to UG-12): the EOA private key and the mnemonic phrase of the account. */
    private fun seedWallet(wrap: NativeTestWrap, files: NativeTestFiles) {
        SealedPageRecordStore(wrap, files, "$ACCOUNT:default").write(
            JSONObject()
                .put("rev", 1)
                .put("schemaVersion", 2)
                .put("mnemonicPhrase", "M")
                .put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("privateKeyArmor", "EOA"))),
        )
    }

    private fun seed(given: JSONObject, wrap: NativeTestWrap, files: NativeTestFiles) {
        if (given.optBoolean("W")) seedWallet(wrap, files)
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
            // UG-07: an invalid account is refused before anything is read. UG-08: another operation holds the account.
            val eoa = if (f.optBoolean("invalidEoa")) "0xnot-an-address" else ACCOUNT
            val engine = migrationEngine(
                files, wrap, legacy, ChainAnswer.Unavailable, faults, recovery,
                eoa = eoa, busy = f.optBoolean("busy"),
                wallet = PageWalletRemoval(SealedPageRecordStore(wrap, files, "$ACCOUNT:default")),
            )
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
            expect.getJSONObject("state").opt("W")?.let { want ->
                val hasWallet = SealedPageRecordStore(wrap, files, "$ACCOUNT:default").read()?.let { ShellRecordPolicy.walletIn(it).isNotEmpty() } ?: false
                if (hasWallet != want) stepFailures += "W $hasWallet != $want"
            }
            if (stepFailures.isNotEmpty()) failures += "step ${i + 1}: " + stepFailures.joinToString("; ")
        }
        return failures
    }

    /** SS-01 to SS-06: the stored N, M and last code, and the state the engine derives from them. */
    private fun runMigrationState(c: JSONObject): String {
        val st = c.getJSONObject("st")
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        st.optJSONObject("N")?.let { n ->
            val k = PgpMigrationKeys.byLabel(n.getString("fp"))
            SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE).write(StagedItem(ACCOUNT, k.fp, k.priv))
        }
        st.optJSONObject("M")?.let { m ->
            val k = PgpMigrationKeys.byLabel(m.getString("fp"))
            SealedMarkerStore(wrap, files, ACCOUNT, WORKSPACE).write(MarkerItem(k.fp, "legacyPwa", 1L))
        }
        if (!st.isNull("lastCode")) FileLastCodeStore(files, ACCOUNT, WORKSPACE).write(st.getString("lastCode"))
        // SS-07: L is present with its own fingerprint, which verified must agree with (§25.52I.6).
        val legacy = st.optJSONObject("L")?.let { l ->
            val k = PgpMigrationKeys.byLabel(l.getString("fp"))
            legacyRecord(ACCOUNT, k.priv, k.pub)
        }
        return migrationEngine(files, wrap, legacy, ChainAnswer.Unavailable).state()
    }

    /**
     * SR-01 to SR-07 as the SDK receives them. P, when present, is the page store's record and carries a trailing newline, so the
     * stored bytes show whether P or L was used. Both keys are synthetic (`A` and `B`).
     */
    private fun runSourceCase(c: JSONObject): List<String> {
        val input = c.getJSONObject("input")
        val expect = c.getJSONObject("expect")
        val pJson = input.optJSONObject("P")
        val lJson = input.optJSONObject("L")
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()

        val primary = pJson?.let { p ->
            val k = PgpMigrationKeys.byLabel(p.getString("fp"))
            legacyRecord(ACCOUNT, k.priv + "\n", k.pub)
        }
        val legacy = lJson?.let { l ->
            val k = PgpMigrationKeys.byLabel(l.getString("fp"))
            legacyRecord(ACCOUNT, k.priv, k.pub)
        }
        val chainLabel = pJson?.getString("fp") ?: lJson?.getString("fp") ?: "A"

        val out = mutableListOf<String>()
        val engine = migrationEngine(files, wrap, legacy, ChainAnswer.Found(PgpMigrationKeys.byLabel(chainLabel).fp), primary = primary)
        val result = engine.run()
        val stored = SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE).read()

        val wantCode = expect.opt("code") as? String
        if (wantCode != null) {
            if (result.code.wire != wantCode) out += "code ${result.code.wire} != $wantCode"
            if (stored != null) out += "N was written for a refused source"
        } else {
            if (result.code != MigrationCode.OK) out += "code ${result.code.wire} != ok"
        }
        when (expect.opt("use") as? String) {
            "P" -> if (stored?.privateArmor != primary?.privateText()) out += "N does not hold the page source P"
            "L" -> if (stored?.privateArmor != legacy?.privateText()) out += "N does not hold the legacy record L"
        }
        return out
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
        return legacyRecord(account, priv, PgpMigrationKeys.byLabel(l.getString("pubFp")).pub)
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
        /** sha256 of `spec/pgp-migration-vectors.v1.json`, re-pinned by the interface seat in r2.5.12 (AK-60): b4f62c4a…c1c439 (v2 b5ae750a…d31cd). */
        const val PINNED_SHA256 = "b4f62c4adb40eea4d1bcff40e2d389f39f1201e46d5ba023bb4c8911a268d313"
    }
}
