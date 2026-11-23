package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * Data-driven runner: the cases are read from the vector files (not from the test names).
 *  - SO-25d, SO-25e, SO-25f (E2 附加 .1): spec-59e-synthetic-vectors.v3.3.1-E2-addendum.1.json (sha256 09ff42c8…)
 *  - SO-26 (E5.1): spec-59e-synthetic-vectors.v3.3.1-E5.1-add.json (sha256 76941a58…)
 *  - PE-01, NE-01, NE-02, NE-04, NE-05, NE-06, NE-07, NE-08 (E6): spec-59e-synthetic-vectors.v3.3.1-E6-add.json (sha256 3bb3f572…)
 * The files are vendored under src/test/resources/spec-vectors. SPEC_VECTOR_DIR, when set, reads the same names from that folder instead. A missing file fails the test.
 */
class SpecVectorRunnerTest {
    private val oldPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val newPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val garbage = "GARBAGE_BYTES".toByteArray(Charsets.UTF_8)


    @Before fun newLaunch() {
        NativeWalletVault.resetLaunchForTests()
    }

    private fun vectorCase(file: String, id: String): JSONObject {
        // The vector files are vendored under test resources (spec-vectors/). SPEC_VECTOR_DIR, when set, reads the same names from that folder.
        val text = System.getenv("SPEC_VECTOR_DIR")?.let { File(it, file).readText(Charsets.UTF_8) }
            ?: javaClass.classLoader!!.getResourceAsStream("spec-vectors/$file")!!.bufferedReader(Charsets.UTF_8).use { it.readText() }
        val doc = JSONObject(text)
        val cases = doc.getJSONArray("cases")
        return (0 until cases.length()).map { cases.getJSONObject(it) }.first { it.getString("id") == id }
    }

    private class VaultWrap(val inner: NativeTestWrap) : KeyWrap {
        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray = inner.seal(aad, plain)
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = inner.open(aad, sealed)
        override fun deleteKey(): Boolean = inner.deleteKey()
    }

    private fun digest(b: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    /** The vector's pre-state (E2 附加 .1): REC holds GARBAGE, the sealed old REC is isolated, MNEM and COMMIT absent, MARK old, marker pending. */
    private fun stageFromVector(wrap: VaultWrap, files: NativeTestFiles): ByteArray {
        val key = checkNotNull(MnemonicDerivation.deriveKey(oldPhrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(key))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa, key, oldPhrase))
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val oldMark = files.map[NativeWalletVault.MARK]!!.copyOf()
        val isoRec = "${NativeWalletVault.REC}.isolated.20261117T000000Z.aaaaaaaa"
        val isoMark = "${NativeWalletVault.MARK}.isolated.20261117T000000Z.bbbbbbbb"
        files.map.remove(NativeWalletVault.MNEM)
        files.map.remove(NativeWalletVault.COMMIT)
        files.map.remove(NativeWalletVault.INTENT)
        files.map[isoRec] = oldRec
        files.map[NativeWalletVault.REC] = garbage
        files.map[isoMark] = oldMark
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-17T00:00:00Z").put("eoa", eoa)
            .put("preWriteAliasAbsent", false).put("newRecordSha", JSONObject.NULL)
            .put("items", org.json.JSONArray()
                .put(JSONObject().put("name", NativeWalletVault.REC).put("isolated", isoRec).put("oldSha", digest(oldRec)))
                .put(JSONObject().put("name", NativeWalletVault.MARK).put("isolated", isoMark).put("oldSha", digest(oldMark))))
            .toString().toByteArray(Charsets.UTF_8)
        return oldRec
    }

    /** The isolated names whose bytes are [bytes]. */
    private fun isolatedHolding(files: NativeTestFiles, bytes: ByteArray): List<String> =
        files.map.filter { (n, b) -> n.contains(".isolated.") && b.contentEquals(bytes) }.keys.toList()

    /** The audit rows that name [isolated] (one row per isolated copy is expected). */
    private fun auditRowsFor(files: NativeTestFiles, isolated: String): Int =
        files.map[NativeWalletVault.AUDIT]?.let { String(it, Charsets.UTF_8).lines().count { l -> l.contains("\"isolated\":\"$isolated\"") } } ?: 0

    /** SO-25d (E2 附加 A1): the garbage is kept under an isolated name, the old REC is restored, two isolated copies with the expected digests. */
    @Test fun so25d_fromVector() {
        val c = vectorCase("spec-59e-synthetic-vectors.v3.3.1-E2-addendum.1.json", "SO-25d")
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        val oldRec = stageFromVector(wrap, files)
        val before = files.map.filterKeys { it != NativeWalletVault.PENDING && it != NativeWalletVault.AUDIT }.mapValues { digest(it.value) }
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        val exp = c.getJSONObject("expect")
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        val pattern = exp.getJSONObject("files").getJSONObject("isolated_pattern")
        val isolated = files.map.keys.filter { it.contains(".isolated.") }
        assertEquals(pattern.getInt("count"), isolatedHolding(files, oldRec).size + isolatedHolding(files, garbage).size)
        assertTrue(isolated.any { files.map[it]!!.contentEquals(garbage) })
        // deleted: []  (every earlier byte string is still present, under a fixed or isolated name)
        before.forEach { (name, sha) -> assertTrue("$name kept", files.map.values.any { digest(it) == sha }) }
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
        assertEquals("ok", NativeWalletVault(wrap, files).readStateLabel())
        val audit = String(files.map.getValue(NativeWalletVault.AUDIT), Charsets.UTF_8)
        assertTrue(audit.contains("restored_from_sealed_copy"))
        assertTrue(audit.contains("preserved_before_restore") || audit.contains("partial_new_isolated"))
    }

    /** SO-25e (E2 附加 A2): the rename of the garbage fails: nothing is overwritten or deleted, no audit row, rollback_pending, one automatic resume per launch. */
    @Test fun so25e_fromVector() {
        val c = vectorCase("spec-59e-synthetic-vectors.v3.3.1-E2-addendum.1.json", "SO-25e")
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        stageFromVector(wrap, files)
        files.failRename = { it == NativeWalletVault.REC }
        val before = files.map.mapValues { it.value.copyOf() }
        val auditBefore = files.map[NativeWalletVault.AUDIT]?.size ?: 0
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        val exp = c.getJSONObject("expect")
        assertArrayEquals(garbage, files.map[NativeWalletVault.REC])
        assertEquals("the garbage is still the only copy under the fixed name", 1, files.map.values.count { it.contentEquals(garbage) })
        before.forEach { (name, bytes) -> assertTrue("$name kept", bytes.contentEquals(files.map[name])) }
        assertEquals("no audit row for the failed rename", auditBefore, files.map[NativeWalletVault.AUDIT]?.size ?: 0)
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
        // The vault's actual state: the marker is pending, so the state is locked as rollback_pending (not ok, not no_key), and it reads as unknown.
        val state = NativeWalletVault(wrap, files).state()
        assertTrue("rollback_pending expected, was $state", state is NativeWalletVault.State.Locked && state.reason == "rollback_pending")
        assertEquals("unknown", NativeWalletVault(wrap, files).readStateLabel())
        assertEquals(exp.getString("state_after"), "rollback_pending")
        // a second resume in the same launch is not run automatically (one per launch): nothing changes
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        before.forEach { (name, bytes) -> assertTrue("$name kept after the second call", bytes.contentEquals(files.map[name])) }
    }

    /**
     * SO-25f (E2 附加 .1 A3, 项目技术裁定 2026-11-17): the rename succeeds, the audit row cannot be written. The first launch does not roll the
     * rename back. The next launch backfills exactly one row for that copy (matched by its isolated name, idempotent) and then completes SO-25d.
     */
    @Test fun so25f_fromVector() {
        val c = vectorCase("spec-59e-synthetic-vectors.v3.3.1-E2-addendum.1.json", "SO-25f")
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        val oldRec = stageFromVector(wrap, files)
        files.failWrite = NativeWalletVault.AUDIT
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        val first = c.getJSONObject("expect").getJSONObject("after_first_launch")
        assertFalse(first.getJSONObject("files").let { files.map.containsKey(NativeWalletVault.REC) })
        val garbageIso = isolatedHolding(files, garbage)
        assertEquals("the renamed garbage is kept (not rolled back)", 1, garbageIso.size)
        assertEquals("no row yet for the renamed copy", 0, auditRowsFor(files, garbageIso.single()))
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
        // Next launch: the fault cleared; the missing row is backfilled once, then the resume runs.
        files.failWrite = null
        NativeWalletVault.resetLaunchForTests()
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        assertEquals("exactly one audit row for the renamed copy", 1, auditRowsFor(files, garbageIso.single()))
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
        assertEquals("ok", NativeWalletVault(wrap, files).readStateLabel())
    }

    /** SO-25f, the backfill fails again: everything is kept, rollback_pending; the user's retry then completes (retryPendingByUser). */
    @Test fun so25f_backfillFailureKeepsEverythingUntilTheUserRetries() {
        val c = vectorCase("spec-59e-synthetic-vectors.v3.3.1-E2-addendum.1.json", "SO-25f")
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        val oldRec = stageFromVector(wrap, files)
        files.failWrite = NativeWalletVault.AUDIT
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        NativeWalletVault.resetLaunchForTests()
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        val garbageIso = isolatedHolding(files, garbage)
        assertEquals(1, garbageIso.size)
        assertEquals(0, auditRowsFor(files, garbageIso.single()))
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
        val retry = c.getJSONObject("expect").getJSONObject("if_backfill_fails")
        assertEquals("retryPendingByUser", retry.getString("retry_by_user"))
        files.failWrite = null
        assertTrue(NativeWalletVault(wrap, files).retryPendingByUser())
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        assertEquals(1, auditRowsFor(files, garbageIso.single()))
    }

    /** SO-26 (E5.1): PHRASE_ONLY + pwaWalletSync. Each operation of the vector is run; the answers and the no-change facts are the vector's. */
    @Test fun so26_fromVector() {
        val c = vectorCase("spec-59e-synthetic-vectors.v3.3.1-E5.1-add.json", "SO-26")
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val residue = oldPhrase
        val resKey = checkNotNull(MnemonicDerivation.deriveKey(residue))
        NativeWalletVault(wrap, files).importMnemonicKey(checkNotNull(WalletAddress.fromPrivateKey(resKey)), resKey, residue)
        files.map.remove(NativeWalletVault.REC)
        val v = NativeWalletVault(wrap, files)
        val before = files.map.mapValues { it.value.copyOf() }
        val ops = c.getJSONArray("op")
        val answers = c.getJSONObject("expect").getJSONArray("answers")
        repeat(2) {
            for (i in 0 until ops.length()) {
                val op = ops.getJSONObject(i)
                // op 0: the same account (residue phrase); op 1: a different account.
                val (phrase, key) = if (i == 0) residue to resKey else newPhrase to checkNotNull(MnemonicDerivation.deriveKey(newPhrase))
                val outcome = v.syncPhrase(checkNotNull(WalletAddress.fromPrivateKey(key)), key, phrase)
                val want = answers.getJSONObject(i)
                assertEquals("op $i error", want.getString("error"), NativeSyncAck.codeOf(outcome))
                assertFalse("op $i is not ok", want.getBoolean("ok"))
                assertEquals("op $i reason", want.getString("reason"), NativeSyncAck.answerOf(outcome).reason)
            }
        }
        before.forEach { (name, bytes) -> assertTrue("$name unchanged", bytes.contentEquals(files.map[name])) }
        assertEquals(before.keys, files.map.keys)
        assertFalse(files.map.containsKey(NativeWalletVault.INTENT))
        assertFalse(files.map.containsKey(NativeWalletVault.AUDIT))
        assertEquals("valid", v.nativeStateLabel())
        assertTrue(c.getJSONObject("expect").getBoolean("retryable"))
    }

    // ---- E6: nativeMnemonicPreread restricted return (spec-59e-synthetic-vectors.v3.3.1-E6-add.json, sha256 3bb3f572…) ----

    private val e6Phrase = "SYNTHETIC-TEST-PHRASE-NOT-A-WALLET"
    private val e6Eoa = "0xaaaa000000000000000000000000000000000001"

    /** Runs one E6 operation through the SDK's preread reply. Returns the reply, the log lines it produces, and whether the vault was read. */
    private data class E6Run(val payload: JSONObject, val logs: List<String>, val read: Boolean)

    private fun runE6(c: JSONObject): E6Run {
        val pre = c.getJSONObject("pre")
        val op = c.getJSONObject("op")
        MnemonicPreread.resetForTests()
        assertTrue(MnemonicPreread.accept(0L))
        var read = false
        val answer: () -> MnemonicPreread.Answer = {
            read = true
            when (pre.getString("native_state")) {
                "valid" -> MnemonicPreread.Answer.Valid(e6Eoa, e6Phrase)
                else -> MnemonicPreread.Answer.Unknown // unknown and unreadable both answer unknown (NE-01, NE-02)
            }
        }
        val body = JSONObject().put("type", "nativeMnemonicPreread").put("reqId", op.getInt("reqId"))
        if (op.has("trustedOrigin")) body.put("trustedOrigin", op.getBoolean("trustedOrigin"))
        body.put("seq", op.getInt("seq"))
        if (op.has("extra_field")) body.put(op.getString("extra_field"), "SYNTHETIC-KEY-FIELD")
        val payload = NativeSyncAck.prereadPayload(op.getInt("reqId"), body, answer)
        // The module logs only the ok flag of this reply, and the refusal code when one is given.
        val logs = listOf(NativeSyncAck.prereadLogLine(payload.getBoolean("ok")))
        return E6Run(payload, logs, read)
    }

    private fun assertE6(id: String) {
        val c = vectorCase("spec-59e-synthetic-vectors.v3.3.1-E6-add.json", id)
        val run = runE6(c)
        val exp = c.getJSONObject("expect")
        assertEquals("$id ok", exp.getBoolean("ok"), run.payload.getBoolean("ok"))
        if (exp.has("error")) assertEquals("$id error", exp.getString("error"), run.payload.getString("error"))
        if (exp.has("read_performed")) assertEquals("$id read", exp.getBoolean("read_performed"), run.read)
        if (exp.has("result")) {
            val want = exp.getJSONObject("result")
            val got = run.payload.getJSONObject("result")
            //  (2.2): the state of the old shape is compared as the code shape (valid → ok with mnemonic, absent → confirmed_missing,
            // unknown → read_error). The eoa is not compared (the reply carries none).
            val wantCode = when (want.getString("state")) {
                "valid" -> "ok"
                "absent" -> "confirmed_missing"
                else -> "read_error"
            }
            assertEquals("$id code", wantCode, got.getString("code"))
            if (wantCode == "ok") assertEquals("$id mnemonic", e6Phrase, got.getString("mnemonic"))
            else assertFalse("$id carries no mnemonic", got.has("mnemonic"))
        }
        if (exp.has("has_phrase_field") && !exp.getBoolean("has_phrase_field")) {
            val result = run.payload.optJSONObject("result")
            assertFalse("$id has no mnemonic field", result?.has("mnemonic") == true)
        }
        if (exp.has("log_contains_phrase") && !exp.getBoolean("log_contains_phrase")) {
            assertFalse("$id log holds no phrase", run.logs.any { it.contains(e6Phrase) })
        }
    }

    @Test fun e6_PE01_validInTheTrustedTopFrameReturnsThePhrase() = assertE6("PE-01")

    @Test fun e6_NE01_unknownReturnsNoPhrase() = assertE6("NE-01")

    @Test fun e6_NE02_unreadableReturnsNoPhrase() = assertE6("NE-02")

    @Test fun e6_NE04_childFrameIsUntrustedAndNotRead() = assertE6("NE-04")

    @Test fun e6_NE05_untrustedOriginIsUntrustedAndNotRead() = assertE6("NE-05")

    @Test fun e6_NE06_aPhraseFieldInTheRequestIsRefusedAndNotRead() = assertE6("NE-06")

    /** NE-07: the log lines of the runs PE-01, NE-01, NE-02, NE-04, NE-05 carry no phrase and only the state (ok flag or refusal code). */
    @Test fun e6_NE07_logsCarryNoPhraseAndOnlyTheState() {
        val c = vectorCase("spec-59e-synthetic-vectors.v3.3.1-E6-add.json", "NE-07")
        val runs = c.getJSONObject("pre").getJSONArray("runs")
        for (i in 0 until runs.length()) {
            val id = runs.getString(i)
            val run = runE6(vectorCase("spec-59e-synthetic-vectors.v3.3.1-E6-add.json", id))
            run.logs.forEach { line ->
                assertFalse("$id log holds no phrase", line.contains(e6Phrase))
                assertTrue("$id log is a state line: $line", Regex("^nativeMnemonicPreread ok=(true|false)$").matches(line))
            }
        }
        assertEquals(false, c.getJSONObject("expect").getBoolean("mnemonic_substring_found"))
    }

    /**
     * NE-08: telemetry and crash reports. The module emits no telemetry on this path; on the JVM the only carrier of the phrase is the reply
     * event itself. The check is that the phrase appears in no log line of any run and that the run's error text carries no phrase. Upload is
     * a device-side check (not reachable here).
     */
    @Test fun e6_NE08_telemetryAndErrorTextCarryNoPhrase() {
        val c = vectorCase("spec-59e-synthetic-vectors.v3.3.1-E6-add.json", "NE-08")
        val runs = c.getJSONObject("pre").getJSONArray("runs")
        for (i in 0 until runs.length()) {
            val run = runE6(vectorCase("spec-59e-synthetic-vectors.v3.3.1-E6-add.json", runs.getString(i)))
            assertFalse(run.payload.optString("error", "").contains(e6Phrase))
        }
        assertEquals(false, c.getJSONObject("expect").getBoolean("uploaded"))
    }
}
