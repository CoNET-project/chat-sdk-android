package network.conet.chat.nativekey

import network.conet.chat.nativekey.NativeWalletVault.Import
import network.conet.chat.nativekey.NativeWalletVault.State
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 25.52Y.122, 25.52Y.123, 25.52Y.124, 25.52Y.125, 25.52Y.127, 25.52Y.128 (r3rz; Y.130 for WK-33 to WK-38; Y.139 for WK-39 to WK-46, which carry
 * Y.138 第 6、7 項). Vectors: `spec/wrap-key-loss-vectors.v1.json` (49 cases), pinned by sha256 f9b9102d… (Y.144: WK-49 added; WK-14 decided by the current probe). One test per case; each reads the case's
 * `input` and `expect` and checks the SDK-side fields.
 *
 * The SDK checks the native half: the state, the gate answer, `hasKey`, the write answer, the seal decision, the files, the audit. The PWA half
 * (IndexedDB, page, retry timing) and the iOS half (SE and Keychain probes) are not executed here; for those the vector's own classification rule is
 * checked, and the rest is listed in the 0.2.24 receipt.
 */
class WrapKeyLossVectorsTest {
    private val path = "../spec/wrap-key-loss-vectors.v1.json"
    private val doc: JSONObject by lazy { JSONObject(File(path).readText(Charsets.UTF_8)) }

    private fun case(id: String): JSONObject {
        val arr = doc.getJSONArray("cases")
        for (i in 0 until arr.length()) if (arr.getJSONObject(i).getString("id") == id) return arr.getJSONObject(i)
        fail("no vector $id")
        throw IllegalStateException()
    }

    @Test
    fun theVectorFileIsThePinnedCopyWithFortyNineCases() {
        val sha = MessageDigest.getInstance("SHA-256").digest(File(path).readBytes()).joinToString("") { "%02x".format(it) }
        assertEquals("f9b9102d008f993768112e34d4ae560abff3fe63c1b0bcdea3584d0120f28a1f", sha)
        val ids = (0 until doc.getJSONArray("cases").length()).map { doc.getJSONArray("cases").getJSONObject(it).getString("id") }
        assertEquals((1..49).map { "WK-%02d".format(it) }, ids)
    }

    /** The vector's own classification rule (its `classificationRule`), applied to a probe. Used for the iOS-only and PWA-only cases. */
    private fun ruleClassification(probe: JSONObject): String {
        val platform = probe.getString("platform")
        return if (platform == "android") {
            val confirmed = probe.getString("enumeration") == "ok" && !probe.isNull("aliasPresent") && probe.getBoolean("aliasPresent").not()
            if (confirmed) "confirmed_missing" else "unknown"
        } else {
            val confirmed = probe.getString("enumeration") == "ok" && probe.getString("iosSeQuery") == "ok" &&
                probe.getString("iosOtherQuery") == "ok" && probe.getString("iosSeError") == "errSecItemNotFound"
            if (confirmed) "confirmed_missing" else "unknown"
        }
    }

    private fun retrySecondsFor(attempt: Int): Int = doc.getJSONArray("retrySeconds").getInt(attempt)

    /**
     * Wrap whose presence and open result each case sets. Sealing goes through [resolveSealKey] (the device's seal decision, 25.52Y.124), with the same
     * sealed-record rule for the directory ([recordsExist]). `keyGone` is the alias removed: open fails and presence reads absent.
     */
    private class ProbeWrap : KeyWrap {
        var secret: SecretKey = newSecret()
        var presenceValue = WrapKeyPresence.PRESENT
        var openFails = false
        var keyGone = false
        var recordsExist: () -> Boolean = { false }

        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray {
            val key = resolveSealKey(
                presence = { presenceValue },
                sealedRecordsExist = recordsExist,
                existing = { if (keyGone) null else secret },
                create = {
                    secret = newSecret()
                    keyGone = false
                    presenceValue = WrapKeyPresence.PRESENT
                    secret
                },
            )
            val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            c.updateAAD(aad)
            return iv + c.doFinal(plain)
        }

        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? {
            if (openFails || keyGone) return null
            return try {
                val c = Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
                c.updateAAD(aad)
                c.doFinal(sealed.copyOfRange(12, sealed.size))
            } catch (_: java.security.GeneralSecurityException) {
                null
            }
        }

        override fun deleteKey(): Boolean {
            keyGone = true
            presenceValue = WrapKeyPresence.CONFIRMED_ABSENT
            return true
        }

        override fun presence(): WrapKeyPresence = presenceValue
    }

    /** Files whose read of [name] throws (a read failure is unknown, never absent). */
    private class ReadFails(private val inner: NativeTestFiles, private val name: String) : VaultFiles {
        override fun read(name: String): ByteArray? {
            if (name == this.name) throw IOException("read failed")
            return inner.read(name)
        }
        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)
        override fun delete(name: String) = inner.delete(name)
    }

    private val eoa = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    private val key = ByteArray(32).also { it[31] = 1 }

    /** A vault with one complete account written by the vault's own import. */
    private fun imported(): Triple<NativeTestFiles, ProbeWrap, NativeWalletVault> {
        val files = NativeTestFiles()
        val wrap = ProbeWrap()
        wrap.recordsExist = { files.map.keys.any { isSealedRecordName(it) } }
        val v = NativeWalletVault(wrap, files)
        assertEquals(Import.OK, v.importKey(eoa, key))
        return Triple(files, wrap, v)
    }

    /** The vector's hasKey (25.52Y.137 第 5 項): a boolean is asserted; null (the record cannot be decided) is not. */
    private fun assertHasKeyPerVector(id: String, s: State) {
        val e = case(id).getJSONObject("expect")
        if (!e.has("hasKey") || e.isNull("hasKey")) return
        assertEquals("$id hasKey", e.getBoolean("hasKey"), hasKeyOf(s))
    }

    private fun gateStatus(s: State): String = NoKeyGate.walletStatusFor(NoKeyGate.gateOf(s, false), s).getString("status")
    private fun gateReason(s: State): String? = NoKeyGate.walletStatusFor(NoKeyGate.gateOf(s, false), s).optString("notReadyReason", null)

    /** The native half of a no-key answer (25.52Y.122 第 2 項): the gate is G0, the answer is no_key, and no key is held. */
    private fun assertConfirmedNoKey(s: State) {
        assertTrue("expected no_key, got $s", s is State.NoKey)
        assertEquals("no_key", gateStatus(s))
        assertFalse("hasKey is false", s is State.Ready)
    }

    /** The native half of an unknown answer (25.52Y.122 第 1 項): not_ready with reason unreadable, never no_key. */
    private fun assertUnknown(s: State) {
        assertTrue("expected unknown, got $s", s is State.Locked)
        assertEquals("not_ready", gateStatus(s))
        assertEquals("unreadable", gateReason(s))
    }

    private fun runWrap(id: String) {
        val c = case(id)
        val expect = c.getJSONObject("expect")
        val probe = c.getJSONObject("input").optJSONObject("probe")
        if (probe != null && probe.getString("platform") == "ios") {
            assertEquals(id, expect.getString("classification"), ruleClassification(probe))
        }
        if (probe != null && probe.getString("platform") == "android") {
            if (expect.has("classification")) assertEquals(id, expect.getString("classification"), ruleClassification(probe))
        }
    }

    // ---- Y.122: wrap key loss, the classification rule and the native answer ----

    /** WK-01: the alias is confirmed absent (enumeration ok), no phrase: no_key. */
    @Test fun wk01_confirmedAbsentAliasWithNoPhraseIsNoKey() {
        runWrap("WK-01")
        val (files, wrap, _) = imported()
        wrap.presenceValue = WrapKeyPresence.CONFIRMED_ABSENT
        wrap.keyGone = true
        val s = NativeWalletVault(wrap, files).state()
        assertConfirmedNoKey(s)
        assertHasKeyPerVector("WK-01", s)
        assertTrue("the records are kept (25.52Y.122 第 3 項)", files.map.containsKey(NativeWalletVault.REC))
    }

    /** WK-02: the same loss with a phrase the page holds: the native half is still no_key (the page restores the account). */
    @Test fun wk02_confirmedAbsentAliasWithAPageHeldPhraseIsStillNoKeyNatively() {
        runWrap("WK-02")
        val (files, wrap, _) = imported()
        wrap.presenceValue = WrapKeyPresence.CONFIRMED_ABSENT
        wrap.keyGone = true
        val s2 = NativeWalletVault(wrap, files).state()
        assertConfirmedNoKey(s2)
        assertHasKeyPerVector("WK-02", s2)
    }

    /** WK-03: aead_failed with the alias present is unknown; the retry is 30 seconds and the write is blocked. */
    @Test fun wk03_aeadFailureIsUnknownWithRetryThirtySecondsAndWriteBlocked() {
        runWrap("WK-03")
        val (files, wrap, _) = imported()
        wrap.openFails = true
        val v = NativeWalletVault(wrap, files)
        val s3 = v.state()
        assertUnknown(s3)
        assertHasKeyPerVector("WK-03", s3)
        assertEquals(retrySecondsFor(0), 30)
        assertEquals(Import.RECORD_EXISTS, v.importKey(eoa, key))
    }

    /** WK-04: marker_mismatch is unknown; the retry is 2 minutes on the second attempt. */
    @Test fun wk04_markerMismatchIsUnknownWithRetryTwoMinutes() {
        runWrap("WK-04")
        val (files, wrap, _) = imported()
        files.map[NativeWalletVault.MARK] = "not-the-digest".toByteArray()
        val s = NativeWalletVault(wrap, files).state()
        assertTrue("marker mismatch", s is State.Locked && s.reason == "marker_mismatch")
        assertUnknown(s)
        assertHasKeyPerVector("WK-04", s)
        assertEquals(120, retrySecondsFor(1))
    }

    /** WK-05: keystore enumeration fails: unknown, never absent; the third retry (600 s) is the manual step. */
    @Test fun wk05_keystoreUnavailableIsUnknownAndNeverAbsent() {
        runWrap("WK-05")
        val (files, wrap, _) = imported()
        wrap.presenceValue = WrapKeyPresence.UNKNOWN
        wrap.openFails = true
        assertUnknown(NativeWalletVault(wrap, files).state())
        assertEquals(600, retrySecondsFor(2))
    }

    /** WK-08: an existing record that still opens blocks the write even when the alias reads as absent. */
    @Test fun wk08_aRecordThatOpensBlocksTheWriteEvenWhenTheAliasReadsAbsent() {
        runWrap("WK-08")
        val (files, wrap, v) = imported()
        wrap.presenceValue = WrapKeyPresence.CONFIRMED_ABSENT
        val before = files.map.mapValues { it.value.copyOf() }
        assertFalse("the write is blocked", v.importKey(eoa, key) == Import.OK)
        assertEquals("nothing is written", before.keys, files.map.keys)
        before.forEach { (name, bytes) -> assertArrayEquals(name, bytes, files.map[name]) }
    }

    /** WK-09 (iOS, SE and Keychain queries ok, item not found): confirmed by the vector's rule. The Android SDK does not run the iOS probe. */
    @Test fun wk09_iosItemNotFoundWithBothQueriesOkIsNoKeyByTheRule() {
        runWrap("WK-09")
        // The iOS probe is not run here; the Android value for a confirmed absence (no key record) is checked against the vector.
        assertHasKeyPerVector("WK-09", State.NoKey)
    }

    @Test fun wk10_iosOtherQueryFailureIsUnknownByTheRule() = runWrap("WK-10")

    @Test fun wk11_iosSeQueryFailureIsUnknownByTheRule() = runWrap("WK-11")

    /** WK-14: a confirmed loss followed, in the same session, by aead_failed is unknown. */
    /** WK-14 (Y.144): confirmed loss, then aead_failed. The last probe decides: unknown. No session latch. */
    @Test fun wk14_aConfirmedLossThenAnUnreadableReadIsUnknownInTheSession() {
        runWrap("WK-14")
        val (files, wrap, _) = imported()
        val v = NativeWalletVault(wrap, files)
        wrap.presenceValue = WrapKeyPresence.CONFIRMED_ABSENT
        wrap.keyGone = true
        assertConfirmedNoKey(v.state())
        wrap.keyGone = false
        wrap.openFails = true
        wrap.presenceValue = WrapKeyPresence.PRESENT
        v.invalidateSnapshot()
        assertUnknown(v.state())
    }

    // ---- Y.124: the seal fails closed when the alias is gone and sealed records remain ----

    /** WK-15: the alias is confirmed absent and a sealed record exists: no key is created, wrap_key_missing. */
    @Test fun wk15_sealWithAbsentAliasAndSealedRecordFailsClosed() {
        runWrap("WK-15")
        var created = 0
        val thrown = runCatching {
            resolveSealKey(presence = { WrapKeyPresence.CONFIRMED_ABSENT }, sealedRecordsExist = { true }, existing = { null }, create = { created++; ByteArray(32) })
        }.exceptionOrNull()
        assertTrue("wrap_key_missing", thrown is WrapKeyMissingException)
        assertEquals("wrap_key_missing", thrown!!.message)
        assertEquals("no key is created", 0, created)
    }

    /** WK-16: no sealed record and the alias absent: the first use creates the key. */
    @Test fun wk16_firstUseWithNoSealedRecordCreatesTheKey() {
        runWrap("WK-16")
        var created = 0
        resolveSealKey(presence = { WrapKeyPresence.CONFIRMED_ABSENT }, sealedRecordsExist = { false }, existing = { null }, create = { created++; ByteArray(32) })
        assertEquals(1, created)
    }

    /** WK-17: the enumeration fails: no key is generated and the result is unknown. */
    @Test fun wk17_enumerationFailureCreatesNoKeyAndIsUnknown() {
        runWrap("WK-17")
        var created = 0
        val thrown = runCatching {
            resolveSealKey(presence = { throw IOException("keystore unavailable") }, sealedRecordsExist = { true }, existing = { null }, create = { created++; ByteArray(32) })
        }.exceptionOrNull()
        assertTrue(thrown is IOException)
        assertEquals("no key is created", 0, created)
    }

    // ---- Y.125: reads never delete; the write path settles ----

    private fun withIntent(files: NativeTestFiles, wrap: ProbeWrap, v: NativeWalletVault, created: List<String>) {
        files.map[NativeWalletVault.INTENT] = v.encodeIntent(eoa, mnemonicPlanned = false, created = created)
        wrap.presenceValue = WrapKeyPresence.PRESENT
    }

    /** WK-18: a read with an intent manifest and residue deletes nothing and changes no byte. */
    @Test fun wk18_aReadNeverDeletesOrChangesAFile() {
        runWrap("WK-18")
        val (files, wrap, v) = imported()
        files.map.remove(NativeWalletVault.COMMIT)
        withIntent(files, wrap, v, listOf(NativeWalletVault.MARK, NativeWalletVault.REC, NativeWalletVault.COMMIT))
        val before = files.map.mapValues { it.value.copyOf() }
        assertUnknown(NativeWalletVault(wrap, files).state())
        assertEquals(before.keys, files.map.keys)
        before.forEach { (name, bytes) -> assertArrayEquals(name, bytes, files.map[name]) }
    }

    /** WK-19: the write path removes the manifest files that belong to the intent's account, after an audit line for each. */
    @Test fun wk19_theWritePathRemovesAttributedManifestFilesWithAnAuditLine() {
        runWrap("WK-19")
        val (files, wrap, v) = imported()
        files.map.remove(NativeWalletVault.COMMIT)
        withIntent(files, wrap, v, listOf(NativeWalletVault.MARK, NativeWalletVault.REC, NativeWalletVault.COMMIT))
        val w = NativeWalletVault(wrap, files)
        assertEquals(Import.OK, w.importKey(eoa, key))
        assertEquals(0, w.retainedUnattributed)
        val audit = String(files.map[NativeWalletVault.AUDIT]!!, Charsets.UTF_8)
        assertTrue(audit.contains("pending_import_rollback"))
        assertTrue(audit.contains(NativeWalletVault.REC))
    }

    /** WK-20: a file the manifest does not prove is kept and counted; nothing is removed and no exception is thrown. */
    @Test fun wk20_anUnattributedFileIsKeptAndCountedWithoutAnError() {
        runWrap("WK-20")
        val files = NativeTestFiles()
        val wrap = ProbeWrap()
        val otherKey = ByteArray(32).also { it[31] = 2 }
        val other = WalletAddress.fromPrivateKey(otherKey)!!
        assertEquals(Import.OK, NativeWalletVault(wrap, files).importKey(other, otherKey))
        files.map.remove(NativeWalletVault.COMMIT)
        files.map.remove(NativeWalletVault.MARK)
        val v = NativeWalletVault(wrap, files)
        files.map[NativeWalletVault.INTENT] = v.encodeIntent(eoa, mnemonicPlanned = false, created = listOf(NativeWalletVault.REC))
        val rec = files.map[NativeWalletVault.REC]!!.copyOf()
        val w = NativeWalletVault(wrap, files)
        w.importKey(eoa, key)
        assertArrayEquals("the file is kept", rec, files.map[NativeWalletVault.REC])
        assertEquals(1, w.retainedUnattributed)
    }

    // ---- Y.127: the residue shape, and every shape outside it ----

    /**
     * A fully imported account with COMMIT removed: the Y.127 residue shape (REC and MARK, no COMMIT, INTENT or MNEM). With [rotate] the alias
     * is still present but holds another key, so the record does not open (a conflict that is unreadable, 25.52Y.122 第 3 項).
     */
    private fun residueShape(rotate: Boolean = false): Triple<NativeTestFiles, ProbeWrap, NativeWalletVault> {
        val (files, wrap, _) = imported()
        files.map.remove(NativeWalletVault.COMMIT)
        if (rotate) wrap.secret = newSecret()
        return Triple(files, wrap, NativeWalletVault(wrap, files))
    }

    /** WK-21: REC and MARK present, COMMIT, INTENT and MNEM absent, reads and keystore normal: no_key; the new slot is written (not blocked). */
    @Test fun wk21_theResidueShapeIsNoKeyAndTheNewSlotIsWritten() {
        runWrap("WK-21")
        val (files, _, v) = residueShape(rotate = true)
        val s = v.state()
        assertConfirmedNoKey(s)
        assertHasKeyPerVector("WK-21", s)
        assertEquals(Import.OK, v.importKey(eoa, key))
        assertTrue("the old record is kept under an isolated name", files.map.keys.any { it.startsWith(NativeWalletVault.REC + ".isolated.") })
    }

    /** WK-22: the residue shape with a phrase the page holds: the native half is no_key. */
    @Test fun wk22_theResidueShapeWithAPageHeldPhraseIsNoKeyNatively() {
        runWrap("WK-22")
        val (_, _, v) = residueShape()
        assertConfirmedNoKey(v.state())
    }

    /** WK-23: the residue shape; the page's IndexedDB is unreadable (page side). The native half is no_key. */
    @Test fun wk23_theResidueShapeIsNoKeyNativelyWhateverThePageStore() {
        runWrap("WK-23")
        val (_, _, v) = residueShape()
        assertConfirmedNoKey(v.state())
    }

    /** WK-24: a COMMIT present makes the shape unknown. The record does not open here, so the vault cannot answer no_key. */
    @Test fun wk24_aCommitRecordMakesTheShapeUnknown() {
        runWrap("WK-24")
        val (files, wrap, _) = imported()
        wrap.openFails = true
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-25: an intent present makes the shape unknown. */
    @Test fun wk25_anIntentMakesTheShapeUnknown() {
        runWrap("WK-25")
        val (files, wrap, _) = residueShape()
        files.map[NativeWalletVault.INTENT] = "{}".toByteArray()
        assertUnknown(NativeWalletVault(wrap, files).state())
        assertNotNull(files.map[NativeWalletVault.INTENT])
    }

    /**
     * WK-26 (rewritten by the -59E-classification-single-judgement-WK26-2026-11-17): a readable phrase record at the fixed position
     * with its COMMIT moved away is a ready account, and it agrees with the pre-read (source order). The former expectation (unknown, never no_key)
     * is superseded for this shape only; 25.52Y.127/136/143(1) are superseded when the current position holds a valid phrase.
     */
    @Test fun wk26_aReadableMnemonicWithAMovedCommitIsAReadyAccountAgreeingWithThePreread() {
        runWrap("WK-26")
        val phrase = NativeAccountCreate.phraseOf(ByteArray(16) { 7 })
        val k = MnemonicDerivation.deriveKey(phrase)!!
        val a = WalletAddress.fromPrivateKey(k)!!
        val files = NativeTestFiles()
        val wrap = ProbeWrap()
        assertEquals(Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(a, k, phrase))
        files.map.remove(NativeWalletVault.COMMIT)
        val st = NativeWalletVault(wrap, files).state()
        assertTrue("ready account: $st", st is NativeWalletVault.State.Ready)
        val answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))
        assertTrue("pre-read valid: $answer", answer is MnemonicPreread.Answer.Valid)
    }

    /** WK-27: an unreadable phrase record present makes the shape unknown. */
    @Test fun wk27_anUnreadableMnemonicMakesTheShapeUnknown() {
        runWrap("WK-27")
        val (files, wrap, _) = residueShape()
        files.map[NativeWalletVault.MNEM] = """{"record":1,"eoa":"$eoa","sealed":"00"}""".toByteArray()
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-28: the keystore is unavailable: the shape is unknown, never no_key. */
    @Test fun wk28_anUnavailableKeystoreMakesTheShapeUnknown() {
        runWrap("WK-28")
        val (files, wrap, _) = residueShape()
        wrap.presenceValue = WrapKeyPresence.UNKNOWN
        wrap.openFails = true
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-29: a read that throws propagates; it is never taken for absence. */
    /**
     * WK-29. The original vector does not name the failed object and does not confirm the MNEM read result. Per E9.10.3 it is instantiated as a
     * MNEM read fault as well (fixture only; the expectation is unchanged: the failed read surfaces as an error, never a state).
     */
    @Test fun wk29_aFailedReadIsNeverNoKey() {
        runWrap("WK-29")
        val (files, wrap, _) = residueShape()
        files.failRead = { it == NativeWalletVault.REC || it == NativeWalletVault.MNEM }
        val thrown = runCatching { NativeWalletVault(wrap, files).state() }.exceptionOrNull()
        assertTrue("the failed read surfaces as an error, not as a state", thrown is IOException)
    }

    /** WK-30: a missing marker with an unreadable record is unknown (the legacy exception needs a readable record, Y.92 第 2 項). */
    @Test fun wk30_aMissingMarkerIsUnknown() {
        runWrap("WK-30")
        val (files, wrap, _) = imported()
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
        wrap.openFails = true
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-31: a missing record with a marker is unknown, never no_key. */
    /**
     * WK-31. The original vector does not confirm the MNEM read result. Per E9.10.3 it is instantiated as a MNEM read fault (fixture only;
     * the expectation is unchanged: unknown, never no_key).
     */
    @Test fun wk31_aMissingRecordWithAMarkerIsUnknown() {
        runWrap("WK-31")
        val (files, wrap, _) = imported()
        files.map.remove(NativeWalletVault.REC)
        files.failRead = { it == NativeWalletVault.MNEM }
        val r = runCatching { NativeWalletVault(wrap, files).state() }
        val thrown = r.exceptionOrNull()
        if (thrown != null) assertTrue("unknown (the read surfaces as an error): $thrown", thrown is IOException) else assertUnknown(r.getOrThrow())
    }

    private fun isolatedNames(files: NativeTestFiles, base: String): List<String> = files.map.keys.filter { it.startsWith(base + ".isolated.") }

    private fun auditLines(files: NativeTestFiles): List<JSONObject> {
        val raw = files.map[NativeWalletVault.AUDIT] ?: return emptyList()
        return String(raw, Charsets.UTF_8).lines().filter { it.isNotBlank() }.map { JSONObject(it) }
    }

    /** A confirmed loss with an unopenable record and the wrap alias absent: the Y.122 shape. */
    private fun lostRecord(): Triple<NativeTestFiles, ProbeWrap, NativeWalletVault> {
        val (files, wrap, _) = imported()
        val rec = files.map[NativeWalletVault.REC]!!.copyOf()
        wrap.presenceValue = WrapKeyPresence.CONFIRMED_ABSENT
        wrap.keyGone = true
        assertTrue("the old record is kept", rec.contentEquals(files.map[NativeWalletVault.REC]))
        return Triple(files, wrap, NativeWalletVault(wrap, files))
    }

    /** WK-06: a new account after a confirmed loss: the old bytes stay under the isolated name, and the new record is written to the fixed name. */
    @Test fun wk06_theNewAccountIsWrittenAfterTheOldBytesAreIsolated() {
        runWrap("WK-06")
        val (files, _, v) = lostRecord()
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        assertConfirmedNoKey(v.state())
        assertEquals(Import.OK, v.importKey(eoa, key))
        val iso = isolatedNames(files, NativeWalletVault.REC).single()
        assertArrayEquals("the old bytes are unchanged", oldRec, files.map[iso])
        assertFalse("the new record is distinct", oldRec.contentEquals(files.map[NativeWalletVault.REC]))
        assertFalse("the pending marker is gone", files.map.containsKey(NativeWalletVault.PENDING))
    }

    /** WK-07: already_exists does not block when the existing record is unreadable and the loss is confirmed; the write leaves an audit line. */
    @Test fun wk07_alreadyExistsDoesNotBlockAnUnreadableRecordAndIsAudited() {
        runWrap("WK-07")
        val (files, _, v) = lostRecord()
        assertTrue("the write is not blocked", v.importKey(eoa, key) != Import.RECORD_EXISTS)
        assertTrue(auditLines(files).any { it.getString("reason") == "isolated_for_new_slot" && it.getString("name") == NativeWalletVault.REC })
    }

    /** WK-12: the isolation rename fails: nothing changes, no audit line, the state is unknown and nothing is written. */
    @Test fun wk12_aFailedIsolationChangesNothingAndStaysUnknown() {
        runWrap("WK-12")
        val (files, wrap, v) = lostRecord()
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        files.failRename = { it == NativeWalletVault.REC }
        assertEquals(Import.STORE_FAILED, v.importKey(eoa, key))
        assertArrayEquals("the old record is unchanged", oldRec, files.map[NativeWalletVault.REC])
        assertTrue("no isolated name", isolatedNames(files, NativeWalletVault.REC).isEmpty())
        // r2.5 audit order: the pending row is written before the rename; the rename failed, so no done row exists.
        assertTrue("only pending rows, no done row", auditLines(files).all { it.optString("state") == "pending" })
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-13: the new-slot write fails: the old file stays, the state is unknown, and the fixed name is restored. */
    @Test fun wk13_aFailedNewSlotWriteKeepsTheOldFileAndStaysUnknown() {
        runWrap("WK-13")
        val (files, wrap, v) = lostRecord()
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        files.failWrite = NativeWalletVault.REC
        assertEquals(Import.STORE_FAILED, v.importKey(eoa, key))
        assertArrayEquals("the old record is back under its name", oldRec, files.map[NativeWalletVault.REC])
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-32: a residue shape whose isolation fails: the old REC and MARK stay, nothing is written, the state is unknown. */
    @Test fun wk32_aFailedIsolationOfTheResidueShapeKeepsTheOldFilesAndStaysUnknown() {
        runWrap("WK-32")
        val (files, wrap, v) = residueShape(rotate = true)
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val oldMark = files.map[NativeWalletVault.MARK]!!.copyOf()
        files.failRename = { it == NativeWalletVault.REC }
        assertEquals(Import.STORE_FAILED, v.importKey(eoa, key))
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        assertArrayEquals(oldMark, files.map[NativeWalletVault.MARK])
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-33: the normal write-back: isolate, verify, audit, write, read back. The isolated bytes are the old bytes; the fixed name is the new record. */
    @Test fun wk33_theNormalWriteBackIsolatesVerifiesAuditsAndWrites() {
        runWrap("WK-33")
        val (files, wrap, _) = imported()
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        wrap.keyGone = true
        wrap.presenceValue = WrapKeyPresence.CONFIRMED_ABSENT
        val w = NativeWalletVault(wrap, files)
        assertEquals(Import.OK, w.importKey(eoa, key))
        val iso = isolatedNames(files, NativeWalletVault.REC).single()
        assertArrayEquals(oldRec, files.map[iso])
        // r2.5 audit order: one pending row, then one done row for the same copy (the done row follows the read-back).
        assertEquals(listOf("pending", "done"), auditLines(files).map { it.optString("state") })
        assertFalse(oldRec.contentEquals(files.map[NativeWalletVault.REC]))
        assertTrue(NativeWalletVault(wrap, files).state() is State.Ready)
    }

    /** WK-34: (a) the rename fails: nothing changes, no audit line, the state is unknown. (Same as WK-12 for the residue shape.) */
    @Test fun wk34_theIsolationRenameFailureIsTheFirstStepAndChangesNothing() {
        runWrap("WK-34")
        val (files, wrap, v) = residueShape(rotate = true)
        files.failRename = { it == NativeWalletVault.REC }
        assertEquals(Import.STORE_FAILED, v.importKey(eoa, key))
        assertTrue("only pending rows, no done row", auditLines(files).all { it.optString("state") == "pending" })
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-35: (d) the write fails and the fixed name is empty: the isolated file goes back under its name, the restore is audited, the state is unknown. */
    @Test fun wk35_aFailedWriteRestoresTheIsolatedFileAndAuditsTheRollback() {
        runWrap("WK-35")
        val (files, wrap, v) = lostRecord()
        // The vector's single fixed-name file: REC only, so one isolation and one restoration are audited.
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        files.failWrite = NativeWalletVault.REC
        assertEquals(Import.STORE_FAILED, v.importKey(eoa, key))
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        assertTrue("no isolated name", isolatedNames(files, NativeWalletVault.REC).isEmpty())
        // r2.5 audit order: the isolation adds a pending and a done row (2), then the rollback rows as before (E9 keep: the intent's rollback is audited).
        assertEquals(4, auditLines(files).size)
        assertTrue(auditLines(files).last().getString("reason") == "restored_after_failed_write")
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-36: the rollback fails too: both files are kept, the fixed name is empty, nothing is written, the state is unknown. */
    @Test fun wk36_aFailedRollbackKeepsBothFilesAndStaysUnknown() {
        runWrap("WK-36")
        val (files, wrap, v) = lostRecord()
        files.failWrite = NativeWalletVault.REC
        files.failRename = { it.contains(".isolated.") }
        assertEquals(Import.ROLLBACK_PENDING, v.importKey(eoa, key))
        assertTrue("the fixed name is empty", !files.map.containsKey(NativeWalletVault.REC))
        assertEquals(1, isolatedNames(files, NativeWalletVault.REC).size)
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-37: the read path after a successful write-back reads the fixed name and never opens an isolated file. */
    @Test fun wk37_theReadPathAfterAWriteReadsOnlyTheFixedName() {
        runWrap("WK-37")
        val (files, wrap, v) = lostRecord()
        assertEquals(Import.OK, v.importKey(eoa, key))
        files.reads.clear()
        val s = NativeWalletVault(wrap, files).state()
        assertTrue(s is State.Ready)
        assertTrue("no isolated file is read", files.reads.none { it.contains(".isolated.") })
    }

    /** WK-38: after a failed rollback, a read reads only the fixed name (empty), opens no isolated file, and is unknown. */
    @Test fun wk38_aReadAfterAFailedRollbackOpensNoIsolatedFile() {
        runWrap("WK-38")
        val (files, wrap, v) = lostRecord()
        files.failWrite = NativeWalletVault.REC
        files.failRename = { it.contains(".isolated.") }
        v.importKey(eoa, key)
        files.reads.clear()
        assertUnknown(NativeWalletVault(wrap, files).state())
        assertTrue("no isolated file is read", files.reads.none { it.contains(".isolated.") })
    }

    // ---- 25.52Y.136 (r3rz) ----

    /** 25.52Y.136 第 6 項: Y.127 residue with a record that opens (alias present): the write is not blocked, and the old files are isolated. */
    @Test fun wk21b_residueWithAnOpeningRecordStillWritesTheNewSlot() {
        val (files, _, v) = residueShape(rotate = false)
        assertConfirmedNoKey(v.state())
        assertEquals(Import.OK, v.importKey(eoa, key))
        assertTrue("the old record is kept under an isolated name", isolatedNames(files, NativeWalletVault.REC).isNotEmpty())
    }

    /** 25.52Y.136 第 1 項 with the 第 4 項 附注: a write that fails midway and cannot roll back is unknown; the next write rolls forward and proceeds. */
    @Test fun partialWriteIsUnknownAndTheNextWriteResolvesIt() {
        val (files, wrap, v) = lostRecord()
        files.failWrite = NativeWalletVault.COMMIT
        // The second move of REC (the kept move of the new record in the rollback) fails; the first (the isolation of the old record) succeeds.
        var recMoves = 0
        files.failRename = { if (it == NativeWalletVault.REC) { recMoves++; recMoves >= 2 } else false }
        assertEquals(Import.ROLLBACK_PENDING, v.importKey(eoa, key))
        assertTrue("the new record remains", files.map.containsKey(NativeWalletVault.REC))
        assertTrue("the pending marker remains", files.map.containsKey(NativeWalletVault.PENDING))
        assertUnknown(NativeWalletVault(wrap, files).state())
        files.failWrite = null
        files.failDelete = null
        // The new record reads under the wrap and matches the marker: the next write completes it (MARK, COMMIT) and the account is present.
        assertEquals(Import.ALREADY_PRESENT, NativeWalletVault(wrap, files).importKey(eoa, key))
        assertFalse("the marker is removed", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue(NativeWalletVault(wrap, files).state() is State.Ready)
    }

    /** 25.52Y.136 第 9 項: the record is written and read back, the marker deletion fails: ok with cleanupPending; the original name is authoritative. */
    @Test fun cleanupPendingReturnsOkAndTheMarkerStaysUntilTheNextWrite() {
        val (files, wrap, v) = lostRecord()
        files.failDelete = NativeWalletVault.PENDING
        assertEquals(Import.OK_CLEANUP_PENDING, v.importKey(eoa, key))
        assertTrue("the marker stays", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue("the original name is authoritative on a read", NativeWalletVault(wrap, files).state() is State.Ready)
        files.failDelete = null
        assertEquals(Import.ALREADY_PRESENT, NativeWalletVault(wrap, files).importKey(eoa, key))
        assertFalse("the next write removes the marker", files.map.containsKey(NativeWalletVault.PENDING))
    }

    /** 25.52Y.136 第 8 項: under a confirmed loss the other sealed records of the vault (PGP, K) are isolated too, audited, and the new account is written. */
    @Test fun wk06b_otherSealedRecordsAreIsolatedUnderAConfirmedLoss() {
        val (files, _, v) = lostRecord()
        files.map["userpgp.v1.test"] = "sealed-pgp-record".toByteArray(Charsets.UTF_8)
        assertEquals(Import.OK, v.importKey(eoa, key))
        assertEquals(1, isolatedNames(files, "userpgp.v1.test").size)
        assertTrue(auditLines(files).any { it.getString("name") == "userpgp.v1.test" && it.getString("reason") == "isolated_for_new_slot" })
    }

    /** 25.52Y.136 第 2 項: an isolated file that does not match its old hash keeps the marker, is counted, and the state stays unknown. */
    @Test fun aPendingMarkWhoseIsolatedFileDoesNotMatchIsKeptAndCounted() {
        val (files, wrap, v) = lostRecord()
        files.failWrite = NativeWalletVault.REC
        files.failRename = { it.contains(".isolated.") }
        assertEquals(Import.ROLLBACK_PENDING, v.importKey(eoa, key))
        files.failWrite = null
        files.failRename = null
        val iso = isolatedNames(files, NativeWalletVault.REC).single()
        files.map[iso] = "tampered".toByteArray(Charsets.UTF_8)
        val w = NativeWalletVault(wrap, files)
        assertUnknown(w.state())
        assertTrue(w.importKey(eoa, key) != Import.OK)
        assertTrue("the isolated file is kept", files.map.containsKey(iso))
        assertTrue("counted as retained", w.retainedUnattributed > 0)
    }

    // ---- 25.52Y.137 (r3rz) ----

    private fun pendingItemNames(files: NativeTestFiles): List<String> {
        val o = JSONObject(String(files.map[NativeWalletVault.PENDING]!!, Charsets.UTF_8))
        val arr = o.getJSONArray("items")
        return (0 until arr.length()).map { arr.getJSONObject(it).getString("name") }
    }

    /** 25.52Y.137 第 1 項 (i) and (ii): the marker is written before the first isolation, with no new-record hash and no key material. */
    @Test fun markerIsWrittenBeforeTheFirstIsolationWithoutTheNewHash() {
        val (files, wrap, v) = lostRecord()
        files.failRename = { it == NativeWalletVault.REC }
        assertEquals(Import.STORE_FAILED, v.importKey(eoa, key))
        val raw = String(files.map[NativeWalletVault.PENDING]!!, Charsets.UTF_8)
        val o = JSONObject(raw)
        assertEquals(eoa, o.getString("eoa"))
        assertTrue("the new-record hash is empty until the record is written", o.isNull("newRecordSha"))
        assertEquals(listOf(NativeWalletVault.REC, NativeWalletVault.MARK, NativeWalletVault.COMMIT), pendingItemNames(files))
        assertFalse("no key material", raw.contains("0000000000000000000000000000000000000000000000000000000000000001"))
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** 25.52Y.137 第 1 項 (iv): the new-record hash is filled after the record is written; a failure after that leaves the hash in the marker. */
    @Test fun theNewRecordHashIsFilledAfterTheRecordIsWritten() {
        val (files, wrap, v) = lostRecord()
        files.failWrite = NativeWalletVault.MARK
        assertEquals(Import.STORE_FAILED, v.importKey(eoa, key))
        val o = JSONObject(String(files.map[NativeWalletVault.PENDING]!!, Charsets.UTF_8))
        assertFalse("the hash is filled", o.isNull("newRecordSha"))
        assertEquals(64, o.getString("newRecordSha").length)
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /**
     * WK-49 (Y.144): confirmed loss, then aead_failed, then confirmed loss again. Each read is decided by its own probe (no session latch): the last
     * probe is a confirmed loss, so the answer is no_key.
     */
    @Test fun wk49_noSessionLatchTheLastConfirmedLossIsNoKey() {
        runWrap("WK-49")
        val (files, wrap, _) = imported()
        val v = NativeWalletVault(wrap, files)
        wrap.presenceValue = WrapKeyPresence.CONFIRMED_ABSENT
        wrap.keyGone = true
        assertConfirmedNoKey(v.state())
        wrap.keyGone = false
        wrap.openFails = true
        wrap.presenceValue = WrapKeyPresence.PRESENT
        v.invalidateSnapshot()
        assertUnknown(v.state())
        wrap.openFails = false
        wrap.keyGone = true
        wrap.presenceValue = WrapKeyPresence.CONFIRMED_ABSENT
        v.invalidateSnapshot()
        assertConfirmedNoKey(v.state())
        assertConfirmedNoKey(NativeWalletVault(wrap, files).state())
    }

    /**
     * 25.52Y.143 第 1 至 3 項: a failed write leaves the restored group under its marker. The marker blocks every read (unknown) in every instance until the
     * next write operation; that operation settles it (the flag is written), and the write then proceeds instead of answering RECORD_EXISTS.
     */
    @Test fun aRestoredGroupIsUnknownUntilTheNextWriteThenProceeds() {
        val (files, wrap, v) = lostRecord()
        files.failWrite = NativeWalletVault.REC
        assertEquals(Import.STORE_FAILED, v.importKey(eoa, key))
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
        assertUnknown(NativeWalletVault(wrap, files).state())
        files.failWrite = null
        assertEquals(Import.OK, NativeWalletVault(wrap, files).importKey(eoa, key))
        assertFalse("the marker of the completed write is removed", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue(NativeWalletVault(wrap, files).state() is State.Ready)
    }

    /** 25.52Y.137 第 4 項: all or nothing. The second restore fails; the first is isolated again, nothing is complete, and the marker stays. */
    @Test fun aFailedRestoreOfTheGroupUndoesTheRestoredFiles() {
        val (files, wrap, v) = lostRecord()
        files.failWrite = NativeWalletVault.REC
        // The restore runs in reverse order (COMMIT, MARK, REC): the MARK restore fails after COMMIT was restored.
        files.failRename = { it.startsWith(NativeWalletVault.MARK + ".isolated.") }
        assertEquals(Import.ROLLBACK_PENDING, v.importKey(eoa, key))
        assertFalse(files.map.containsKey(NativeWalletVault.COMMIT))
        assertFalse(files.map.containsKey(NativeWalletVault.MARK))
        assertFalse(files.map.containsKey(NativeWalletVault.REC))
        assertEquals(1, isolatedNames(files, NativeWalletVault.COMMIT).size)
        assertEquals(1, isolatedNames(files, NativeWalletVault.MARK).size)
        assertEquals(1, isolatedNames(files, NativeWalletVault.REC).size)
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** 25.52Y.137 第 2 項: attributable by the K name, the PGP recipient, or the old hash; a file that meets none is not attributable. */
    @Test fun anIsolatedFileIsAttributableByTheKRulePgpRuleOrHash() {
        val files = NativeTestFiles()
        val v = NativeWalletVault(ProbeWrap(), files)
        val other = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
        val bytes = "record".toByteArray(Charsets.UTF_8)
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertTrue("by the old hash", v.attributable("wallet.v1.rec", bytes, eoa, sha))
        assertTrue("by the K name", v.attributable("K.v1|$eoa|default", "k".toByteArray(), eoa, "00"))
        assertFalse("another account's K name", v.attributable("K.v1|$other|default", "k".toByteArray(), eoa, "00"))
        assertFalse("nothing matches", v.attributable("userpgp", "z".toByteArray(), eoa, "00"))
    }

    /**
     * 25.52Y.138 第 3 項: a PGP record is attributable only when the account's K item (`K.v1|<eoa>|default`) carries the same keyId exactly. An absent K
     * item, a K item without keyId, an unreadable K item, and a different keyId do not establish it.
     */
    @Test fun aPgpRecordIsAttributableOnlyByTheExactKeyIdOfTheKItem() {
        val files = NativeTestFiles()
        val v = NativeWalletVault(ProbeWrap(), files)
        val pgp = JSONObject().put("recipientEoa", eoa).put("userPgpKeyId", "ABCD").toString().toByteArray(Charsets.UTF_8)
        val kName = "K.v1|$eoa|default"
        assertFalse("no K item", v.attributable("userpgp", pgp, eoa, "00"))
        files.map[kName] = JSONObject().put("keyId", "abcd").toString().toByteArray(Charsets.UTF_8)
        assertFalse("the keyId must be equal exactly", v.attributable("userpgp", pgp, eoa, "00"))
        files.map[kName] = JSONObject().put("eoa", eoa).toString().toByteArray(Charsets.UTF_8)
        assertFalse("a K item without keyId", v.attributable("userpgp", pgp, eoa, "00"))
        files.map[kName] = JSONObject().put("keyId", "ABCD").toString().toByteArray(Charsets.UTF_8)
        assertTrue("the same keyId establishes it", v.attributable("userpgp", pgp, eoa, "00"))
        val otherRecipient = JSONObject().put("recipientEoa", "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa").put("userPgpKeyId", "ABCD")
            .toString().toByteArray(Charsets.UTF_8)
        assertFalse("another recipient", v.attributable("userpgp", otherRecipient, eoa, "00"))
    }

    /**
     * B2 (second review): interrupted after the isolation and before the record was written. The marker and the isolated files are on disk, the fixed
     * names are empty. The next write restores the isolated files, removes the marker, and then writes.
     */
    @Test fun anInterruptionBetweenTheIsolationAndTheRecordWriteIsRecovered() {
        val (files, wrap, _) = lostRecord()
        val names = listOf(NativeWalletVault.REC, NativeWalletVault.MARK, NativeWalletVault.COMMIT)
        val items = org.json.JSONArray()
        for (name in names) {
            val bytes = files.map[name]!!.copyOf()
            val iso = "$name.isolated.20261116T100000Z.0badc0de"
            files.map[iso] = bytes
            files.map.remove(name)
            items.put(JSONObject().put("name", name).put("isolated", iso).put("oldSha", MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }))
        }
        files.map[NativeWalletVault.PENDING] = JSONObject()
            .put("v", 1).put("utc", "2026-11-16T10:00:00Z").put("eoa", eoa).put("items", items).put("newRecordSha", JSONObject.NULL)
            .toString().toByteArray(Charsets.UTF_8)
        assertUnknown(NativeWalletVault(wrap, files).state())
        assertEquals(Import.OK, NativeWalletVault(wrap, files).importKey(eoa, key))
        assertTrue("the restored commit is audited", auditLines(files).any { it.getString("reason") == "rollback" })
        assertFalse("the marker of the interrupted write is removed", files.map.containsKey(NativeWalletVault.PENDING))
    }

    // ---- 25.52Y.138 第 6、7 項 and 25.52Y.139 (WK-39 to WK-46): the marker with no new-record hash, and the alias-absent marker ----

    /** An interrupted write-back: the fixed record moved to an isolated name holding [old], the marker with no new-record hash. */
    private fun markerWithIsolated(files: NativeTestFiles, name: String, old: ByteArray, preWriteAliasAbsent: Boolean = false) {
        val iso = "$name.isolated.20261116T100000Z.0badc0de"
        files.map[iso] = old
        files.map.remove(name)
        val items = org.json.JSONArray().put(
            JSONObject().put("name", name).put("isolated", iso)
                .put("oldSha", MessageDigest.getInstance("SHA-256").digest(old).joinToString("") { "%02x".format(it) }),
        )
        files.map[NativeWalletVault.PENDING] = JSONObject()
            .put("v", 1).put("utc", "2026-11-16T10:00:00Z").put("eoa", eoa).put("items", items).put("newRecordSha", JSONObject.NULL)
            .put("preWriteAliasAbsent", preWriteAliasAbsent).toString().toByteArray(Charsets.UTF_8)
    }

    /** WK-39 (Y.138 第 6 項 (a)): the fixed record reads under the wrap with the marker's EOA: roll forward, hash filled, audited, marker removed, isolated kept. */
    @Test fun wk39_anUnhashedMarkerWithAReadableRecordRollsForward() {
        runWrap("WK-39")
        val (files, wrap, _) = imported()
        val oldBytes = "old-record-bytes".toByteArray(Charsets.UTF_8)
        // The new record is on disk (readable, same account); MARK and COMMIT were not written; the old bytes sit in an isolated file.
        val iso = "${NativeWalletVault.REC}.isolated.20261116T100000Z.0badc0de"
        files.map[iso] = oldBytes
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-16T10:00:00Z").put("eoa", eoa)
            .put("items", org.json.JSONArray().put(JSONObject().put("name", NativeWalletVault.REC).put("isolated", iso)
                .put("oldSha", MessageDigest.getInstance("SHA-256").digest(oldBytes).joinToString("") { "%02x".format(it) })))
            .put("newRecordSha", JSONObject.NULL).toString().toByteArray(Charsets.UTF_8)
        val v = NativeWalletVault(wrap, files)
        assertEquals(Import.ALREADY_PRESENT, v.importKey(eoa, key))
        assertFalse("the marker is removed", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue("the isolated file is kept", files.map.containsKey(iso))
        assertEquals(1, auditLines(files).size)
        assertEquals("roll_forward", auditLines(files).single().getString("reason"))
        assertTrue(NativeWalletVault(wrap, files).state() is State.Ready)
    }

    /** WK-40 (Y.138 第 6 項 (b), Y.128 第 3 項): the fixed name is empty and the isolated file holds the old bytes: rolled back, audited, marker removed; unknown. */
    @Test fun wk40_anUnhashedMarkerWithAnIsolatedFileRollsBack() {
        runWrap("WK-40")
        val (files, wrap, _) = imported()
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        // The alias is present but holds another key, so the old record does not open: unknown, not a confirmed loss.
        wrap.secret = newSecret()
        markerWithIsolated(files, NativeWalletVault.REC, oldRec)
        val iso = isolatedNames(files, NativeWalletVault.REC).single()
        val v = NativeWalletVault(wrap, files)
        assertEquals(Import.RECORD_EXISTS, v.importKey(eoa, key))
        assertArrayEquals("the old bytes are back under the fixed name", oldRec, files.map[NativeWalletVault.REC])
        assertFalse("the isolated file is gone", files.map.containsKey(iso))
        assertFalse("the marker is removed", files.map.containsKey(NativeWalletVault.PENDING))
        assertEquals(2, auditLines(files).size) // E9.11.15-r2-2: the marker isolation row is the second
        assertEquals("rollback", auditLines(files)[0].getString("reason"))
        assertEquals("rollback_marker", auditLines(files)[1].getString("reason"))
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-41 (Y.138 第 6 項 (c)): the fixed record is present and does not open: both files kept, the marker kept, unknown, nothing deleted. */
    @Test fun wk41_anUnhashedMarkerWithAnUnopenableFixedRecordKeepsBothFiles() {
        runWrap("WK-41")
        val (files, wrap, _) = imported()
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        markerWithIsolated(files, NativeWalletVault.REC, oldRec.copyOf())
        files.map[NativeWalletVault.REC] = oldRec.copyOf() // the fixed record is present again, and it does not open
        wrap.openFails = true
        val iso = isolatedNames(files, NativeWalletVault.REC).single()
        val v = NativeWalletVault(wrap, files)
        assertEquals(Import.RECORD_EXISTS, v.importKey(eoa, key))
        assertTrue("the isolated file is kept", files.map.containsKey(iso))
        assertTrue("the marker is kept", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue("the fixed record is kept", files.map.containsKey(NativeWalletVault.REC))
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-42 (Y.138 第 6 項 (c)): the fixed record opens for another account: both files kept, unknown. */
    @Test fun wk42_anUnhashedMarkerWithAnotherAccountsRecordKeepsBothFiles() {
        runWrap("WK-42")
        val (files, wrap, _) = imported()
        val otherKey = ByteArray(32).also { it[31] = 2 }
        val otherEoa = WalletAddress.fromPrivateKey(otherKey)!!
        val otherFiles = NativeTestFiles()
        assertEquals(Import.OK, NativeWalletVault(wrap, otherFiles).importKey(otherEoa, otherKey))
        val otherRec = otherFiles.map[NativeWalletVault.REC]!!.copyOf()
        markerWithIsolated(files, NativeWalletVault.REC, "old".toByteArray(Charsets.UTF_8))
        files.map[NativeWalletVault.REC] = otherRec
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
        val iso = isolatedNames(files, NativeWalletVault.REC).single()
        val v = NativeWalletVault(wrap, files)
        assertEquals(Import.RECORD_EXISTS, v.importKey(eoa, key))
        assertTrue("the isolated file is kept", files.map.containsKey(iso))
        assertTrue("the marker is kept", files.map.containsKey(NativeWalletVault.PENDING))
        assertArrayEquals("the other account's record is kept", otherRec, files.map[NativeWalletVault.REC])
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-43 (B2, Y.138 第 6 項 (b)): interrupted after the isolation, before the record was written; the alias holds a key the old record does not open with. */
    @Test fun wk43_theB2InterruptionIsRolledBackWithTwoAuditLinesAndTheMarkerIsolated() {
        runWrap("WK-43")
        val (files, wrap, _) = imported()
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        wrap.secret = newSecret()
        markerWithIsolated(files, NativeWalletVault.REC, oldRec.copyOf())
        val v = NativeWalletVault(wrap, files)
        assertEquals(Import.RECORD_EXISTS, v.importKey(eoa, key))
        assertArrayEquals("the old bytes are restored", oldRec, files.map[NativeWalletVault.REC])
        assertTrue("no isolated file remains", isolatedNames(files, NativeWalletVault.REC).isEmpty())
        assertFalse("the marker is deleted", files.map.containsKey(NativeWalletVault.PENDING))
        assertEquals(2, auditLines(files).size) // E9.11.15-r2-2: the marker isolation row is the second
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-44 (B2 反例): the fixed names are empty, but the isolated bytes do not match the old hash: both kinds kept, unknown, marker not deleted. */
    @Test fun wk44_aB2InterruptionWithMismatchedIsolatedBytesKeepsEverything() {
        runWrap("WK-44")
        val (files, wrap, _) = imported()
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        markerWithIsolated(files, NativeWalletVault.REC, oldRec.copyOf())
        val iso = isolatedNames(files, NativeWalletVault.REC).single()
        files.map[iso] = "tampered".toByteArray(Charsets.UTF_8)
        val v = NativeWalletVault(wrap, files)
        assertEquals(Import.RECORD_EXISTS, v.importKey(eoa, key))
        assertFalse("the fixed record stays absent", files.map.containsKey(NativeWalletVault.REC))
        assertTrue("the isolated file is kept", files.map.containsKey(iso))
        assertTrue("the marker is kept", files.map.containsKey(NativeWalletVault.PENDING))
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /**
     * WK-45 (Y.138 第 7 項, Y.143 第 3 項): the marker records the alias as absent before its write and the old record does not open. The marker blocks
     * the read (unknown); the next write path settles it, the flag confirms the loss, and the write is not blocked by RECORD_EXISTS.
     */
    @Test fun wk45_aMarkerWithPreWriteAliasAbsentConfirmsTheLossAndDoesNotBlock() {
        runWrap("WK-45")
        val (files, wrap, _) = imported()
        wrap.secret = newSecret() // the alias now holds the key of the failed write; the old record stays unopenable
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-16T10:00:00Z").put("eoa", eoa)
            .put("items", org.json.JSONArray()).put("newRecordSha", JSONObject.NULL).put("preWriteAliasAbsent", true)
            .toString().toByteArray(Charsets.UTF_8)
        val v = NativeWalletVault(wrap, files)
        assertUnknown(v.state())
        assertTrue("a read does not remove the marker", files.map.containsKey(NativeWalletVault.PENDING))
        val r = v.importKey(eoa, key)
        assertFalse("RECORD_EXISTS does not block", r == Import.RECORD_EXISTS)
        assertEquals(Import.OK, r)
        assertTrue("the loss is audited as a flag for the fixed record", auditLines(files).any { it.optString("kind") == "flag" && it.getString("name") == NativeWalletVault.REC })
    }

    /**
     * WK-47 (Y.142 第 1 項, Y.143 第 1、3 項): a failed write whose rollback completed, with preWriteAliasAbsent=true. The failed write is unknown; a read
     * while the marker stands is unknown and removes nothing; the next write path settles the marker, and then the flag makes the loss no_key.
     */
    @Test fun wk47_aRolledBackFailureWithAnAbsentAliasIsUnknownThenNoKeyAfterTheWritePath() {
        runWrap("WK-47")
        val (files, wrap, v) = lostRecord()
        files.failWrite = NativeWalletVault.REC
        assertEquals(Import.STORE_FAILED, v.importKey(eoa, key))
        assertUnknown(v.state())
        files.failWrite = null
        assertUnknown(NativeWalletVault(wrap, files).state())
        assertTrue("a read does not remove the marker", files.map.containsKey(NativeWalletVault.PENDING))
        NativeWalletVault(wrap, files).settleForWrite() // the write-path step of the next write operation (Y.143 第 2 項)
        assertFalse("the write path removes the marker", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue("the flag is audited", auditLines(files).any { it.optString("kind") == "flag" })
        assertConfirmedNoKey(NativeWalletVault(wrap, files).state())
    }

    /**
     * WK-48 (Y.142 第 1 項 反例, Y.143 第 3 項): the same rolled-back shape without preWriteAliasAbsent. No flag is written, and the read stays unknown.
     */
    @Test fun wk48_withoutPreWriteAliasAbsentTheRolledBackReadStaysUnknown() {
        runWrap("WK-48")
        val (files, wrap, _) = imported()
        wrap.secret = newSecret() // the alias holds another key: the old record does not open
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-16T10:00:00Z").put("eoa", eoa)
            .put("items", org.json.JSONArray()).put("newRecordSha", JSONObject.NULL).put("preWriteAliasAbsent", false)
            .toString().toByteArray(Charsets.UTF_8)
        val v = NativeWalletVault(wrap, files)
        assertUnknown(v.state())
        v.settleForWrite()
        assertFalse("the write path removes the marker", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue("no flag is written", auditLines(files).none { it.optString("kind") == "flag" })
        assertUnknown(NativeWalletVault(wrap, files).state())
    }

    /** WK-46 (反例): the same record without preWriteAliasAbsent: the existing record blocks the write, and the state is unknown. */
    @Test fun wk46_withoutPreWriteAliasAbsentTheUnopenableRecordBlocksAndIsUnknown() {
        runWrap("WK-46")
        val (files, wrap, _) = imported()
        wrap.secret = newSecret()
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-16T10:00:00Z").put("eoa", eoa)
            .put("items", org.json.JSONArray()).put("newRecordSha", JSONObject.NULL).put("preWriteAliasAbsent", false)
            .toString().toByteArray(Charsets.UTF_8)
        val v = NativeWalletVault(wrap, files)
        assertEquals(Import.RECORD_EXISTS, v.importKey(eoa, key))
        assertUnknown(NativeWalletVault(wrap, files).state())
    }
}

/** A fresh AES-256 key for the probe wrap (the test double of the device alias). */
private fun newSecret(): SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
