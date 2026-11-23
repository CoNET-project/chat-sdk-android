package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 *  (iii, additive field overwrite, i): an unsettled OVERWRITE is a pending marker with overwrite=true that lists an isolated copy
 * of REC or MNEM. Only that is unknown for the pre-read. A first-write half window (intent only), a residual MARK of an import, a settled keep
 * residue (E9.1-4), and a marker without the field are not overwrites.
 */
class PrereadOverwriteMarkerTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"

    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))

    /** A complete native import of A (REC, MNEM, MARK, COMMIT present). */
    private fun importedA(wrap: NativeTestWrap, files: NativeTestFiles) {
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
    }

    private fun marker(overwrite: Boolean?, vararg names: String): ByteArray {
        val items = JSONArray()
        for (n in names) items.put(JSONObject().put("name", n).put("isolated", "$n.isolated.20261118T000000Z.0000abcd").put("oldSha", "00".repeat(32)))
        val o = JSONObject().put("v", 1).put("utc", "2026-11-18T00:00:00Z").put("eoa", eoaOf(phraseA))
            .put("preWriteAliasAbsent", false).put("newRecordSha", JSONObject.NULL).put("items", items)
        if (overwrite != null) o.put("overwrite", overwrite)
        return o.toString().toByteArray(Charsets.UTF_8)
    }

    @Test fun anUnsettledOverwriteWithAListedRecOrMnemCopyIsUnknown() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        importedA(wrap, files)
        files.map[NativeWalletVault.PENDING] = marker(true, NativeWalletVault.REC, NativeWalletVault.MNEM)
        val vault = NativeWalletVault(wrap, files)
        assertTrue("the overwrite is unsettled", vault.overwriteIntentUnsettled())
        assertTrue("unknown: ${MnemonicPreread.vaultAnswerOrUnknown(vault)}", MnemonicPreread.vaultAnswerOrUnknown(vault) is MnemonicPreread.Answer.Unknown)
    }

    @Test fun aFirstWriteHalfWindowWithOnlyTheIntentIsValid() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        importedA(wrap, files)
        // A first write interrupted before its commit: the intent is present, no pending marker, the phrase reads and verifies.
        files.map[NativeWalletVault.INTENT] = JSONObject().put("v", 1).put("eoa", eoaOf(phraseA)).toString().toByteArray(Charsets.UTF_8)
        val vault = NativeWalletVault(wrap, files)
        assertFalse("not an overwrite", vault.overwriteIntentUnsettled())
        assertTrue("valid", MnemonicPreread.vaultAnswerOrUnknown(vault) is MnemonicPreread.Answer.Valid)
    }

    @Test fun aResidualMarkOfAnImportIsNotAnOverwriteAndStaysValid() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        importedA(wrap, files)
        // The import left a MARK entry in the list (the list is non-empty), but it lists no REC or MNEM copy: not an overwrite, with or without the flag.
        files.map[NativeWalletVault.PENDING] = marker(true, NativeWalletVault.MARK, NativeWalletVault.COMMIT)
        val withFlag = NativeWalletVault(wrap, files)
        assertFalse(withFlag.overwriteIntentUnsettled())
        assertTrue("valid with the flag", MnemonicPreread.vaultAnswerOrUnknown(withFlag) is MnemonicPreread.Answer.Valid)
        files.map[NativeWalletVault.PENDING] = marker(null, NativeWalletVault.MARK)
        assertTrue("valid without the flag", MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)) is MnemonicPreread.Answer.Valid)
    }

    @Test fun aMarkerWithoutTheFieldIsNotAnOverwrite() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        importedA(wrap, files)
        // The format before the field existed: it lists a REC copy but carries no overwrite field, so it is read as not an overwrite (valid).
        files.map[NativeWalletVault.PENDING] = marker(null, NativeWalletVault.REC)
        val vault = NativeWalletVault(wrap, files)
        assertFalse(vault.overwriteIntentUnsettled())
        assertTrue("valid", MnemonicPreread.vaultAnswerOrUnknown(vault) is MnemonicPreread.Answer.Valid)
    }

    @Test fun aSettledKeepResidueOfAValidAccountStaysValid() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        importedA(wrap, files)
        // E9.1-4 shape: a keep entry (a settled move) for REC, no overwrite field: not an overwrite.
        files.map[NativeWalletVault.PENDING] = marker(null, NativeWalletVault.REC)
        assertTrue("valid", MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)) is MnemonicPreread.Answer.Valid)
    }

    /** The rollback residue (step 4): the commit write fails, the rollback is blocked; the new phrase still decrypts. The answer is not valid. */
    @Test fun aRollbackPendingOverwriteWithADecryptableNewPhraseIsNotValid() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        importedA(wrap, files)
        files.failWrite = NativeWalletVault.COMMIT
        files.failRename = { it == NativeWalletVault.MNEM || it.startsWith("${NativeWalletVault.REC}.isolated.") }
        val answer = NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseB), keyOf(phraseB), phraseB)
        assertEquals("the overwrite did not finish: $answer", NativeWalletVault.SyncOutcome.ROLLBACK_PENDING, answer)
        val fresh = NativeWalletVault(wrap, files)
        assertTrue("the marker is an overwrite", fresh.overwriteIntentUnsettled())
        assertFalse("not Valid", MnemonicPreread.vaultAnswerOrUnknown(fresh) is MnemonicPreread.Answer.Valid)
    }

    /** Proof (a): the overwrite field is written only by the overwrite path (writeNewSlot's two marker writes). Source guard. */
    @Test fun theOverwriteFieldIsWrittenOnlyByTheOverwritePath() {
        val src = java.io.File("src/main/java/network/conet/chat/nativekey/NativeWalletVault.kt").readText()
        assertEquals("one writer of the field", 1, Regex("put\\(\"overwrite\"").findAll(src).count())
        // D1: the marker writes take the parameter; only the overwrite call site (replaceWithIsolation) passes true.
        assertEquals("the two marker writes take the parameter", 2, Regex("overwrite = overwrite").findAll(src).count())
        assertEquals("only the overwrite path passes true", 1, Regex("overwrite = true").findAll(src).count())
    }

    /** Proof (b): a keep entry (addPendingEntry) never carries the overwrite field. Source guard on that function's body. */
    @Test fun aKeepEntryNeverCarriesTheOverwriteField() {
        val src = java.io.File("src/main/java/network/conet/chat/nativekey/NativeWalletVault.kt").readText()
        val start = src.indexOf("private fun addPendingEntry(")
        val body = src.substring(start, src.indexOf("private fun ", start + 10))
        assertTrue("the keep entry is written", body.contains("\"kind\", \"keep\""))
        assertFalse("no overwrite field in a keep entry", body.contains("overwrite"))
    }

    /** Proof (a), behaviour: a first write (import) leaves no pending marker, so it cannot be an overwrite. */
    @Test fun aFirstWriteLeavesNoPendingMarker() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        importedA(wrap, files)
        assertFalse("no marker", files.map.containsKey(NativeWalletVault.PENDING))
        assertFalse(NativeWalletVault(wrap, files).overwriteIntentUnsettled())
    }

    /** Proof (c): after keepMarkerAsIsolated moves the pending marker, the pre-read reads no marker and the answer is not an unsettled overwrite. */
    @Test fun aMarkerKeptAsIsolatedIsNoLongerAnUnsettledOverwrite() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        importedA(wrap, files)
        files.failWrite = NativeWalletVault.REC
        assertEquals(NativeWalletVault.SyncOutcome.WRITE_FAILED, NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseB), keyOf(phraseB), phraseB))
        assertFalse("the marker was moved", files.map.containsKey(NativeWalletVault.PENDING))
        assertFalse(NativeWalletVault(wrap, files).overwriteIntentUnsettled())
    }

    /** E1: a pending marker that is present but cannot be parsed is not a valid answer (a read failure is unknown). */
    @Test fun aPendingMarkerThatCannotBeParsedIsNotAValidAnswer() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        importedA(wrap, files)
        files.map[NativeWalletVault.PENDING] = "not json".toByteArray(Charsets.UTF_8)
        val vault = NativeWalletVault(wrap, files)
        assertTrue("the marker is unreadable", vault.pendingMarkerUnreadable())
        assertTrue("not valid: ${MnemonicPreread.vaultAnswerOrUnknown(vault)}", MnemonicPreread.vaultAnswerOrUnknown(vault) is MnemonicPreread.Answer.Unknown)
    }

    /** E1, the other side: no marker at all is not unreadable, so the valid account keeps its answer. */
    @Test fun noMarkerIsNotUnreadableAndTheAccountStaysValid() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        importedA(wrap, files)
        val vault = NativeWalletVault(wrap, files)
        assertFalse(vault.pendingMarkerUnreadable())
        assertTrue("valid", MnemonicPreread.vaultAnswerOrUnknown(vault) is MnemonicPreread.Answer.Valid)
    }

    /** The read of the pending marker itself throws, while the other positions are absent: unknown, not absent (global rule). */
    @Test fun aPendingMarkerReadFaultIsUnknownEvenWhenTheOtherPositionsAreAbsent() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        // No phrase anywhere: the key record only (the other positions read as absent).
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoaOf(phraseA), keyOf(phraseA)))
        files.map[NativeWalletVault.PENDING] = "{}".toByteArray(Charsets.UTF_8)
        val failing = object : VaultFiles by files {
            override fun read(name: String): ByteArray? = if (name == NativeWalletVault.PENDING) throw java.io.IOException("device I/O") else files.read(name)
        }
        val vault = NativeWalletVault(wrap, failing)
        assertTrue("the read fault is seen", vault.pendingMarkerReadFault())
        assertTrue("unknown, not absent: ${MnemonicPreread.vaultAnswerOrUnknown(vault)}", MnemonicPreread.vaultAnswerOrUnknown(vault) is MnemonicPreread.Answer.Unknown)
    }

    /** The other side: a marker that reads but is empty ("{}") keeps the absent answer (P-14, 2026-11-17): it is not a read fault. */
    @Test fun anEmptyReadableMarkerKeepsTheAbsentAnswer() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoaOf(phraseA), keyOf(phraseA)))
        files.map[NativeWalletVault.PENDING] = "{}".toByteArray(Charsets.UTF_8)
        val vault = NativeWalletVault(wrap, files)
        assertFalse("not a read fault", vault.pendingMarkerReadFault())
        assertTrue("absent (P-14)", MnemonicPreread.vaultAnswerOrUnknown(vault) is MnemonicPreread.Answer.Absent)
    }
}
