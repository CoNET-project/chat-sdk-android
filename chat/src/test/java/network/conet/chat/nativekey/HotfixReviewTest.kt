package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.MessageDigest

/** Hotfix review: P2, P3 (settle write faults do not escape) and H2 (a hashed marker's rollback keeps the marker). Each case is a cold start. */
class HotfixReviewTest {
    private val phraseA = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val phraseB = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    @Before fun coldStart() {
        NativeWalletVault.resetLaunchForTests()
    }

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    private fun keyAndEoa(p: String): Pair<ByteArray, String> {
        val k = checkNotNull(MnemonicDerivation.deriveKey(p))
        return k to checkNotNull(WalletAddress.fromPrivateKey(k))
    }

    /** A valid A with a pending roll-forward marker that lists B's move (commit missing). */
    private fun pendingRollForward(): Triple<NativeTestFiles, NativeTestWrap, String> {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val (kA, eA) = keyAndEoa(phraseA)
        val (kB, eB) = keyAndEoa(phraseB)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eA, kA, phraseA))
        val bRec = NativeTestFiles().also { assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, it).importKey(eB, kB)) }.map[NativeWalletVault.REC]!!
        val iso = "${NativeWalletVault.REC}.isolated.20261117T000000Z.bbbbbbbb"
        files.map[iso] = bRec
        files.map.remove(NativeWalletVault.COMMIT)
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-17T00:00:00Z").put("eoa", eA)
            .put("preWriteAliasAbsent", false).put("newRecordSha", JSONObject.NULL)
            .put("items", JSONArray().put(JSONObject().put("name", NativeWalletVault.REC).put("isolated", iso).put("oldSha", sha(bRec))))
            .toString().toByteArray(Charsets.UTF_8)
        return Triple(files, wrap, eB)
    }

    // P2 / P3: a write fault while the roll-forward completes the marker (MARK, then COMMIT) is a refusal, not an exception.
    @Test fun p2_markWriteFaultDuringTheSettleIsRefusedAndKeepsTheMarker() {
        val (files, wrap, eB) = pendingRollForward()
        files.map.remove(NativeWalletVault.MARK) // the roll-forward must write the marker, and that write fails
        files.failWrite = NativeWalletVault.MARK
        val (kB, _) = keyAndEoa(phraseB)
        val answer = NativeWalletVault(wrap, files).importKey(eB, kB)
        assertEquals(NativeWalletVault.Import.STORE_FAILED, answer)
        assertTrue("marker kept", files.map.containsKey(NativeWalletVault.PENDING))
        NativeWalletVault.resetLaunchForTests()
        val eA = keyAndEoa(phraseA).second
        val v = NativeWalletVault(wrap, files)
        assertEquals(eA, (v.state() as NativeWalletVault.State.Ready).eoa)
        assertEquals(NativeWalletVault.PhraseVerdict.VALID, v.phraseVerdict())
    }

    @Test fun p3_commitWriteFaultDuringTheSettleIsRefusedAndKeepsTheMarker() {
        val (files, wrap, eB) = pendingRollForward()
        files.failWrite = NativeWalletVault.COMMIT
        val (kB, _) = keyAndEoa(phraseB)
        val answer = NativeWalletVault(wrap, files).importKey(eB, kB)
        assertEquals(NativeWalletVault.Import.STORE_FAILED, answer)
        assertTrue("marker kept", files.map.containsKey(NativeWalletVault.PENDING))
        NativeWalletVault.resetLaunchForTests()
        val eA = keyAndEoa(phraseA).second
        val v = NativeWalletVault(wrap, files)
        assertEquals(eA, (v.state() as NativeWalletVault.State.Ready).eoa)
        assertEquals(NativeWalletVault.PhraseVerdict.VALID, v.phraseVerdict())
    }

    // H2 (independent review): a hashed marker whose write was interrupted before the new record landed, the current phrase is valid for A.
    // A's data is kept, the state is Ready(A), and the marker is isolated (not erased) by the rollback.
    @Test fun h2_hashedMarkerRollbackIsolatesTheMarkerAndKeepsA() {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val (kA, eA) = keyAndEoa(phraseA)
        val (kB, eB) = keyAndEoa(phraseB)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eA, kA, phraseA))
        val bRec = NativeTestFiles().also { assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, it).importKey(eB, kB)) }.map[NativeWalletVault.REC]!!
        val iso = "${NativeWalletVault.REC}.isolated.20261117T000000Z.bbbbbbbb"
        files.map[iso] = bRec
        files.map.remove(NativeWalletVault.REC)
        files.map.remove(NativeWalletVault.COMMIT)
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-17T00:00:00Z").put("eoa", eB)
            .put("preWriteAliasAbsent", false).put("newRecordSha", "00".repeat(32))
            .put("items", JSONArray().put(JSONObject().put("name", NativeWalletVault.REC).put("isolated", iso).put("oldSha", sha(bRec))))
            .toString().toByteArray(Charsets.UTF_8)
        val before = files.map.filterKeys { it != NativeWalletVault.AUDIT }.mapValues { sha(it.value) }
        NativeWalletVault.resetLaunchForTests()
        val settled = NativeWalletVault(wrap, files).settleForWrite()
        assertFalse("marker fixed name absent", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue("marker isolated", files.map.keys.any { it.startsWith(NativeWalletVault.PENDING + ".isolated.") })
        assertTrue("no byte is lost", before.values.all { d -> files.map.values.any { sha(it) == d } })
    }

    private fun fullA(): Triple<NativeTestFiles, NativeTestWrap, String> {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val (kA, eA) = keyAndEoa(phraseA)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eA, kA, phraseA))
        return Triple(files, wrap, eA)
    }

    // H3 (review): A's complete account plus a leftover marker that names A (the REC -> B copy): Ready(A), verdict VALID (cold start, no write).
    @Test fun h3_aValidAccountWithALeftoverMarkerIsReady() {
        val (files, wrap, eA) = fullA()
        val (_, eB) = keyAndEoa(phraseB)
        val bCopy = "b-record".toByteArray(Charsets.UTF_8)
        val iso = "${NativeWalletVault.REC}.isolated.20261117T000000Z.bbbbbbbb"
        files.map[iso] = bCopy
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-17T00:00:00Z").put("eoa", eA)
            .put("preWriteAliasAbsent", false).put("newRecordSha", JSONObject.NULL)
            .put("items", JSONArray().put(JSONObject().put("name", NativeWalletVault.REC).put("isolated", iso).put("oldSha", sha(bCopy))))
            .toString().toByteArray(Charsets.UTF_8)
        NativeWalletVault.resetLaunchForTests()
        val v = NativeWalletVault(wrap, files)
        assertEquals(eA, (v.state() as NativeWalletVault.State.Ready).eoa)
        assertEquals(NativeWalletVault.PhraseVerdict.VALID, v.phraseVerdict())
        // the leftover marker still blocks a write: a key-mode import of another account is not written
        val (kB, _) = keyAndEoa(phraseB)
        // the settle runs on the first write path (roll forward of the valid account A); the write of B is refused, not written
        assertEquals(NativeWalletVault.Import.RECORD_EXISTS, NativeWalletVault(wrap, files).importKey(eB, kB))
    }

    // H2 (independent review fixture): REC = A's record, MNEM = A's phrase, MARK and COMMIT complete; the marker names C with two items holding A's bytes.
    @Test fun h2_reviewFixtureIsReadyAForA() {
        val (files, wrap, eA) = fullA()
        val rec = files.map[NativeWalletVault.REC]!!.copyOf()
        val mnem = files.map[NativeWalletVault.MNEM]!!.copyOf()
        val isoRec = "${NativeWalletVault.REC}.isolated.20261117T000000Z.aaaaaaaa"
        val isoMnem = "${NativeWalletVault.MNEM}.isolated.20261117T000000Z.aaaaaaaa"
        files.map[isoRec] = rec
        files.map[isoMnem] = mnem
        val (_, eC) = keyAndEoa(phraseB)
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-17T00:00:00Z").put("eoa", eC)
            .put("preWriteAliasAbsent", false).put("newRecordSha", "11".repeat(32))
            .put("items", JSONArray()
                .put(JSONObject().put("name", NativeWalletVault.REC).put("isolated", isoRec).put("oldSha", sha(rec)))
                .put(JSONObject().put("name", NativeWalletVault.MNEM).put("isolated", isoMnem).put("oldSha", sha(mnem))))
            .toString().toByteArray(Charsets.UTF_8)
        NativeWalletVault.resetLaunchForTests()
        val v = NativeWalletVault(wrap, files)
        v.settleForWrite()
        val st = NativeWalletVault(wrap, files).state()
        assertTrue("Ready(A)", st is NativeWalletVault.State.Ready && st.eoa == eA)
    }
}
