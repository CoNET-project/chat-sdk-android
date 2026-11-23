package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.MessageDigest

/**
 * E9.11.16 RF-1 / RF-2 / k=5 (hotfix, ported from main): a valid current account rolls forward at cold start; its files do not move.
 */
class RollForwardRecoveryTest {
    private val phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val otherPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    @Before fun newLaunch() {
        NativeWalletVault.resetLaunchForTests()
    }

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    private fun keyAndEoa(p: String): Pair<ByteArray, String> {
        val key = checkNotNull(MnemonicDerivation.deriveKey(p))
        return key to checkNotNull(WalletAddress.fromPrivateKey(key))
    }

    /** A valid account A (phrase, record, marker, commit) with a marker that lists another account's move B; [withCommit] keeps the commit. */
    private fun markerWithOtherMove(withCommit: Boolean): Triple<NativeTestFiles, NativeTestWrap, String> {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val (keyA, eoaA) = keyAndEoa(phrase)
        val (keyB, eoaB) = keyAndEoa(otherPhrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaA, keyA, phrase))
        val bRec = NativeTestFiles().also { assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, it).importKey(eoaB, keyB)) }.map[NativeWalletVault.REC]!!
        val iso = "${NativeWalletVault.REC}.isolated.20261117T000000Z.bbbbbbbb"
        files.map[iso] = bRec
        if (!withCommit) files.map.remove(NativeWalletVault.COMMIT)
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-17T00:00:00Z").put("eoa", eoaA)
            .put("preWriteAliasAbsent", false).put("newRecordSha", JSONObject.NULL)
            .put("items", JSONArray().put(JSONObject().put("name", NativeWalletVault.REC).put("isolated", iso).put("oldSha", sha(bRec))))
            .toString().toByteArray(Charsets.UTF_8)
        return Triple(files, wrap, iso)
    }

    private fun assertRollForward(files: NativeTestFiles, wrap: NativeTestWrap, iso: String, recBefore: String, mnemBefore: String, eoaA: String) {
        assertTrue("settle completes", NativeWalletVault(wrap, files).settleForWrite())
        assertEquals("A's record is not moved", recBefore, sha(files.map.getValue(NativeWalletVault.REC)))
        assertEquals("A's phrase is not moved", mnemBefore, sha(files.map.getValue(NativeWalletVault.MNEM)))
        assertFalse("the marker fixed name is absent", files.map.containsKey(NativeWalletVault.PENDING))
        assertEquals("the marker is isolated", 1, files.map.keys.count { it.startsWith(NativeWalletVault.PENDING + ".isolated.") })
        assertTrue("B stays isolated", files.map.containsKey(iso))
        val st = NativeWalletVault(wrap, files).state()
        assertTrue("state Ready", st is NativeWalletVault.State.Ready)
        assertEquals("one valid account", eoaA, (st as NativeWalletVault.State.Ready).eoa)
    }

    @Test fun rf1_commitMissingRollsForwardAndKeepsTheOtherMoveIsolated() {
        val (files, wrap, iso) = markerWithOtherMove(withCommit = false)
        val eoaA = keyAndEoa(phrase).second
        val recBefore = sha(files.map.getValue(NativeWalletVault.REC))
        val mnemBefore = sha(files.map.getValue(NativeWalletVault.MNEM))
        assertRollForward(files, wrap, iso, recBefore, mnemBefore, eoaA)
        assertTrue("commit completed", files.map.containsKey(NativeWalletVault.COMMIT))
    }

    @Test fun rf2_commitPresentRollsForwardAndKeepsTheOtherMoveIsolated() {
        val (files, wrap, iso) = markerWithOtherMove(withCommit = true)
        val eoaA = keyAndEoa(phrase).second
        val recBefore = sha(files.map.getValue(NativeWalletVault.REC))
        val mnemBefore = sha(files.map.getValue(NativeWalletVault.MNEM))
        assertRollForward(files, wrap, iso, recBefore, mnemBefore, eoaA)
    }

    /** k=5: the write fails at the marker and the rollback cannot read the store; a cold start rolls forward the valid current account. */
    @Test fun k5_coldStartRollsForwardWhenTheCurrentPhraseIsValid() {
        val wrap = NativeTestWrap(); val files = NativeTestFiles()
        val (key, eoa) = keyAndEoa(phrase)
        files.failWrite = NativeWalletVault.MARK
        files.failRead = { files.map.containsKey(NativeWalletVault.REC) && it in setOf(NativeWalletVault.REC, NativeWalletVault.MNEM, NativeWalletVault.MARK, NativeWalletVault.COMMIT, NativeWalletVault.INTENT) }
        NativeWalletVault(wrap, files).importMnemonicKey(eoa, key, phrase)
        files.failRead = null
        files.failWrite = null
        NativeWalletVault.resetLaunchForTests()
        NativeWalletVault(wrap, files).settleForWrite()
        assertEquals(eoa, (NativeWalletVault(wrap, files).state() as NativeWalletVault.State.Ready).eoa)
    }
}
