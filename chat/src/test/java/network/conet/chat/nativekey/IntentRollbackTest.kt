package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The rollback-all resume (settleUnhashed branch b) removes the intent of the aborted write (1d546c0 item 1, independent review 2026-11-17):
 *  (a) every entry can be put back: rollback_new_record is audited, then INTENT is removed;
 *  (b) the audit row cannot be written: INTENT stays and the resume returns false;
 *  (c) the restore of an entry fails: INTENT stays and the resume returns false.
 * The sealed copy is made unopenable in these cases, so the window branch does not apply and the rollback branch runs.
 */
class IntentRollbackTest {
    private val oldPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    @Before fun newLaunch() {
        NativeWalletVault.resetLaunchForTests()
    }

    /** A wrap whose sealed records stop opening while [breakOpen] is set (the window shape is then not confirmed). */
    private class BreakableWrap(val inner: NativeTestWrap) : KeyWrap {
        var breakOpen = false
        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray = inner.seal(aad, plain)
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = if (breakOpen) null else inner.open(aad, sealed)
        override fun deleteKey(): Boolean = inner.deleteKey()
    }

    private fun digest(b: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    /**
     * The state after an aborted write that renamed REC and MARK to isolated names (both still hold the old bytes), with the fixed names empty
     * and an intent written before the record. Returns the old REC and MARK bytes.
     */
    private fun stageRollbackAll(wrap: BreakableWrap, files: NativeTestFiles): Pair<ByteArray, ByteArray> {
        val key = checkNotNull(MnemonicDerivation.deriveKey(oldPhrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(key))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa, key, oldPhrase))
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val oldMark = files.map[NativeWalletVault.MARK]!!.copyOf()
        files.map.remove(NativeWalletVault.REC)
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.MNEM)
        files.map.remove(NativeWalletVault.COMMIT)
        val isoRec = "${NativeWalletVault.REC}.isolated.20261117T000000Z.cccccccc"
        val isoMark = "${NativeWalletVault.MARK}.isolated.20261117T000000Z.dddddddd"
        files.map[isoRec] = oldRec
        files.map[isoMark] = oldMark
        files.map[NativeWalletVault.INTENT] = NativeWalletVault(wrap, files).encodeIntent(eoa, mnemonicPlanned = true, created = null)
        files.map[NativeWalletVault.PENDING] = org.json.JSONObject().put("v", 1).put("utc", "2026-11-17T00:00:00Z").put("eoa", eoa)
            .put("preWriteAliasAbsent", false).put("newRecordSha", org.json.JSONObject.NULL)
            .put("items", org.json.JSONArray()
                .put(org.json.JSONObject().put("name", NativeWalletVault.REC).put("isolated", isoRec).put("oldSha", digest(oldRec)))
                .put(org.json.JSONObject().put("name", NativeWalletVault.MARK).put("isolated", isoMark).put("oldSha", digest(oldMark))))
            .toString().toByteArray(Charsets.UTF_8)
        wrap.breakOpen = true
        return oldRec to oldMark
    }

    // (a) every entry can be put back: the abort is audited (rollback_new_record), the intent is removed, the fixed names hold the old bytes.
    @Test fun a_rollbackAllAuditsAndRemovesTheIntent() {
        val wrap = BreakableWrap(NativeTestWrap()); val files = NativeTestFiles()
        val (oldRec, oldMark) = stageRollbackAll(wrap, files)
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        assertArrayEquals(oldMark, files.map[NativeWalletVault.MARK])
        assertFalse("intent removed", files.map.containsKey(NativeWalletVault.INTENT))
        assertFalse("marker removed", files.map.containsKey(NativeWalletVault.PENDING))
        val audit = String(files.map.getValue(NativeWalletVault.AUDIT), Charsets.UTF_8)
        assertTrue("rollback_new_record is audited", audit.contains("rollback_new_record"))
    }

    // (b) the audit row cannot be written: nothing is removed, INTENT stays, the resume returns false (the next launch retries).
    @Test fun b_auditFailureKeepsTheIntentAndReturnsFalse() {
        val wrap = BreakableWrap(NativeTestWrap()); val files = NativeTestFiles()
        stageRollbackAll(wrap, files)
        files.failWrite = NativeWalletVault.AUDIT
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertTrue("intent kept", files.map.containsKey(NativeWalletVault.INTENT))
        assertTrue("marker kept", files.map.containsKey(NativeWalletVault.PENDING))
        // The fault clears: the next launch removes the intent after the audit row is written.
        files.failWrite = null
        NativeWalletVault.resetLaunchForTests()
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertFalse(files.map.containsKey(NativeWalletVault.INTENT))
        assertTrue(String(files.map.getValue(NativeWalletVault.AUDIT), Charsets.UTF_8).contains("rollback_new_record"))
    }

    // (c) an entry cannot be restored (its rename from the isolated name fails): nothing is removed, INTENT stays, the resume returns false.
    @Test fun c_restoreFailureKeepsTheIntentAndReturnsFalse() {
        val wrap = BreakableWrap(NativeTestWrap()); val files = NativeTestFiles()
        stageRollbackAll(wrap, files)
        files.failRename = { it.contains(".isolated.") }
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertTrue("intent kept", files.map.containsKey(NativeWalletVault.INTENT))
        assertTrue("marker kept", files.map.containsKey(NativeWalletVault.PENDING))
        assertFalse("no rollback audit row for an unfinished restore", files.map[NativeWalletVault.AUDIT]?.let { String(it, Charsets.UTF_8).contains("rollback_new_record") } == true)
    }
}
