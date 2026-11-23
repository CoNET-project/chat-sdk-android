package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.json.JSONObject

/**
 * Negative probes of the half-written window (Android independent review, 2026-11-17: 59E-window-negative-probe-main3-vs-b-2026-11-17.md).
 * The stop is after REC is written and before MNEM (the window). The sealed old copy of REC is then (negA) unopenable or (negB) opened to the new
 * account's record. Expected (the rule b behaviour, which the probe report establishes): nothing is removed, nothing is audited, the marker keeps
 * no new-record digest, and the user retry leaves everything as it is.
 * On the main line the rule b change is not applied (it is a pending), so these tests are @Ignore'd there with that reason. The branches
 * that carry rule b run them (see the branch notes).
 */
class NegativeProbeTest {
    private val oldPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val newPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val wrap = NativeTestWrap()
    private val oldKey by lazy { checkNotNull(MnemonicDerivation.deriveKey(oldPhrase)) }
    private val oldEoa by lazy { checkNotNull(WalletAddress.fromPrivateKey(oldKey)) }
    private val newKey by lazy { checkNotNull(MnemonicDerivation.deriveKey(newPhrase)) }
    private val newEoa by lazy { checkNotNull(WalletAddress.fromPrivateKey(newKey)) }

    @Before fun newLaunch() {
        NativeWalletVault.resetLaunchForTests()
    }

    private fun digest(b: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    /** Stops after REC is written. Returns the files and the name of the sealed copy of the old record (named by the marker). */
    private fun stopAfterRec(): Pair<NativeTestFiles, String> {
        val files = NativeTestFiles()
        NativeWalletVault(wrap, files).importMnemonicKey(oldEoa, oldKey, oldPhrase)
        files.crashAfterWrite = NativeWalletVault.REC
        try {
            NativeWalletVault(wrap, files).syncPhrase(newEoa, newKey, newPhrase)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        val items = JSONObject(String(files.map.getValue(NativeWalletVault.PENDING), Charsets.UTF_8)).getJSONArray("items")
        val rec = (0 until items.length()).map { items.getJSONObject(it) }.first { it.getString("name") == NativeWalletVault.REC }
        return files to rec.getString("isolated")
    }

    private fun snapshot(files: NativeTestFiles): Map<String, String> =
        files.map.filterKeys { it != NativeWalletVault.AUDIT }.mapValues { digest(it.value) }

    private fun auditText(files: NativeTestFiles) = files.map[NativeWalletVault.AUDIT]?.let { String(it, Charsets.UTF_8) } ?: ""

    /** The shared expectation: retained, no audit, no new-record digest, unchanged on the user retry. */
    private fun assertRetained(files: NativeTestFiles, before: Map<String, String>, auditBefore: String) {
        assertEquals("nothing removed or changed", before, snapshot(files))
        assertEquals("no audit row written", auditBefore, auditText(files))
        assertFalse("no roll-forward row", auditText(files).contains("roll_forward"))
        val pending = JSONObject(String(files.map.getValue(NativeWalletVault.PENDING), Charsets.UTF_8))
        assertTrue("no new-record digest in the marker", pending.isNull("newRecordSha"))
        assertFalse("not the new account", NativeWalletVault(wrap, files).state() is NativeWalletVault.State.Ready &&
            (NativeWalletVault(wrap, files).state() as NativeWalletVault.State.Ready).eoa.equals(newEoa, ignoreCase = true))
    }

    @Ignore("known gap: rule b (pending) is not on the main line; the window roll-forward path writes roll_forward here")
    @Test fun probe_negA_corruptedSealedCopyThenRestart() {
        val (files, isoRec) = stopAfterRec()
        val before = snapshot(files)
        val auditBefore = auditText(files)
        files.map[isoRec] = "unopenable-garbage".toByteArray()
        val before2 = snapshot(files)
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertRetained(files, before2, auditBefore)
        assertTrue("the pre-corruption state was also retained", before.keys == before2.keys)
    }

    @Ignore("known gap: rule b (pending) is not on the main line")
    @Test fun probe_negB_copyDecryptsToOtherEoaThenRestart() {
        val (files, isoRec) = stopAfterRec()
        // The sealed copy now holds the new account's record (it opens, but to B, not A).
        files.map[isoRec] = files.map[NativeWalletVault.REC]!!.copyOf()
        val before = snapshot(files)
        val auditBefore = auditText(files)
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertRetained(files, before, auditBefore)
    }

    @Ignore("known gap: rule b (pending) is not on the main line")
    @Test fun probe_negA_secondLaunchAndUserRetry() {
        val (files, isoRec) = stopAfterRec()
        files.map[isoRec] = "unopenable-garbage".toByteArray()
        val before = snapshot(files)
        val auditBefore = auditText(files)
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        NativeWalletVault.resetLaunchForTests()
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertRetained(files, before, auditBefore)
        assertFalse(NativeWalletVault(wrap, files).retryPendingByUser())
        assertRetained(files, before, auditBefore)
    }
}
