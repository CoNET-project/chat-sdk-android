package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 *  (D1, D2): the overwrite field is set only by the overwrite path, and a roll-forward keeps it. Every window here is produced by
 * the real write path (no hand-written marker).
 */
class OverwriteFlagPathsTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))

    /** A wrap whose old key can be removed: opens fail and the alias is confirmed absent; new seals still work (the new key is in place). */
    private class GoneWrap(private val inner: NativeTestWrap) : KeyWrap by inner {
        var gone = false
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = if (gone) null else inner.open(aad, sealed)
        override fun presence(): WrapKeyPresence = if (gone) WrapKeyPresence.CONFIRMED_ABSENT else WrapKeyPresence.PRESENT
    }

    private fun markerOf(files: NativeTestFiles): JSONObject =
        JSONObject(String(files.map.getValue(NativeWalletVault.PENDING), Charsets.UTF_8))

    /** D1: the store path (a no_key state with a residue) isolates REC and MNEM; its marker must not carry the field. */
    @Test fun aStorePathIsolationWritesAMarkerWithoutTheOverwriteField() {
        val inner = NativeTestWrap()
        val wrap = GoneWrap(inner)
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
        // The old key is gone and the alias is confirmed absent: the state is no_key with the residue, so the new account takes the store path.
        wrap.gone = true
        files.crashAfterWrite = NativeWalletVault.REC
        try {
            NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseB), keyOf(phraseB), phraseB)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        val marker = markerOf(files)
        assertFalse("the store path does not write the overwrite field", marker.has("overwrite"))
        val items = marker.getJSONArray("items")
        assertTrue("the store path isolated a REC or MNEM copy", (0 until items.length()).any {
            items.getJSONObject(it).getString("name").let { n -> n == NativeWalletVault.REC || n == NativeWalletVault.MNEM }
        })
        assertFalse("not an unsettled overwrite", NativeWalletVault(wrap, files).overwriteIntentUnsettled())
    }

    /** D2: a roll-forward rewrites the marker and keeps the overwrite field; the pre-read stays unknown. */
    @Test fun aRollForwardKeepsTheOverwriteFieldAndTheAnswerStaysUnknown() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
        // An overwrite interrupted after the new record is written: the marker is overwrite=true with the REC copy listed.
        files.crashAfterWrite = NativeWalletVault.REC
        try {
            NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseB), keyOf(phraseB), phraseB)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        assertTrue("the window is an unsettled overwrite", NativeWalletVault(wrap, files).overwriteIntentUnsettled())
        // The next settle rolls the window forward, and the commit cannot be written, so the window stays open: the rewritten marker must keep the field.
        files.failWrite = NativeWalletVault.COMMIT
        NativeWalletVault(wrap, files).settleForWrite()
        files.failWrite = null
        assertTrue("the marker is still there", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue("the field survives the roll-forward rewrite", markerOf(files).optBoolean("overwrite", false))
        assertTrue("the pre-read stays unknown", MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)) is MnemonicPreread.Answer.Unknown)
    }
}
