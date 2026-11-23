package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v227 §247.4 PHR-01..04 (parity with iOS): the phrase residue (a readable phrase with no key record). Driven through the production
 * vault and the production gate: a valid phrase is `has` (locked + phrase_only on G2; not_ready + g1_uninitialized on G1), an unreadable residue is unknown
 * (not_ready + unreadable). Never no_key.
 *
 * PHR-03 (readable but invalid) builds the residue as the vault itself stores it: the envelope of NativeWalletVault.encodeMnemonic, sealed with the public
 * mnemAad, around a 12-word phrase whose checksum is wrong. It unseals (readable) and derives no key (invalid).
 */
class PhraseOnlyPhrTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(p))))
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))

    /** A valid phrase with its key record removed: the residue (pointer set, key record missing, readable phrase). */
    private fun residue(): Pair<NativeWalletVault, String> {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phrase), keyOf(phrase), phrase))
        files.map.remove(NativeWalletVault.REC)
        return NativeWalletVault(wrap, files) to eoaOf(phrase)
    }

    /** PHR-01: session ready (G2) with a valid residue and the pointer: locked + phrase_only + the pointer's accountKey, never no_key. */
    @Test
    fun phr01ReadyWithValidResidueIsLockedPhraseOnly() {
        val (vault, eoa) = residue()
        val state = vault.state()
        assertEquals(NativeWalletVault.State.Locked(NativeWalletVault.PHRASE_ONLY).reason, (state as NativeWalletVault.State.Locked).reason)
        assertEquals(NoKeyGate.Gate.G2, NoKeyGate.gateOf(state, sessionReady = true))
        val answer = NoKeyGate.phraseOnlyWalletStatus(eoa)
        assertEquals("locked", answer.getString("status"))
        assertEquals(NativeWalletVault.PHRASE_ONLY, answer.getString("reason"))
        assertTrue(answer.has("accountKey"))
        assertFalse(answer.optString("status") == "no_key")
    }

    /** PHR-02: session not ready (G1) with a valid residue: not_ready + g1_uninitialized, never no_key. */
    @Test
    fun phr02NotReadyWithValidResidueIsG1Uninitialized() {
        val (vault, _) = residue()
        val state = vault.state()
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.gateOf(state, sessionReady = false))
        assertEquals("g1_uninitialized", NoKeyGate.notReadyReasonOf(state, vault))
    }

    /** PHR-03: a readable but invalid residue phrase (the envelope the vault writes, a phrase that derives no key): not_ready + unreadable, never no_key. */
    @Test
    fun phr03ReadableButInvalidResidueIsUnreadableNeverNoKey() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phrase), keyOf(phrase), phrase))
        files.map.remove(NativeWalletVault.REC)
        // Self-check: the phrase is invalid (its checksum is wrong), so no key derives from it.
        val bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        assertEquals(null, MnemonicDerivation.deriveKey(bad))
        val eoa = eoaOf(phrase)
        val sealed = wrap.seal(NativeWalletVault.mnemAad(eoa), bad.toByteArray(Charsets.UTF_8))
        val envelope = org.json.JSONObject()
            .put("record", NativeWalletVault.RECORD_VERSION)
            .put("eoa", eoa)
            .put("sealed", ConetChatCryptoUtil.toHex(sealed))
            .toString()
        files.map[NativeWalletVault.MNEM] = envelope.toByteArray(Charsets.UTF_8)
        val vault = NativeWalletVault(wrap, files)
        val state = vault.state()
        assertFalse("a readable invalid residue is not confirmed absent", state is NativeWalletVault.State.NoKey)
        assertFalse("the phrase does not verify", vault.phraseOnlyVerifies())
        assertEquals("unreadable", NoKeyGate.notReadyReasonOf(state, vault))
    }

    /** PHR-04: the residue phrase cannot be read: not_ready + unreadable, never no_key (the state is not NoKey, so no confirmed absence). */
    @Test
    fun phr04UnreadableResidueIsUnreadableNeverNoKey() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phrase), keyOf(phrase), phrase))
        files.map.remove(NativeWalletVault.REC)
        files.map[NativeWalletVault.MNEM] = "not a phrase record".toByteArray(Charsets.UTF_8)
        val vault = NativeWalletVault(wrap, files)
        val state = vault.state()
        assertFalse("unreadable residue is not confirmed absent", state is NativeWalletVault.State.NoKey)
        assertEquals("unreadable", NoKeyGate.notReadyReasonOf(state, vault))
    }
}
