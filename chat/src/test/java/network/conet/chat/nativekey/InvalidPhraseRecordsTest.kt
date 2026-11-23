package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 2026-11-17 (item 2): a phrase record that is deterministically not a valid phrase is never taken for a valid one. Three classes:
 *  (1) BIP-39 checksum wrong, (2) derived EOA differs from the record's EOA (keyID), (3) truncated or out of the word list.
 * Each class sits at the fixed position (MNEM) and as an isolated copy. Deterministic invalidity answers "absent" (no phrase), never valid.
 */
class InvalidPhraseRecordsTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()
    private fun key() = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoa() = checkNotNull(WalletAddress.fromPrivateKey(key()))
    private val otherEoa = "0x1111111111111111111111111111111111111111"

    /** A phrase record sealed under [eoa] with the given plain text (the same envelope the vault writes). */
    private fun mnemRecord(eoa: String, text: String): ByteArray =
        JSONObject().put("record", NativeWalletVault.RECORD_VERSION).put("eoa", eoa)
            .put("sealed", ConetChatCryptoUtil.toHex(wrap.seal(NativeWalletVault.mnemAad(eoa), text.toByteArray(Charsets.UTF_8))))
            .toString().toByteArray(Charsets.UTF_8)

    private val classes: Map<String, Pair<String, String>> = mapOf(
        // (1) same word count and words, wrong checksum: twelve "abandon" (the valid last word is "about").
        "checksum" to (eoa() to "abandon ".repeat(11) + "abandon"),
        // (2) a valid phrase whose derived EOA is not the record's keyID.
        "eoaMismatch" to (otherEoa to phrase),
        // (3) truncated (eleven words), and a word outside the list.
        "truncated" to (eoa() to phrase.split(' ').dropLast(1).joinToString(" ")),
        "outOfList" to (eoa() to phrase.replace("about", "zzzzzz")),
    )

    /** The fixed position holds the invalid record (the marker is rewritten to match, as a settled write would leave it). */
    @Test fun invalidRecordAtTheFixedPositionIsNeverValid() {
        for ((name, c) in classes) {
            val files = NativeTestFiles()
            assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa(), key(), phrase))
            val rec = files.map.getValue(NativeWalletVault.REC)
            val mnem = mnemRecord(c.first, c.second)
            files.map[NativeWalletVault.MNEM] = mnem
            files.map[NativeWalletVault.MARK] = NativeWalletVault.markerOf(rec, mnem)
            NativeWalletVault.resetLaunchForTests()
            val v = NativeWalletVault(wrap, files)
            val verdict = v.phraseVerdict()
            assertNotEquals("$name: phrase verdict is not valid", NativeWalletVault.PhraseVerdict.VALID, verdict)
            val answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))
            assertTrue("$name: pre-read is not a valid phrase: $answer", answer !is MnemonicPreread.Answer.Valid)
            // 2026-11-17: at the fixed position an invalid phrase is not a normal account; walletStatus is no_key with a session too.
            val st = v.state()
            val status = NoKeyGate.walletStatusFor(NoKeyGate.walletStatusGate(st, sessionReady = true, keyOnly = v.isKeyOnlyAccount()), st)
            assertEquals("$name: walletStatus is no_key, not a normal account", "no_key", status.getString("status"))
        }
    }

    /** The same invalid record as an isolated copy only (the fixed names are empty): no valid phrase, the pre-read is absent. */
    @Test fun invalidRecordAsAnIsolatedCopyIsAbsentNeverValid() {
        for ((name, c) in classes) {
            val files = NativeTestFiles()
            files.map["${NativeWalletVault.MNEM}.isolated.20261117T000000Z.abcdef01"] = mnemRecord(c.first, c.second)
            NativeWalletVault.resetLaunchForTests()
            val v = NativeWalletVault(wrap, files)
            assertNotEquals("$name: phrase verdict is not valid", NativeWalletVault.PhraseVerdict.VALID, v.phraseVerdict())
            assertEquals("$name: pre-read is absent", MnemonicPreread.Answer.Absent, MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)))
            assertEquals("$name: walletStatus is no_key", "no_key",
                NoKeyGate.walletStatusFor(NoKeyGate.gateOf(v.state(), sessionReady = false), v.state()).getString("status"))
        }
    }
}
