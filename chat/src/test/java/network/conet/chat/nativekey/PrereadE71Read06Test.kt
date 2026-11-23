package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * E7.1-06 (spec-59e-synthetic-vectors.v3.3.1-E7.1-add.json, applicable on Android: a read failure at any position is unknown). Android has one
 * phrase position (wallet.v1.mnem) and the records that decide it (wallet.v1.rec, wallet.v1.ok). A read exception at any of them is unknown and
 * never absent. Mapping: MnemonicPreread.vaultAnswerOrUnknown (MnemonicPreread.kt:116-120) turns any thrown read into Answer.Unknown; a read that
 * returns no bytes for the phrase item is handled by NativeWalletVault.phraseVerdict (NativeWalletVault.kt:653).
 */
class PrereadE71Read06Test {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()

    private class FailingOn(val inner: NativeTestFiles, val name: String) : VaultFiles {
        override fun read(name: String): ByteArray? {
            if (name == this.name) throw IOException("read failed: $name")
            return inner.read(name)
        }
        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)
        override fun delete(name: String) = inner.delete(name)
        override fun names(): List<String> = inner.names()
        override fun rename(from: String, to: String) = inner.rename(from, to)
    }

    private fun account(): NativeTestFiles {
        val files = NativeTestFiles()
        val k = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(checkNotNull(WalletAddress.fromPrivateKey(k)), k, phrase))
        return files
    }

    /** E9.1: a read failure of the phrase position is unknown. REC and MARK are not read by the pre-read, so their failure does not change the answer. */
    @Test fun e7106_aPhraseReadFailureIsUnknownAndRecordFailuresDoNotDecide() {
        val inner = account()
        assertEquals("a read failure of the mnemonic item", MnemonicPreread.Answer.Unknown,
            MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, FailingOn(inner, NativeWalletVault.MNEM))))
        for (name in listOf(NativeWalletVault.REC, NativeWalletVault.MARK)) {
            val answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, FailingOn(account(), name)))
            assertTrue("a read failure of $name does not decide the answer: $answer", answer is MnemonicPreread.Answer.Valid)
        }
    }
}
