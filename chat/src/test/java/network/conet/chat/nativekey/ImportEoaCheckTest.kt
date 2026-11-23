package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** importMnemonicKey checks that the EOA derived from the phrase is the account named by the caller (E7-1, E7-3 N4). */
class ImportEoaCheckTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val otherPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"

    @Test fun mismatchedEoaIsRefusedAndWritesNothing() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val key = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        val otherEoa = checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(otherPhrase))))
        assertEquals(NativeWalletVault.Import.BAD_KEY, NativeWalletVault(wrap, files).importMnemonicKey(otherEoa, key, phrase))
        assertTrue("nothing written", files.map.isEmpty())
    }

    @Test fun matchingEoaIsAccepted() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val key = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(key))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa.lowercase(), key, phrase))
    }
}
