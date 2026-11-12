package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * P-MNEMONIC (spec 25.25.2 and the batch limit at 25.25, item 6): the native import takes a secp256k1 private key
 * only. A BIP-39 phrase is refused as `invalid_format` and no address is derived from it.
 *
 * The phrase is the public BIP-39 test vector ("abandon … about", entropy 00…00). The agreed derivation (English
 * list, no passphrase, path m/44'/60'/0'/0/0, account 0, the ethers v6 default) was checked with the repository's
 * ethers 6.16.0 `Wallet.fromPhrase`: private key 0x1ab42cc4…b727, address 0x9858EfFD…Eda94.
 */
class MnemonicRefusedTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseKeyHex = "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
    private val phraseEoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

    @Test
    fun aPhraseIsRefusedAsInvalidFormatAndNothingIsWritten() {
        val files = NativeTestFiles()
        val vault = NativeWalletVault(NativeTestWrap(), files)
        val r = NativeImport.submit(raw = phrase, expectedEoa = null, vault = vault)
        assertEquals(NativeImport.Code.INVALID_FORMAT, r.code)
        assertNull(r.eoa)
        assertTrue(vault.state() is NativeWalletVault.State.NoKey)
        assertFalse(files.map.containsKey(NativeWalletVault.REC))
        assertFalse(files.map.containsKey(NativeWalletVault.MARK))
    }

    @Test
    fun aPhraseIsNotMatchedEvenAgainstItsOwnAccount() {
        // The import was started for the phrase's account. The phrase is still not a key, so it is refused
        // before any address comparison.
        val vault = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val r = NativeImport.submit(raw = phrase, expectedEoa = phraseEoa, vault = vault)
        assertEquals(NativeImport.Code.INVALID_FORMAT, r.code)
        assertNull(r.eoa)
        assertTrue(vault.state() is NativeWalletVault.State.NoKey)
    }

    @Test
    fun aPhraseWithLineBreaksIsStillRefused() {
        val vault = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val r = NativeImport.submit(raw = "  " + phrase.replace(" ", "\n") + "\n", expectedEoa = null, vault = vault)
        assertEquals(NativeImport.Code.INVALID_FORMAT, r.code)
        assertTrue(vault.state() is NativeWalletVault.State.NoKey)
    }

    @Test
    fun theAccountKeyOfThePhraseImportsAsTheSameAccount() {
        // The key the agreed derivation gives for the public vector, typed as hex, is the same account. This ties
        // the native address derivation to the ethers result for the same vector.
        val files = NativeTestFiles()
        val vault = NativeWalletVault(NativeTestWrap(), files)
        val r = NativeImport.submit(raw = phraseKeyHex, expectedEoa = phraseEoa, vault = vault)
        assertEquals(NativeImport.Code.OK, r.code)
        assertEquals(phraseEoa, r.eoa?.lowercase())
        val state = vault.state()
        assertTrue(state is NativeWalletVault.State.Ready)
        assertEquals(phraseEoa, (state as NativeWalletVault.State.Ready).eoa.lowercase())
    }
}
