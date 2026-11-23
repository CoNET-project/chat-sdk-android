package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.Callable
import java.util.concurrent.Executors

/**
 * keyOnlyLive() and state() share the observedNoPhrase flag and the snapshot; both are synchronized on the vault. Several threads alternate the two
 * calls on one vault: each keyOnlyLive() answer must be the account's own answer (a key-only account is always true, a phrase account always false),
 * and each state() answer must be Ready for the account.
 */
class KeyOnlyConcurrencyTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()

    private fun account(keyOnly: Boolean): NativeTestFiles {
        val files = NativeTestFiles()
        val k = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(k))
        if (keyOnly) {
            assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, k))
            files.map.remove(NativeWalletVault.MNEM)
        } else {
            assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa, k, phrase))
        }
        return files
    }

    private fun hammer(files: NativeTestFiles, keyOnly: Boolean) {
        val vault = NativeWalletVault(wrap, files)
        val pool = Executors.newFixedThreadPool(8)
        try {
            val jobs = (0 until 8).map { t ->
                pool.submit(Callable {
                    val bad = ArrayList<String>()
                    for (i in 0 until 200) {
                        if ((t + i) % 2 == 0) {
                            val kl = vault.keyOnlyLive()
                            if (kl != keyOnly) bad += "keyOnlyLive=$kl at $t/$i"
                        } else {
                            val st = vault.state()
                            if (st !is NativeWalletVault.State.Ready) bad += "state=$st at $t/$i"
                        }
                    }
                    bad
                })
            }
            val problems = jobs.flatMap { it.get() }
            assertTrue("no interleaved answer: ${problems.take(5)}", problems.isEmpty())
        } finally {
            pool.shutdown()
        }
    }

    @Test fun keyOnlyAccountAnswersKeyOnlyUnderConcurrentCalls() = hammer(account(keyOnly = true), keyOnly = true)

    @Test fun phraseAccountNeverAnswersKeyOnlyUnderConcurrentCalls() {
        val files = account(keyOnly = false)
        assertFalse(NativeWalletVault(wrap, files).keyOnlyLive())
        hammer(files, keyOnly = false)
    }
}
