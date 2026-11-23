package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

/**
 * Per-account key-only criterion and the device fail-closed fallback (2026-11-22). Synthetic values only. The three
 * inconsistent cases must refuse (keyOnlyClearRefused true) and leave every byte unchanged; a read failure only refuses.
 */
class KeyOnlyPerAccountTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /** One wrap key per test: the records written by a vault open only with the same wrap. */
    private val wrap = NativeTestWrap()

    private val fogPhrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val abandonPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p))).lowercase()

    private fun store(): MnemonicSetStore = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))

    /** A readable file store that fails on one name; everything else delegates. */
    private class ReadFailsFor(private val inner: NativeTestFiles, private val name: String) : VaultFiles by inner {
        override fun read(name: String): ByteArray? {
            if (name == this.name) throw IOException("read fault")
            return inner.read(name)
        }
    }

    /** Case 1: only a private key on the device, no other account, the key is the current account. */
    @Test
    fun onlyAPrivateKeyWithNoOtherAccountIsKeyOnlyAndNothingChanges() {
        val files = NativeTestFiles()
        val a = eoaOf(abandonPhrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(a, keyOf(abandonPhrase).copyOf()))
        val before = files.map.toMap()
        val vault = NativeWalletVault(wrap, files)
        assertTrue("the key-only account is refused for the clear",
            keyOnlyClearRefused(vault.keyWithoutPhraseFor(a, store()), PendingOwner.Absent, a))
        assertEquals("nothing is written or deleted by the criterion", before, files.map.toMap())
    }

    /** Case 2: a legacy wallet key with no phrase set at all, and no current account (the device fallback). */
    @Test
    fun aLegacyKeyWithNoPhraseSetAndNoCurrentAccountIsRefusedAndNothingChanges() {
        val files = NativeTestFiles()
        val a = eoaOf(abandonPhrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(a, keyOf(abandonPhrase).copyOf()))
        val before = files.map.toMap()
        val vault = NativeWalletVault(wrap, files)
        assertTrue("no current account with a key present is refused (fail closed)",
            keyOnlyClearRefused(vault.keyWithoutPhraseFor(null, store()), PendingOwner.Absent, null))
        assertEquals(before, files.map.toMap())
    }

    /** Case 3: two accounts. A has a phrase in the set store; the current account B holds only a key. B is refused, and A's set is untouched. */
    @Test
    fun withTwoAccountsTheCurrentKeyOnlyAccountIsRefusedAndNothingChanges() {
        val files = NativeTestFiles()
        val s = store()
        val a = eoaOf(fogPhrase)
        val b = eoaOf(abandonPhrase)
        assertTrue("A's phrase is in the set store", s.writePlain(a, fogPhrase) is MnemonicSetStore.Write.Stored)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(b, keyOf(abandonPhrase).copyOf()))
        val before = files.map.toMap()
        val vault = NativeWalletVault(wrap, files)
        assertTrue("B (key only) is refused although A has a phrase",
            keyOnlyClearRefused(vault.keyWithoutPhraseFor(b, s), PendingOwner.Absent, b))
        assertEquals(before, files.map.toMap())
        assertTrue("A's own set still answers for A", s.current() is MnemonicSetStore.Current.Found)
    }

    /** Positive control: an account whose phrase is in the vault is not key-only. */
    @Test
    fun anAccountWithItsPhraseInTheVaultIsNotKeyOnly() {
        val files = NativeTestFiles()
        val a = eoaOf(abandonPhrase)
        assertEquals(NativeWalletVault.Import.OK,
            NativeWalletVault(wrap, files).importMnemonicKey(a, keyOf(abandonPhrase), abandonPhrase))
        assertFalse(NativeWalletVault(wrap, files).keyWithoutPhraseFor(a, store()))
    }

    /** Positive control: an account whose phrase is in the set store is not key-only. */
    @Test
    fun anAccountWithItsPhraseInTheSetStoreIsNotKeyOnly() {
        val files = NativeTestFiles()
        val s = store()
        val a = eoaOf(fogPhrase)
        assertTrue(s.writePlain(a, fogPhrase) is MnemonicSetStore.Write.Stored)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(a, keyOf(fogPhrase).copyOf()))
        assertFalse(NativeWalletVault(wrap, files).keyWithoutPhraseFor(a, s))
    }

    /** A read failure of the key record or of the phrase only refuses; it never grants the clear. */
    @Test
    fun aReadFailureOnlyRefuses() {
        val inner = NativeTestFiles()
        val a = eoaOf(abandonPhrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, inner).importMnemonicKey(a, keyOf(abandonPhrase), abandonPhrase))
        for (failing in listOf(NativeWalletVault.REC, NativeWalletVault.MARK, NativeWalletVault.MNEM)) {
            val vault = NativeWalletVault(wrap, ReadFailsFor(inner, failing))
            assertTrue("a read failure of $failing refuses", keyWithoutPhraseFailClosed(vault, a))
        }
    }

    /**
     * A phrase read failure leaves the snapshot unknown (computeState throws), and the identity clear and the
     * unregister refuse; nothing is deleted and every byte is unchanged. The per-account criterion and the clear's own hold check both refuse.
     */
    @Test
    fun aPhraseReadFailureLeavesTheSnapshotUnknownAndTheClearRefusesWithoutChange() {
        val inner = NativeTestFiles()
        val a = eoaOf(abandonPhrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, inner).importMnemonicKey(a, keyOf(abandonPhrase), abandonPhrase))
        val before = inner.map.toMap()
        val failing = NativeWalletVault(wrap, ReadFailsFor(inner, NativeWalletVault.MNEM))
        assertTrue("the state read throws on the phrase read", runCatching { failing.state() }.isFailure)
        assertEquals("the snapshot stays unknown", null, failing.snapshotState())
        // The precheck with no current account (the snapshot is unknown) and with the account known: both refuse.
        assertTrue("no account known: refused", keyOnlyClearRefused(failing.keyWithoutPhraseFor(null, store()), PendingOwner.Absent, null))
        assertTrue("account known: refused", keyOnlyClearRefused(failing.keyWithoutPhraseFor(a, store()), PendingOwner.Absent, a))
        // The clear's own check: a held wallet with an unknown read answers unregister_refused and writes nothing.
        var wrote = false
        val ic = IdentityClear(
            flags = ClearFlagFiles(inner),
            holdsWallet = { null },
            eraseWallet = { wrote = true; true },
            eraseInbox = { wrote = true; true },
            reportLegacyAbsent = { wrote = true; true },
            clearPointer = { wrote = true; true },
        )
        assertEquals(IdentityClearCode.UNREGISTER_REFUSED, ic.clear())
        assertFalse("nothing is deleted or written", wrote)
        assertEquals("every byte is unchanged", before, inner.map.toMap())
    }

    private fun keyWithoutPhraseFailClosed(vault: NativeWalletVault, a: String): Boolean =
        keyOnlyClearRefused(vault.keyWithoutPhraseFor(a, store()), PendingOwner.Absent, a)
}
