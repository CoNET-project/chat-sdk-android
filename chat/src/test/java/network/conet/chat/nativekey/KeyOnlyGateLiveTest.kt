package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Key-only gate (the startup classification ), the live flag, and the account resolver:
 *  - walletStatusGate: a key-only Ready is G0 (no_key) on the walletStatus route whatever the session says; a phrase account is unchanged;
 *  - keyOnlyLive reads the records, while the snapshot flag can be stale when the records change outside the vault;
 *  - ShellRecordAccounts.resolve with keyOnly=true and sessionReady=true does not answer an account for a key-only record.
 */
class KeyOnlyGateLiveTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()

    private fun keyOnly(files: NativeTestFiles): String {
        val k = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(k))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, k))
        files.map.remove(NativeWalletVault.MNEM)
        return eoa.lowercase()
    }

    private fun phraseAccount(files: NativeTestFiles): String {
        val k = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(k))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa, k, phrase))
        return eoa.lowercase()
    }

    @Test fun walletStatusRouteIsNoKeyForAKeyOnlyAccountWhateverTheSession() {
        val files = NativeTestFiles()
        keyOnly(files)
        val vault = NativeWalletVault(wrap, files)
        val state = vault.state()
        assertEquals(NoKeyGate.Gate.G0, NoKeyGate.walletStatusGate(state, sessionReady = true, keyOnly = true))
        assertEquals(NoKeyGate.Gate.G0, NoKeyGate.walletStatusGate(state, sessionReady = false, keyOnly = true))
    }

    @Test fun phraseAccountWalletStatusRouteIsUnchanged() {
        val files = NativeTestFiles()
        phraseAccount(files)
        val vault = NativeWalletVault(wrap, files)
        val state = vault.state()
        assertFalse(vault.keyOnlyLive())
        assertEquals(NoKeyGate.Gate.G2, NoKeyGate.walletStatusGate(state, sessionReady = true, keyOnly = false))
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.walletStatusGate(state, sessionReady = false, keyOnly = false))
    }

    @Test fun keyOnlyLiveSeesAChangeThatTheSnapshotDoesNotYet() {
        // The records change outside the vault after the snapshot was read: the snapshot still says phrase account, the live read says key-only.
        val files = NativeTestFiles()
        phraseAccount(files)
        val vault = NativeWalletVault(wrap, files)
        vault.state()
        assertFalse("the snapshot is a phrase account", vault.snapshotKeyOnly())
        // The phrase item is removed and the marker is rewritten for the key-only shape (a store change made outside the vault).
        val rec = files.map[NativeWalletVault.REC]!!
        files.map.remove(NativeWalletVault.MNEM)
        files.map[NativeWalletVault.MARK] = NativeWalletVault.markerOf(rec, null)
        assertFalse("the snapshot flag is stale", vault.snapshotKeyOnly())
        assertTrue("the live flag reads the records", vault.keyOnlyLive())
    }

    @Test fun resolverDoesNotAnswerAnAccountForAKeyOnlyRecordWithASession() {
        val files = NativeTestFiles()
        val eoa = keyOnly(files)
        val state = NativeWalletVault(wrap, files).state()
        val answer = ShellRecordAccounts.resolve(
            vault = state,
            sessionReady = true,
            sessionGate = false,
            bound = null,
            copyNames = { emptyList() },
            storeOf = { error("no page copy in this test ($it)") },
            keyOnly = true,
        )
        assertFalse("not an account: $answer", answer is ShellRecordAccount.Ready && (answer as ShellRecordAccount.Ready).toString().contains(eoa))
        assertEquals(ShellRecordAccount.Unknown, answer)
    }
}
