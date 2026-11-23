package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * r2.5.17 31(3) and PK-03: a readable key record with no phrase is not an account, so walletStatus is no_key (absent), not not_ready with
 * g1_uninitialized. A record with a phrase is unchanged: not_ready with g1_uninitialized. The keyed snapshot flag is read on the reader's thread,
 * never on the caller's thread.
 */
class KeyOnlyWalletStatusTest {
    private val nativePhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    @Test
    fun aKeyOnlyRecordIsNoKeyForWalletStatus() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap() // one key wrap for both vault instances
        val k = checkNotNull(MnemonicDerivation.deriveKey(nativePhrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(k))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, k))
        val vault = NativeWalletVault(wrap, files)
        val state = vault.state()
        assertTrue("readable key record: $state", state is NativeWalletVault.State.Ready)
        assertTrue("the snapshot knows it has no phrase", vault.snapshotKeyOnly())
        // The module's status answer uses the status gate G0 for this case (PK-03): no_key.
        assertEquals("no_key", NoKeyGate.walletStatusFor(NoKeyGate.Gate.G0, state).getString("status"))
    }

    @Test
    fun aRecordWithAPhraseKeepsNotReadyG1() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val k = checkNotNull(MnemonicDerivation.deriveKey(nativePhrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(k))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa, k, nativePhrase))
        val vault = NativeWalletVault(wrap, files)
        val state = vault.state()
        assertFalse("a phrase is held", vault.snapshotKeyOnly())
        val status = NoKeyGate.walletStatusFor(NoKeyGate.gateOf(state, sessionReady = false), state)
        assertEquals("not_ready", status.getString("status"))
        assertEquals("g1_uninitialized", status.getString("notReadyReason"))
    }

    /**
     * Review: a phrase record that is present but unreadable (corrupt bytes in MNEM) is unknown: walletStatus is not_ready with
     * unreadable, never no_key. The key-only flag is false (the snapshot is not Ready), so the status gate stays G1.
     */
    @Test
    fun aCorruptPhraseRecordIsNotReadyUnreadableNotNoKey() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val k = checkNotNull(MnemonicDerivation.deriveKey(nativePhrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(k))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa, k, nativePhrase))
        files.write(NativeWalletVault.MNEM, ByteArray(64) { 0x5A })
        val vault = NativeWalletVault(wrap, files)
        val state = vault.state()
        assertFalse("not a readable key with no phrase", vault.snapshotKeyOnly())
        // The probe: the corrupt phrase record makes the state Locked(marker_mismatch), not a readable key (31(3) does not apply). It is not_ready,
        // with the reason the implementation gives for a locked or unreadable record (unreadable, 31(3) and 25.52Y.42 第 4 項 (c) r3oc). Never no_key.
        assertTrue("locked, not a readable key: $state", state is NativeWalletVault.State.Locked)
        val status = NoKeyGate.walletStatusFor(NoKeyGate.gateOf(state, sessionReady = false), state)
        assertEquals("not_ready", status.getString("status"))
        assertEquals("unreadable", status.getString("notReadyReason"))
        assertFalse("never no_key", status.getString("status") == "no_key")
    }

    /** The state and the key-only flag come from one snapshot read (no window between two reads). */
    @Test
    fun theStateAndTheFlagComeFromOneSnapshot() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val k = checkNotNull(MnemonicDerivation.deriveKey(nativePhrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(k))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, k))
        val vault = NativeWalletVault(wrap, files)
        assertEquals(null, vault.snapshotWithKeyOnly())
        vault.state()
        val snap = checkNotNull(vault.snapshotWithKeyOnly())
        assertTrue(snap.state is NativeWalletVault.State.Ready)
        assertTrue(snap.keyOnly)
    }
}
