package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 *  (2026-11-17, alignment v2): a private key is not an account. The internal state may still read the key record (Ready), and every
 * external answer must not treat it as an account. This test walks each external surface for a key-only account and asserts what it answers.
 * Surfaces: the pre-read (absent), walletStatus (no_key, via the 31(3) rule of the module: a Ready key-only state on the walletStatus route is G0),
 * the family commands (G1: not_ready, never an account), and the pwaWalletSync path (the key record is not an eligible old account, so no
 * rollback protection (b) applies; the record is kept).
 */
class KeyOnlyExternalSurfacesTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val other = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val wrap = NativeTestWrap()

    private fun keyOnly(files: NativeTestFiles) {
        val k = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(checkNotNull(WalletAddress.fromPrivateKey(k)), k))
        assertFalse(files.map.containsKey(NativeWalletVault.MNEM))
    }

    @Test fun preReadAnswersAbsentNotAnAccount() {
        val files = NativeTestFiles()
        keyOnly(files)
        assertEquals(MnemonicPreread.Answer.Absent, MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)))
    }

    @Test fun walletStatusAnswersNoKeyOnTheWalletStatusRoute() {
        val files = NativeTestFiles()
        keyOnly(files)
        val vault = NativeWalletVault(wrap, files)
        val state = vault.state()
        assertTrue("internal state reads the key record: $state", state is NativeWalletVault.State.Ready)
        assertTrue("the snapshot knows it is key-only", vault.snapshotKeyOnly())
        // The module's walletStatus route: G1 with the key-only flag becomes G0 (no_key), see BeamioConetChatModule (31(3), PK-03).
        assertEquals("no_key", NoKeyGate.walletStatusFor(NoKeyGate.Gate.G0, state).getString("status"))
    }

    @Test fun familyCommandsAreNotReadyNotAnAccountWithoutASession() {
        val files = NativeTestFiles()
        keyOnly(files)
        val state = NativeWalletVault(wrap, files).state()
        // No session: the gate is G1 (not_ready). It is never G2 (the account gate) for a key-only state without a session.
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.gateOf(state, sessionReady = false))
        //  (c): a key-only record has no verified phrase, so it is key_only (not g1_uninitialized).
        assertEquals("key_only", NoKeyGate.notReadyReasonOf(state, NativeWalletVault(wrap, files)))
    }

    @Test fun aPwaSyncOverAKeyOnlyRecordIsNotAnEligibleOldAccount() {
        // The key record is not an old account that a rollback protection (b) must keep: the sync writes the new account through the existing
        // write spec (the key record is isolated, not deleted). The answer is not an idempotent success for the other account.
        val files = NativeTestFiles()
        keyOnly(files)
        val before = files.names().associateWith { files.read(it)!! }
        val k2 = checkNotNull(MnemonicDerivation.deriveKey(other))
        val outcome = NativeWalletVault(wrap, files).syncPhrase(checkNotNull(WalletAddress.fromPrivateKey(k2)), k2, other)
        assertFalse("not an idempotent success for the key-only account", outcome == NativeWalletVault.SyncOutcome.IDEMPOTENT)
        // Every key byte string is still held somewhere (under its name or as an isolated copy).
        val held = files.names().mapNotNull { files.read(it) }.map { it.toList() }.toSet()
        before.values.forEach { b -> assertTrue("the key record bytes are still held", held.contains(b.toList())) }
        assertNotNull(files.read(NativeWalletVault.REC) ?: files.names().firstOrNull { it.contains(".isolated.") })
    }

    /** The session flag does not make a key-only account an account: G1 whatever the session says (the gate is decided by the keyOnly argument). */
    @Test fun sessionReadyDoesNotMakeAKeyOnlyAccountG2() {
        val files = NativeTestFiles()
        keyOnly(files)
        val state = NativeWalletVault(wrap, files).state()
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.gateOf(state, sessionReady = true, keyOnly = true))
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.gateOf(state, sessionReady = false, keyOnly = true))
        assertTrue("key-only is not ready for the account gate: a session flag cannot change it", NoKeyGate.gateOf(state, sessionReady = true, keyOnly = true) != NoKeyGate.Gate.G2)
        assertTrue("the vault knows it is a key-only account", NativeWalletVault(wrap, files).isKeyOnlyAccount())
    }

    /** The module's walletStatus route maps G1 with the key-only flag to G0 (no_key); a session flag does not change that. */
    @Test fun walletStatusRouteAnswersNoKeyWhateverTheSession() {
        val files = NativeTestFiles()
        keyOnly(files)
        val vault = NativeWalletVault(wrap, files)
        val state = vault.state()
        for (ready in listOf(false, true)) {
            val gate = NoKeyGate.gateOf(state, sessionReady = ready, keyOnly = vault.snapshotKeyOnly())
            val routed = if (gate == NoKeyGate.Gate.G1 && vault.snapshotKeyOnly()) NoKeyGate.Gate.G0 else gate
            assertEquals("no_key for sessionReady=$ready", "no_key", NoKeyGate.walletStatusFor(routed, state).getString("status"))
        }
    }

    /** pwaWalletSync over a key-only record: the exact result is UPDATED (the write spec), not an idempotent success and not a protected rollback. */
    @Test fun pwaSyncOverKeyOnlyIsUpdatedExactly() {
        val files = NativeTestFiles()
        keyOnly(files)
        val k2 = checkNotNull(MnemonicDerivation.deriveKey(other))
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, NativeWalletVault(wrap, files).syncPhrase(checkNotNull(WalletAddress.fromPrivateKey(k2)), k2, other))
    }

    /** Regression: an account with a valid phrase keeps its gate (G2 with a session) and is not key-only; its unlock and family gate are unchanged. */
    @Test fun phraseAccountGateIsUnchanged() {
        val files = NativeTestFiles()
        val k = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        val eoa = checkNotNull(WalletAddress.fromPrivateKey(k))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa, k, phrase))
        val vault = NativeWalletVault(wrap, files)
        val state = vault.state()
        assertFalse("a phrase account is not key-only", vault.isKeyOnlyAccount())
        assertEquals(NoKeyGate.Gate.G2, NoKeyGate.gateOf(state, sessionReady = true, keyOnly = vault.snapshotKeyOnly()))
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.gateOf(state, sessionReady = false, keyOnly = vault.snapshotKeyOnly()))
        assertNotNull(vault.unlock())
    }
}
