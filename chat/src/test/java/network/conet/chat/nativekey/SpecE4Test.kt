package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Erratum E4 (spec-59e-errata-v3.3.1-E4.md, sha256 5f7dc9be…): the answers for the storage-derived Locked reasons. Each reason answers
 * the family commands not_ready once (never no_key, never locked); walletStatus answers not_ready / unreadable; the write path (pwaWalletSync)
 * answers write_failed with a reason: internal_state for a not-ready state, rollback_pending for an unfinished rollback, old_copy_unverified for an
 * unverifiable old copy (storage_write for a plain store failure). PHRASE_ONLY is valid (not Locked): it is not answered
 * as not_ready on the family commands.
 */
class SpecE4Test {
    // The storage-derived Locked reasons that the family commands see (E4). rollback_pending here is the store lock as the family commands judge it
    // (not_ready once). It is NOT an on-the-wire word of the pwaWalletSync reasons: the wire reason for an unfinished rollback is rollback_pending
    // only on write_failed, and the family commands never emit it. The wire vocabulary is tested in NativeSyncAckTest and SpecV32Test.
    private val storageReasons = listOf("rollback_pending", "DISCARD_PENDING", "record_missing", "marker_missing", "marker_mismatch", "unreadable")
    private val family = listOf("pgpRestoreEvaluate", "pgpRestore", "pgpIdentityCreate")

    @Test fun eachStorageLockAnswersTheFamilyCommandsNotReadyOnce() {
        for (reason in storageReasons) {
            for (cmd in family) {
                assertEquals("$reason $cmd", NoKeyGate.NOT_READY, NoKeyGate.lockedAnswer(cmd, NativeWalletVault.State.Locked(reason)))
            }
        }
    }

    @Test fun walletStatusForAStorageLockIsNotReadyUnreadable() {
        for (reason in storageReasons) {
            assertEquals(NoKeyGate.StorageAnswer.WALLET_STATUS_NOT_READY, NoKeyGate.storageAnswer("walletStatus", NativeWalletVault.State.Locked(reason)))
        }
        val answer = NoKeyGate.walletStatusUnreadable()
        assertEquals("not_ready", answer.getString("status"))
        assertEquals("unreadable", answer.getString("notReadyReason"))
    }

    @Test fun aStorageLockIsNotNoKeyOrLocked() {
        for (reason in storageReasons) for (cmd in family) {
            val code = NoKeyGate.lockedAnswer(cmd, NativeWalletVault.State.Locked(reason))
            assertEquals(false, code == "no_key" || code == "locked")
        }
    }

    // E5 (spec-59e-errata-v3.3.1-E5.md, sha256 a97ae8e4…): PHRASE_ONLY is a storage-derived residue. The family commands answer not_ready
    // once; walletStatus answers locked + phrase_only on G2 (with the pointer account), not_ready g1_uninitialized on G1 and not_ready
    // unreadable with an empty pointer; nativeMnemonicPreread and nativeState are valid; pwaWalletSync is write_failed / internal_state.
    @Test fun phraseOnlyFamilyCommandsAreNotReadyOnce() {
        val phraseOnly = NativeWalletVault.State.Locked(NativeWalletVault.PHRASE_ONLY)
        for (cmd in listOf("pgpRestoreEvaluate", "pgpRestore", "pgpIdentityCreate")) {
            assertEquals(cmd, NoKeyGate.NOT_READY, NoKeyGate.lockedAnswer(cmd, phraseOnly))
        }
    }

    @Test fun phraseOnlyWalletStatusIsLockedWithThePointerAccount() {
        val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
        val g2 = NoKeyGate.phraseOnlyWalletStatus(eoa)
        assertEquals("locked", g2.getString("status"))
        assertEquals("phrase_only", g2.getString("reason"))
        assertTrue(g2.has("accountKey"))
        assertEquals("not_ready", NoKeyGate.phraseOnlyWalletStatus(null).getString("status"))
        assertEquals("unreadable", NoKeyGate.phraseOnlyWalletStatus(null).getString("notReadyReason"))
        assertEquals("g1_uninitialized", NoKeyGate.notReadyReasonOf(NativeWalletVault.State.Locked(NativeWalletVault.PHRASE_ONLY)))
    }

    /**
     * SO-26 (E5.1, spec-59e-synthetic-vectors.v3.3.1-E5.1-add.json, sha256 76941a58…): PHRASE_ONLY + pwaWalletSync → write_failed /
     * internal_state for the same account and for a different account (no idempotent success on the same account); the residue bytes are
     * unchanged; nativeState reads back valid; no audit row, no deletion, no intent marker; the answer is repeatable (retryable).
     */
    @Test fun so26_phraseOnlyPwaWalletSyncIsWriteFailedForBothAccountsAndChangesNothing() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val residue = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val resKey = checkNotNull(MnemonicDerivation.deriveKey(residue))
        NativeWalletVault(wrap, files).importMnemonicKey(checkNotNull(WalletAddress.fromPrivateKey(resKey)), resKey, residue)
        files.map.remove(NativeWalletVault.REC) // the key record is gone; the phrase record stays (PHRASE_ONLY)
        val v = NativeWalletVault(wrap, files)
        assertTrue("phrase-only: ${v.state()}", v.state() is NativeWalletVault.State.Locked && (v.state() as NativeWalletVault.State.Locked).reason == NativeWalletVault.PHRASE_ONLY)
        val before = files.map.mapValues { it.value.copyOf() }
        val other = "legal winner thank year wave sausage worth useful legal winner thank yellow"
        val otherKey = checkNotNull(MnemonicDerivation.deriveKey(other))
        repeat(2) {
            // 1: the same account (same phrase) - no idempotent success
            assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, v.syncPhrase(checkNotNull(WalletAddress.fromPrivateKey(resKey)), resKey, residue))
            // 2: a different account
            assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, v.syncPhrase(checkNotNull(WalletAddress.fromPrivateKey(otherKey)), otherKey, other))
        }
        assertEquals("write_failed", NativeSyncAck.codeOf(NativeWalletVault.SyncOutcome.NOT_READY))
        assertEquals("internal_state", NativeSyncAck.answerOf(NativeWalletVault.SyncOutcome.NOT_READY).reason)
        // The residue is unchanged; no audit row, no deletion, no intent marker.
        assertEquals(before.keys, files.map.keys)
        before.forEach { (name, bytes) -> assertTrue(name, bytes.contentEquals(files.map[name])) }
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
        // SO-26 (E5.1-add): no intent marker, no audit row, nothing deleted (the key set is unchanged, checked above).
        assertFalse("no intent marker", files.map.containsKey(NativeWalletVault.INTENT))
        assertFalse("no audit row", files.map.containsKey(NativeWalletVault.AUDIT))
        // nativeState reads back valid.
        assertEquals("valid", v.nativeStateLabel())
    }
}
