package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * rc2.2-qa item 3 (25.52Y.88): the answer while the snapshot is unknown or the store is storage-derived
 * Locked. One test per class: A lifecycle and status, B page-open entries, C family commands, D historical reads, E other keystore
 * commands, and G0 `no_key` (unchanged).
 */
class NoKeyStorageAnswerTest {
    private val unknown: NativeWalletVault.State? = null
    private val locked: NativeWalletVault.State = NativeWalletVault.State.Locked("record_missing")
    private val noKey: NativeWalletVault.State = NativeWalletVault.State.NoKey
    private val ready: NativeWalletVault.State = NativeWalletVault.State.Ready("0x" + "a".repeat(40))

    /** A. Lifecycle commands answer before the gate, so the storage answer does not decide them. */
    @Test
    fun classA_lifecycleIsNotDecidedByTheStorageAnswer() {
        for (name in listOf("hello", "pause", "resume", "destroy")) {
            assertNull("$name with unknown snapshot", NoKeyGate.storageAnswer(name, unknown))
            assertNull("$name with storage lock", NoKeyGate.storageAnswer(name, locked))
        }
    }

    /** A. passcodeStatus answers its status while the snapshot is unknown (NK-S2 shape), not not_ready. */
    @Test
    fun classA_passcodeStatusAnswersStatusWhenSnapshotIsUnknown() {
        assertEquals(NoKeyGate.StorageAnswer.PASSCODE_UNKNOWN, NoKeyGate.storageAnswer("passcodeStatus", unknown))
        val r = NoKeyGate.passcodeStatusUnknown()
        assertFalse("status is not the not_ready ack", r.has("status"))
        assertTrue(r.getBoolean("hasKey"))
        assertEquals("not_ready", r.getString("walletState"))
        assertEquals(setOf("set", "locked", "hasKey", "walletState"), r.keys().asSequence().toSet())
        // A storage lock keeps the known-state answer (hasKey true from the gate).
        assertNull(NoKeyGate.storageAnswer("passcodeStatus", locked))
    }

    /** A. walletStatus: not_ready with the unreadable reason, never g1_uninitialized. */
    @Test
    fun classA_walletStatusCarriesUnreadableReason() {
        assertEquals(NoKeyGate.StorageAnswer.WALLET_STATUS_NOT_READY, NoKeyGate.storageAnswer("walletStatus", unknown))
        assertEquals(NoKeyGate.StorageAnswer.WALLET_STATUS_NOT_READY, NoKeyGate.storageAnswer("walletStatus", locked))
        val r = NoKeyGate.walletStatusUnreadable()
        assertEquals("not_ready", r.getString("status"))
        assertEquals("unreadable", r.getString("notReadyReason"))
    }

    /** B. The three page-open entries are not_ready once with an unknown snapshot or a storage lock. The payload is not read. */
    @Test
    fun classB_pageOpenEntriesAreNotReadyWhenUnknownOrLocked() {
        for (name in NoKeyGate.PAGE_OPEN) {
            assertEquals("$name unknown", NoKeyGate.StorageAnswer.ACK_NOT_READY, NoKeyGate.storageAnswer(name, unknown))
            assertEquals("$name locked", NoKeyGate.StorageAnswer.ACK_NOT_READY, NoKeyGate.storageAnswer(name, locked))
        }
    }

    /** B. A known G0 snapshot lets the page-open entries continue (G0 create is never no_key). */
    @Test
    fun classB_pageOpenEntriesContinueWithAKnownNoKeyState() {
        for (name in NoKeyGate.PAGE_OPEN) {
            assertNull("$name with no key", NoKeyGate.storageAnswer(name, noKey))
        }
    }

    /** C. Family commands (25.22.4) and the identity reads are not_ready once while unknown or locked. */
    @Test
    fun classC_familyCommandsAreNotReadyOnceWhenUnknownOrLocked() {
        for (name in listOf("walletSignMessage", "pgpRestoreEvaluate", "pgpRestore", "pgpIdentityCreate", "provisionIdentity", "identityPublic")) {
            assertEquals("$name unknown", NoKeyGate.StorageAnswer.ACK_NOT_READY, NoKeyGate.storageAnswer(name, unknown))
            assertEquals("$name locked", NoKeyGate.StorageAnswer.ACK_NOT_READY, NoKeyGate.storageAnswer(name, locked))
        }
    }

    /** D. Historical reads answer ok:true with source not_ready and no data (25.52DL.1), under unknown and under a storage lock. */
    @Test
    fun classD_historicalReadsReturnSourceNotReadyNotAnError() {
        for (name in listOf("historyRead", "historyLoad", "historyLoadOlder", "historyOpenConversation")) {
            assertEquals("$name unknown", NoKeyGate.StorageAnswer.HISTORY_SOURCE_NOT_READY, NoKeyGate.storageAnswer(name, unknown))
            assertEquals("$name locked", NoKeyGate.StorageAnswer.HISTORY_SOURCE_NOT_READY, NoKeyGate.storageAnswer(name, locked))
        }
        val r = NoKeyGate.historySourceNotReady()
        assertEquals(setOf("source"), r.keys().asSequence().toSet())
        assertEquals("not_ready", r.getString("source"))
    }

    /** E. Other keystore commands are not_ready once; clearIdentity keeps its redo path under a storage lock. */
    @Test
    fun classE_otherKeystoreCommandsAreNotReadyOnce() {
        for (name in listOf("send", "sendGroup", "ackInbound", "mailboxCommand", "voiceFrame", "queryPresence", "queryNativeWake")) {
            assertEquals("$name unknown", NoKeyGate.StorageAnswer.ACK_NOT_READY, NoKeyGate.storageAnswer(name, unknown))
            assertEquals("$name locked", NoKeyGate.StorageAnswer.ACK_NOT_READY, NoKeyGate.storageAnswer(name, locked))
        }
        assertEquals(NoKeyGate.StorageAnswer.ACK_NOT_READY, NoKeyGate.storageAnswer("clearIdentity", unknown))
        assertNull("clearIdentity under a storage lock keeps the clear redo", NoKeyGate.storageAnswer("clearIdentity", locked))
    }

    /** G0. A known snapshot with no key: no_key, as before. The storage answer does not change it. */
    @Test
    fun classG0_knownNoKeyStillAnswersNoKey() {
        assertNull(NoKeyGate.storageAnswer("send", noKey))
        assertNull(NoKeyGate.storageAnswer("historyRead", noKey))
        assertEquals(NoKeyGate.NO_KEY, NoKeyGate.answerFor("send", NoKeyGate.Gate.G0))
        assertEquals(NoKeyGate.NO_KEY, NoKeyGate.answerFor("historyRead", NoKeyGate.Gate.G0))
    }

    /** A known, readable record is decided by the gate, not by the storage answer. */
    @Test
    fun knownReadyStateIsDecidedByTheGate() {
        assertNull(NoKeyGate.storageAnswer("send", ready))
        assertNull(NoKeyGate.storageAnswer("historyRead", ready))
        assertNull(NoKeyGate.storageAnswer("walletStatus", ready))
    }
}
