package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 25.52Y.142 第 3 項 and 25.52Y.88 第 3 項: `nativeImportOpen` and `nativeRecoveryOpen` answer `ack {ok: true}` and open their page in G0, G1 and G2.
 * Their `not_ready` (ack only, once; no page, no event) comes from an unknown snapshot or a storage lock, never from the gate.
 */
class NativeEntryOpenGateTest {
    private class Host(private val isRegistered: Boolean = true) : NativeOpenRules.Host {
        var opened = 0
        override fun registered(): Boolean = isRegistered
        override fun open(reqId: Any): Boolean {
            opened++
            return true
        }
    }

    private val eoa = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    private val fields = listOf("type", "reqId")

    private fun open(command: String, host: Host, storageNotReady: Boolean, reqId: String = "r-1"): NativeOpenRules.Reply =
        // r2.3 41: nativeImportOpen is removed; the recovery page is the entry that remains.
        NativeOpenRules.recoveryOpen(fields, reqId, host, storageNotReady = storageNotReady)

    /** The gate rows: a no-key vault (G0), a readable key without and with a session (G1, G2), and a readable phrase without the key record. */
    private val rows: List<Pair<String, NativeWalletVault.State>> = listOf(
        "G0" to NativeWalletVault.State.NoKey,
        "G1" to NativeWalletVault.State.Ready(eoa),
        "G2" to NativeWalletVault.State.Ready(eoa),
        "phrase_only" to NativeWalletVault.State.Locked(NativeWalletVault.PHRASE_ONLY),
    )

    @Test fun bothEntriesOpenTheirPageAckOkInEveryGate() {
        for (command in listOf("recovery")) {
            for ((label, state) in rows) {
                val host = Host()
                val reply = open(command, host, NativeOpenRules.storageNotReady(state))
                assertTrue("$command $label ack ok", reply.ok)
                assertNull("$command $label no error", reply.error)
                assertEquals("$command $label opens the page once", 1, host.opened)
                val ack = NativeOpenRules.ackPayload("r-1", reply)
                assertTrue(ack.getBoolean("ok"))
                assertFalse("$command $label ack has no error field", ack.has("error"))
            }
        }
    }

    @Test fun anUnknownSnapshotAnswersNotReadyOnceWithoutAPageOrEvent() {
        for (command in listOf("recovery")) {
            val host = Host()
            val reply = open(command, host, NativeOpenRules.storageNotReady(null))
            val ack = NativeOpenRules.ackPayload("r-1", reply)
            assertEquals("$command ack type", "ack", ack.getString("type"))
            assertFalse("$command ok is false", ack.getBoolean("ok"))
            assertEquals("$command error", "not_ready", ack.getString("error"))
            assertFalse("$command has no page", ack.has("page"))
            assertNull("$command has no result event", reply.result)
            assertEquals("$command does not open the page", 0, host.opened)
        }
    }

    @Test fun aStorageLockAnswersNotReadyExceptForAPhraseOnlyRecord() {
        for (reason in listOf("unreadable", "rollback_pending", "marker_mismatch", "record_missing")) {
            assertTrue("locked $reason is a storage lock", NativeOpenRules.storageNotReady(NativeWalletVault.State.Locked(reason)))
        }
        assertFalse("phrase_only is has, not a lock", NativeOpenRules.storageNotReady(NativeWalletVault.State.Locked(NativeWalletVault.PHRASE_ONLY)))
        for (command in listOf("recovery")) {
            val host = Host()
            val reply = open(command, host, NativeOpenRules.storageNotReady(NativeWalletVault.State.Locked("unreadable")))
            assertEquals("$command storage lock", "not_ready", reply.error)
            assertEquals(0, host.opened)
        }
    }

    @Test fun anUnregisteredPageIsNotSupportedEvenWhenNotReady() {
        for (command in listOf("recovery")) {
            val host = Host(isRegistered = false)
            assertEquals("$command", "not_supported", open(command, host, storageNotReady = true).error)
            assertEquals(0, host.opened)
        }
    }

    @Test fun aCredentialFieldIsRefusedBeforeTheStorageCheck() {
        val reply = NativeOpenRules.recoveryOpen(listOf("type", "reqId", "privateKeyHex"), "r-1", Host(), storageNotReady = true)
        assertEquals("key_over_bridge_refused", reply.error)
    }
}
