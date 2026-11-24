package network.conet.chat.nativekey

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The not_ready answers of the lock family (shared vectors A-08, C-25, C-26, C-27): a missing
 * passcode package answers `not_ready` with the reason `passcode_not_provided` at the top level of the ack; a storage state that cannot be read answers
 * `not_ready` with no reason; the answer is never `locked` and no UI lock is read.
 */
class LockedAnswerVectorsTest {
    private val passcode = NativeWalletVault.State.Locked(NativeWalletVault.PASSCODE_REQUIRED)

    private fun vectors(): org.json.JSONArray =
        JSONObject(File("../spec/pgp-bridge-command-vectors.v1.json").readText(Charsets.UTF_8)).getJSONArray("cases")

    @Test
    fun thePasscodePackageCasesAnswerNotReadyWithTheTopLevelReasonExactlyAsTheVectorsSay() {
        val cases = vectors()
        var checked = 0
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("id") !in setOf("A-08", "C-25", "C-26", "C-27")) continue
            val want = c.getJSONObject("expect").getJSONObject("ack")
            val request = c.getJSONObject("request")
            assertTrue("${c.getString("id")}: the command is in the lock family", NoKeyGate.lockedAnswer(request.getString("type"), passcode) != null || request.getString("type") == "pgpDecryptInbound")
            val got = NoKeyGate.lockedAck(want.get("reqId"), passcode)
            assertEquals("${c.getString("id")} keys", want.keys().asSequence().toSet(), got.keys().asSequence().toSet())
            for (k in want.keys()) assertEquals("${c.getString("id")} $k", want.get(k), got.get(k))
            checked++
        }
        assertEquals("all four cases are in the vector file in use", 4, checked)
    }

    @Test
    fun aStorageStateThatCannotBeReadAnswersNotReadyWithNoReason() {
        for (reason in listOf("marker_missing", "unreadable", "record_missing", NativeWalletVault.DISCARD_PENDING, "rollback_pending")) {
            val ack = NoKeyGate.lockedAck("r1", NativeWalletVault.State.Locked(reason))
            assertEquals("not_ready", ack.getString("error"))
            assertFalse("no reason for an unreadable state ($reason)", ack.has("reason"))
            assertFalse(ack.getBoolean("ok"))
        }
        assertNull(NoKeyGate.lockedReasonTopLevel(NativeWalletVault.State.Ready("0x" + "ab".repeat(20))))
    }

    @Test
    fun noLockFamilyAnswerIsLockedAndTheFourEntriesAreInTheFamily() {
        for (cmd in listOf("pgpDecryptInbound", "pgpRestoreEvaluate", "pgpRestore", "pgpIdentityCreate")) {
            assertTrue("$cmd is in the lock family", cmd in NoKeyGate.LOCKED_FAMILY_COMMANDS)
        }
        assertEquals("not_ready", NoKeyGate.lockedAck(1, passcode).getString("error"))
        assertEquals("not_ready", PgpDecryptInbound.gateRefusal(NoKeyGate.Gate.G2, locked = true))
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertTrue(module.contains("emitEvent(NoKeyGate.lockedAck(reqId, state))"))
        assertTrue(module.contains("refuse(it, NoKeyGate.lockedReasonTopLevel(state))"))
        assertFalse("the inbound decrypt no longer answers locked", module.contains("?: return refuse(\"locked\")"))
    }

    @Test
    fun theRestoreCommandsAnswerAStoreSetWithoutItsKeyTheSameWay() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        val restore = module.substringAfter("private fun pgpRestoreCommand(").substringBefore("private val pgpMigrateWorker")
        assertTrue("a Locked vault answers through lockedAck", restore.contains("emitEvent(NoKeyGate.lockedAck(reqId, state))"))
        assertTrue("the store set answers through storeNotReadyAck", restore.contains("emitEvent(NoKeyGate.storeNotReadyAck(reqId, r.reason))"))
        assertFalse("no reason is nested in result any more for these two answers", restore.contains("NoKeyGate.notReadyResult(r.reason)") || restore.contains("notReadyResult(NoKeyGate.lockedReasonOf"))
    }

    // ---- C-31, C-32, C-33: a storage state that cannot be read ----------------------------------------------------------------------------

    @Test
    fun theStorageUnknownCasesAnswerNotReadyWithNoReasonForEveryNonPasscodeState() {
        val cases = vectors()
        var checked = 0
        // Every vault or store state that is not the missing passcode package: the fixtures each end supplies for itself.
        val vaultStates = listOf("marker_missing", "marker_mismatch", "unreadable", "record_missing", NativeWalletVault.DISCARD_PENDING, "rollback_pending", NativeWalletVault.PHRASE_ONLY)
            .map { NativeWalletVault.State.Locked(it) }
        val storeReasons = listOf("unreadable", "store_unreadable", "pointer_missing", "g1_uninitialized")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("id") !in setOf("C-31", "C-32", "C-33")) continue
            assertEquals("G2_storage_unknown", c.getString("gate"))
            val want = c.getJSONObject("expect").getJSONObject("ack")
            val type = c.getJSONObject("request").getString("type")
            for (state in vaultStates) {
                val got = NoKeyGate.lockedAck(want.get("reqId"), state)
                assertEquals("${c.getString("id")} vault $state keys", want.keys().asSequence().toSet(), got.keys().asSequence().toSet())
                for (k in want.keys()) assertEquals(want.get(k), got.get(k))
                assertTrue("$type is in the lock family", type in NoKeyGate.LOCKED_FAMILY_COMMANDS && NoKeyGate.lockedAnswer(type, state) != null)
            }
            // The store path (pgpRestoreEvaluate, pgpRestore): the same answer.
            if (type != "pgpIdentityCreate") for (reason in storeReasons) {
                val got = NoKeyGate.storeNotReadyAck(want.get("reqId"), reason)
                assertEquals(want.keys().asSequence().toSet(), got.keys().asSequence().toSet())
                for (k in want.keys()) assertEquals(want.get(k), got.get(k))
            }
            checked++
        }
        assertEquals(3, checked)
    }

    @Test
    fun theStoreSetWithoutItsKeyIsTheOnlyStoreStateThatCarriesTheReason() {
        val withReason = NoKeyGate.storeNotReadyAck("r", NoKeyGate.NOT_READY_PASSCODE_REQUIRED)
        assertEquals("passcode_not_provided", withReason.getString("reason"))
        assertEquals("not_ready", withReason.getString("error"))
        assertFalse(NoKeyGate.storeNotReadyAck("r", "unreadable").has("reason"))
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertTrue(module.contains("emitEvent(NoKeyGate.storeNotReadyAck(reqId, r.reason))"))
    }

    @Test
    fun pgpIdentityCreateForAStoreAccountIsAKnownGapNotAPass() {
        // C-27 and C-33 are verified for a vault account (the gate step answers them). For a store account the handler is the waiting_registration stub and
        // the gate of a vault with no record answers no_key first: not verified, listed as a gap in the receipt.
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertTrue(module.contains("\"pgpIdentityCreate\" -> pgpIdentityCreateWaiting(body)"))
    }
}
