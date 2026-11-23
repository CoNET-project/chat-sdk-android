package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The bridge answers of `pwaWalletSync` and `nativeMnemonicPreread` (r2.4.6 46(4) and 46(5)), and the gate routes that let them through. */
class NativeSyncAckTest {
    private val closedSync = setOf("ok", "stale_seq", "write_failed", "untrusted_source", "bad_request")

    @Test
    fun aRequestWithoutTheTrustedOriginMarkerIsUntrusted() {
        assertFalse(NativeSyncAck.trusted(JSONObject()))
        assertFalse(NativeSyncAck.trusted(JSONObject().put("trustedOrigin", "yes")))
        assertFalse(NativeSyncAck.trusted(JSONObject().put("trustedOrigin", false)))
        assertTrue(NativeSyncAck.trusted(JSONObject().put("trustedOrigin", true)))
        assertEquals("untrusted_source", NativeSyncAck.admit(JSONObject()))
        assertNull(NativeSyncAck.admit(JSONObject().put("trustedOrigin", true)))
    }

    /** R2 (r2.4.8): every outcome maps into the external closed set; the failures are write_failed with a fixed reason word. */
    @Test
    fun everyOutcomeMapsIntoTheClosedSetAndTheFailuresAreWriteFailedWithAReason() {
        for (o in NativeWalletVault.SyncOutcome.values()) {
            val a = NativeSyncAck.answerOf(o)
            assertTrue("$o -> ${a.code}", a.code in closedSync)
        }
        // r2.4.8 49(1): the internal states are write_failed with reason internal_state; a plain store failure has no reason.
        for (o in listOf(NativeWalletVault.SyncOutcome.NOT_READY, NativeWalletVault.SyncOutcome.READBACK_FAILED)) {
            assertEquals("$o", "write_failed", NativeSyncAck.answerOf(o).code)
            assertEquals("$o", "internal_state", NativeSyncAck.answerOf(o).reason)
        }
        // the two new reasons, and nothing else changes.
        assertEquals("write_failed", NativeSyncAck.answerOf(NativeWalletVault.SyncOutcome.OLD_COPY_UNVERIFIED).code)
        assertEquals("old_copy_unverified", NativeSyncAck.answerOf(NativeWalletVault.SyncOutcome.OLD_COPY_UNVERIFIED).reason)
        assertEquals("write_failed", NativeSyncAck.answerOf(NativeWalletVault.SyncOutcome.ROLLBACK_PENDING).code)
        assertEquals("rollback_pending", NativeSyncAck.answerOf(NativeWalletVault.SyncOutcome.ROLLBACK_PENDING).reason)
        assertEquals("storage_write", NativeSyncAck.answerOf(NativeWalletVault.SyncOutcome.WRITE_FAILED).reason)
        assertEquals("write_failed", NativeSyncAck.codeOf(NativeWalletVault.SyncOutcome.READBACK_FAILED))
        assertEquals("write_failed", NativeSyncAck.codeOf(NativeWalletVault.SyncOutcome.ROLLBACK_PENDING))
        assertEquals("bad_request", NativeSyncAck.answerOf(NativeWalletVault.SyncOutcome.BAD_INPUT).code)
        assertEquals("ok", NativeSyncAck.codeOf(NativeWalletVault.SyncOutcome.UPDATED))
        assertEquals("ok", NativeSyncAck.codeOf(NativeWalletVault.SyncOutcome.IDEMPOTENT))
        assertEquals("bad_request", NativeSyncAck.codeOf(NativeWalletVault.SyncOutcome.BAD_INPUT))
    }

    @Test
    fun successLabelsAreUpdatedAndIdempotent() {
        assertEquals("updated", NativeSyncAck.syncLabel(NativeWalletVault.SyncOutcome.UPDATED))
        assertEquals("idempotent", NativeSyncAck.syncLabel(NativeWalletVault.SyncOutcome.IDEMPOTENT))
        assertNull(NativeSyncAck.syncLabel(NativeWalletVault.SyncOutcome.WRITE_FAILED))
    }

    @Test
    fun thePreReadAnswerHasOnlyTheThreeStates() {
        // Code shape: ok with mnemonic, confirmed_missing, read_error; no eoa and no state field.
        val ok = NativeSyncAck.prereadResult(MnemonicPreread.Answer.Valid("0x" + "1".repeat(40), "p"))
        assertEquals("ok", ok.getString("code"))
        assertEquals("p", ok.getString("mnemonic"))
        assertFalse(ok.has("eoa"))
        assertEquals("confirmed_missing", NativeSyncAck.prereadResult(MnemonicPreread.Answer.Absent).getString("code"))
        assertEquals("read_error", NativeSyncAck.prereadResult(MnemonicPreread.Answer.Unknown).getString("code"))
    }

    /** LG-R24 on the actual outcome lines of every outcome: a line carries the outcome name, never a phrase or a key. */
    @Test
    fun everyOutcomeLogLineCarriesNoKeyMaterial() {
        for (o in NativeWalletVault.SyncOutcome.values()) {
            val line = NativeSyncAck.logLine(o)
            assertFalse(line, Regex("([a-z]+ ){11}[a-z]+").containsMatchIn(line))
            assertFalse(line, Regex("[0-9a-fA-F]{64}").containsMatchIn(line))
        }
    }

    /** IM-01 (r2.5.19 59(5)): the removed page-open name is an unknown name: unknown_command before the gate. */
    @Test
    fun theRemovedImportNameHasItsOwnRoute() {
        assertEquals(NoKeyGate.Route.UNKNOWN_NAME, NoKeyGate.route("nativeImportOpen"))
        assertEquals("unknown_command", network.conet.chat.BridgeCommandTable.UNKNOWN_COMMAND)
    }

    /** B2 (r2.4.8): pwaWalletSync passes the no-key gate (the handler checks trustedOrigin and the sequence). Every other command stays refused. */
    @Test
    fun theGateLetsOnlyTheSyncAndThePreReadThroughWithNoKey() {
        // r2.4.8 48(1): the sync runs on its own lifecycle route, not on the no-key list.
        assertEquals(NoKeyGate.Route.LIFECYCLE, NoKeyGate.route("pwaWalletSync"))
        assertEquals(NoKeyGate.Route.LIFECYCLE, NoKeyGate.route("pwaEmptySignal"))
        assertEquals(NoKeyGate.Route.PASS, NoKeyGate.route("nativeMnemonicPreread"))
        for (other in listOf("send", "historyLoad", "walletAddress", "gossipSign", "init", "provisionIdentity")) {
            assertEquals(other, NoKeyGate.Route.NO_KEY, NoKeyGate.route(other))
        }
    }

    /** (3)(a) with the optional eoa (spec 59(1)(a)): absent keeps the current behaviour; present must be well formed and equal the derived address. */
    @Test
    fun anEoaThatIsPresentMustNameTheDerivedAddress() {
        val derived = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
        assertNull("absent eoa changes nothing", NativeSyncAck.eoaRefusal(JSONObject(), derived))
        assertNull("the derived address, lower case", NativeSyncAck.eoaRefusal(JSONObject().put("eoa", derived), derived))
        assertEquals("another account", "bad_request",
            NativeSyncAck.eoaRefusal(JSONObject().put("eoa", "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"), derived))
        assertEquals("upper case hex is not the canonical form", "bad_request",
            NativeSyncAck.eoaRefusal(JSONObject().put("eoa", "0x9858EFFD232B4033E47D90003D41EC34ECAEDA94"), derived))
        assertEquals("too short", "bad_request", NativeSyncAck.eoaRefusal(JSONObject().put("eoa", "0x9858"), derived))
        assertEquals("not a string", "bad_request", NativeSyncAck.eoaRefusal(JSONObject().put("eoa", 1), derived))
        assertEquals("null is present and not a string", "bad_request",
            NativeSyncAck.eoaRefusal(JSONObject().put("eoa", JSONObject.NULL), derived))
    }

    /** Wiring guard: the command checks eoa after the derivation and before the sequence is accepted, so a refusal advances nothing. */
    @Test
    fun theCommandChecksEoaBeforeTheSequenceIsAccepted() {
        val src = java.io.File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        val start = src.indexOf("private fun pwaWalletSyncCommand(")
        assertTrue("command found", start >= 0)
        val body = src.substring(start, src.indexOf("private fun pwaEmptySignalCommand(", start))
        val check = body.indexOf("NativeSyncAck.eoaRefusal(body, eoa)")
        val accept = body.indexOf("MnemonicPreread.accept(seq)")
        assertTrue("eoa check present", check >= 0)
        assertTrue("eoa check before accept", check in 0 until accept)
    }
}
