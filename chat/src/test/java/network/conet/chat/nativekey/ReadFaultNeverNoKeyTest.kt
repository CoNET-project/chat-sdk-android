package network.conet.chat.nativekey

import java.io.File
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Negative (2026-11-20, lead request): an unknown read never answers walletStatus no_key and never opens account creation.
 * (a) A storage read fault on the wallet record, marker and phrase: the state read throws, the snapshot stays empty, and the walletStatus
 *     answer is not_ready (storageAnswer), never G0.
 * (b) The snapshot is empty while the refresh is backing off: the walletStatus route answers the storage answer before any gate is read.
 *
 * (c) Per the specification E9.1-3 (2026-11-17, confirmed 2026-11-20): a read fault on REC or MARK does not decide the
 *     answer; only a read fault on the phrase position is unknown. So REC/MARK faults with a phrase position that reads cleanly and is
 *     empty answer no_key, and a phrase-position read fault answers not_ready. The two cases are paired below.
 */
class ReadFaultNeverNoKeyTest {
    private val module: String by lazy {
        File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
    }

    @Test
    fun aReadFaultOnTheWalletRecordMarkerAndPhraseLeavesTheSnapshotEmpty() {
        val files = NativeTestFiles()
        files.failRead = { name -> name == NativeWalletVault.REC || name == NativeWalletVault.MARK || name == NativeWalletVault.MNEM }
        val vault = NativeWalletVault(NativeTestWrap(), files)
        try {
            vault.state()
            fail("a read fault must not be decided as a state")
        } catch (_: IOException) {
            // expected: the fault is unknown
        }
        assertNull("the snapshot stays empty after the fault", vault.snapshotWithKeyOnly())
        assertEquals(
            "walletStatus answers the storage answer, not a status",
            NoKeyGate.StorageAnswer.WALLET_STATUS_NOT_READY,
            NoKeyGate.storageAnswer("walletStatus", null),
        )
    }

    @Test
    fun theWalletStatusRouteAnswersTheStorageAnswerBeforeAnyGate() {
        // (b): with an empty snapshot the route returns the storage answer first; walletStatusFor (G0 no_key) is never reached.
        val route = module.substringAfter("NoKeyGate.Route.WALLET_STATUS -> {").substringBefore("NoKeyGate.Route.PASSCODE_STATUS -> {")
        val storage = module.indexOf("NoKeyGate.storageAnswer(type, snap)")
        val walletStatusFor = route.indexOf("NoKeyGate.walletStatusFor(statusGate, state")
        assertTrue("the storage answer exists before the module's routes", storage > 0)
        assertTrue("the walletStatus answer is after the adoption guard inside the route", walletStatusFor > 0)
        assertTrue(
            "the snapshot-null answer is in the shared path above the route",
            module.indexOf("if (snap == null) scheduleSnapshotRefresh(context)") in 0 until storage,
        )
    }

    /** E9.1-3: a REC or MARK read fault does not decide; the phrase position reads cleanly and is empty, so the state is NoKey (no_key). */
    @Test
    fun aRecAndMarkReadFaultWithAnEmptyPhrasePositionIsNoKey() {
        val files = NativeTestFiles()
        files.failRead = { name -> name == NativeWalletVault.REC || name == NativeWalletVault.MARK }
        val vault = NativeWalletVault(NativeTestWrap(), files)
        assertTrue("E9.1-3: the REC/MARK fault does not decide; the empty phrase position is no account", vault.state() is NativeWalletVault.State.NoKey)
    }

    /** E9.1-3: a read fault on the phrase position is unknown, so the snapshot stays empty and walletStatus answers not_ready. */
    @Test
    fun aPhrasePositionReadFaultIsNotReadyNeverNoKey() {
        val files = NativeTestFiles()
        files.failRead = { name -> name == NativeWalletVault.MNEM }
        val vault = NativeWalletVault(NativeTestWrap(), files)
        try {
            vault.state()
            fail("the phrase-position fault must not be decided as a state")
        } catch (_: IOException) {
            // expected: unknown
        }
        assertNull("the snapshot stays empty", vault.snapshotWithKeyOnly())
        assertEquals(NoKeyGate.StorageAnswer.WALLET_STATUS_NOT_READY, NoKeyGate.storageAnswer("walletStatus", null))
    }
}
