package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Y.83 (25.52Y.83): Locked(marker_missing) and Locked(record_missing) are a storage-derived lock (25.52CS.2), not a passcode lock. The family commands
 * answer not_ready exactly once; walletStatus carries notReadyReason unreadable; never no_key, never locked. Gate rules, rule-level.
 */
class LockedStateGateTest {
    private val reasons = listOf("marker_missing", "record_missing")

    @Test
    fun aLockedRecordIsGateG1NotG0() {
        for (r in reasons) {
            assertEquals("$r is not no key", NoKeyGate.Gate.G1, NoKeyGate.gateOf(NativeWalletVault.State.Locked(r), sessionReady = false))
        }
    }

    @Test
    fun aFamilyCommandAnswersNotReadyNeverNoKeyOrLocked() {
        for (r in reasons) {
            val gate = NoKeyGate.gateOf(NativeWalletVault.State.Locked(r), sessionReady = false)
            assertEquals("$r: a family command is not_ready", "not_ready", NoKeyGate.answerFor("identityPublic", gate))
        }
    }

    @Test
    fun walletStatusCarriesUnreadableForALockedRecord() {
        for (r in reasons) {
            val out = NoKeyGate.walletStatusFor(NoKeyGate.gateOf(NativeWalletVault.State.Locked(r), sessionReady = false), NativeWalletVault.State.Locked(r))
            assertEquals("$r: status not_ready", "not_ready", out.optString("status"))
            assertEquals("$r: reason unreadable", "unreadable", out.optString("notReadyReason"))
        }
    }
}
