package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Snapshot QA probe (2026-11-17, five call points). A storage change made outside the vault after a snapshot is taken, before any
 * invalidation, is answered from the snapshot (25.52Y.75). Each probe runs the same expression as one call point on the stale snapshot
 * and on a fresh read, and records both answers. Nothing is asserted as a fix here: the assertions document the observed behaviour.
 */
class SnapshotStaleProbeTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()
    private fun key() = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoa() = checkNotNull(WalletAddress.fromPrivateKey(key()))

    private fun gateName(g: NoKeyGate.Gate) = g.name

    /** The snapshot is Ready; the record and phrase are then removed outside the vault. */
    private fun staleAfterExternalLoss(): Pair<NativeTestFiles, NativeWalletVault> {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa(), key(), phrase))
        val v = NativeWalletVault(wrap, files)
        assertEquals(true, v.state() is NativeWalletVault.State.Ready)
        files.map.remove(NativeWalletVault.REC)
        files.map.remove(NativeWalletVault.MNEM)
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
        return files to v
    }

    @Test fun probeSnapshotCallPoints() {
        val (files, v) = staleAfterExternalLoss()
        val fresh = NativeWalletVault(wrap, files).state()
        val snap = v.snapshotState()
        val snapKeyOnly = v.snapshotKeyOnly()
        val lines = mutableListOf<String>()
        lines += "FRESH state=${fresh.javaClass.simpleName} SNAPSHOT state=${snap?.javaClass?.simpleName} snapKeyOnly=$snapKeyOnly"
        // 386: walletStatus gate (walletStatusGate over the snapshot flag).
        lines += "P386 walletStatus gate(snapshot)=${gateName(NoKeyGate.walletStatusGate(requireNotNull(snap), sessionReady = true, keyOnly = snapKeyOnly))}"
        // 579: unlock gate (gateOf over the snapshot state and flag).
        lines += "P579 unlock gate(snapshot)=${gateName(NoKeyGate.gateOf(requireNotNull(snap), sessionReady = true, keyOnly = snapKeyOnly))}"
        // 2041: identity gate (gateOf over the snapshot state and flag).
        lines += "P2041 identity gate(snapshot)=${gateName(NoKeyGate.gateOf(requireNotNull(snap), sessionReady = true, keyOnly = snapKeyOnly))}"
        // 2500: history delete gate (gateOf over the snapshot state, no flag).
        lines += "P2500 history gate(snapshot)=${gateName(NoKeyGate.gateOf(requireNotNull(snap), sessionReady = true))}"
        // ShellRecord.accountOf: the snapshot state decides (the keyOnly flag is the snapshot flag).
        lines += "PSR accountOf known=${snap?.javaClass?.simpleName} keyOnly=$snapKeyOnly"
        lines.forEach { System.out.println("SNAPPROBE $it") }
        // The probe documents the stale answer: the fresh state is no account while the snapshot still reads Ready.
        assertEquals(NativeWalletVault.State.NoKey, fresh)
    }
}
