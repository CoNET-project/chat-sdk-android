package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * [NoKeyGate.commandGate]: the store lifts only the empty vault (G0). A plain set is G2; a v3 set is G2 only while the session is unlocked for its
 * EOA; an unreadable store is G1 (not_ready); an absent store stays G0. Every other vault state keeps the vault gate, whatever the store holds.
 */
class CommandGateStoreTest {
    private val a = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val b = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
    private fun plain(eoa: String) = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, "synthetic", 1)
    private fun v3(eoa: String) = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.V3, "{}", 1)
    private fun gate(state: NativeWalletVault.State, store: MnemonicSetStore.Current, ready: String? = null, sessionReady: Boolean = ready != null) =
        NoKeyGate.commandGate(state, sessionReady, keyOnly = false, store = store, readyEoa = ready)

    @Test
    fun anEmptyVaultWithAPlainSetIsG2() = assertEquals(NoKeyGate.Gate.G2, gate(NativeWalletVault.State.NoKey, plain(a)))

    @Test
    fun anEmptyVaultWithAV3SetIsG2OnlyWhileUnlockedForThatEoa() {
        assertEquals(NoKeyGate.Gate.G2, gate(NativeWalletVault.State.NoKey, v3(a), ready = a))
        assertEquals(NoKeyGate.Gate.G2, gate(NativeWalletVault.State.NoKey, v3(a), ready = a.uppercase().replace("0X", "0x")))
        assertEquals("exists, needs the passcode: not_ready, never no_key", NoKeyGate.Gate.G1, gate(NativeWalletVault.State.NoKey, v3(a), ready = null))
        assertEquals(NoKeyGate.Gate.G1, gate(NativeWalletVault.State.NoKey, v3(a), ready = b))
    }

    @Test
    fun anEmptyVaultWithAnUnreadableStoreIsG1() {
        assertEquals(NoKeyGate.Gate.G1, gate(NativeWalletVault.State.NoKey, MnemonicSetStore.Current.Unknown("pointer_invalid")))
        assertEquals(NoKeyGate.Gate.G1, gate(NativeWalletVault.State.NoKey, MnemonicSetStore.Current.Unknown("set_missing"), ready = a))
    }

    @Test
    fun anEmptyVaultWithAnAbsentStoreStaysG0() = assertEquals(NoKeyGate.Gate.G0, gate(NativeWalletVault.State.NoKey, MnemonicSetStore.Current.Absent))

    @Test
    fun theOtherVaultStatesKeepTheVaultGateWhateverTheStoreHolds() {
        val stores = listOf(MnemonicSetStore.Current.Absent, plain(a), v3(a), MnemonicSetStore.Current.Unknown("x"))
        for (s in stores) {
            for (ready in listOf(null, a)) {
                for (state in listOf(NativeWalletVault.State.Ready(a), NativeWalletVault.State.Locked("storage"))) {
                    val sessionReady = ready != null
                    assertEquals("$state $s $ready", NoKeyGate.gateOf(state, sessionReady, false), NoKeyGate.commandGate(state, sessionReady, false, s, ready))
                }
            }
        }
    }

    @Test
    fun theVaultGateItselfIsUnchanged() {
        assertEquals(NoKeyGate.Gate.G0, NoKeyGate.gateOf(NativeWalletVault.State.NoKey, true, false))
    }
}
