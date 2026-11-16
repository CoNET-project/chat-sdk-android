package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * kPresent is tri-state (Y.104 第 3 条, Y.105 第 3 条): false only when the K store was read completely and holds no K; an unreadable K store is
 * unknown (null) and is never folded into false. A K-less store with a phrase-only vault is not a K. Pure: the decision is driven without a device.
 */
class NativeKPresentUnknownTest {
    private fun sources(keyReady: Boolean = false, kPresent: Boolean = false, kUnreadable: Boolean = false) =
        BindingLocalSources.of(
            keyReady = keyReady,
            vaultUnreadable = false,
            kActive = false,
            kNonActive = false,
            kUnreadable = kUnreadable,
            kPresent = kPresent,
        )

    @Test
    fun anUnreadableKStoreIsUnknownNeverFalse() {
        val (_, device) = sources(kUnreadable = true)
        assertNull("unknown, not false", device.kPresent)
    }

    @Test
    fun aCompletelyReadEmptyKStoreIsFalse() {
        val (_, device) = sources()
        assertEquals(false, device.kPresent)
    }

    @Test
    fun aKOrAKeyRecordIsTrue() {
        assertEquals(true, sources(kPresent = true).second.kPresent)
        assertEquals(true, sources(keyReady = true).second.kPresent)
    }

    /** The tag path asks the registry: an absent answer with an unknown K is never a create (fail closed). */
    @Test
    fun anUnknownKOnTheTagPathIsLookupUnavailableNeverCreate() {
        val (local, device) = sources(kUnreadable = true)
        val code = BindingDecision.decideFromRead(BindingKind.TAG, RegistryRead.Absent, 0L, local, device)
        assertEquals(BindingCode.LOOKUP_UNAVAILABLE, code)
    }

    @Test
    fun aCompletelyReadEmptyKStoreMayCreateOnTheTagPath() {
        val (local, device) = sources()
        val code = BindingDecision.decideFromRead(BindingKind.TAG, RegistryRead.Absent, 0L, local, device)
        assertEquals(BindingCode.CREATE, code)
    }

    @Test
    fun aPhraseOnlyVaultIsNotAKAndDoesNotChangeKPresent() {
        // The vault's phrase row is not a key or K record: kPresent is decided by the K store alone (Y.105 第 3 条).
        val (_, device) = sources()
        assertFalse(device.walletRecord)
        assertEquals(false, device.kPresent)
    }

    @Test
    fun theBindingDeviceCarriesAnUnknownKPresentWithoutAFalseWalletRecord() {
        val (_, device) = sources(kUnreadable = true)
        assertTrue(device.kPresent == null && !device.walletRecord)
    }
}
