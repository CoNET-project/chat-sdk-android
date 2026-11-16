package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The gate before a derivation reads the key (25.52Y.84). A true lock answers `locked`; an unreadable wallet state or unlock answers
 * `not_ready` with reason `unreadable`. The key is read only when the state is ready, and it is zeroed after the body runs.
 */
class DerivationGateTest {
    private val eoa = "0x" + "ab".repeat(20)
    private val key = ByteArray(32) { (it + 1).toByte() }

    @Test
    fun aReadyVaultRunsTheBodyWithTheEoaAndZeroesTheKey() {
        var seenEoa: String? = null
        var seenKey: ByteArray? = null
        var unlockedKey: ByteArray? = null
        val out = NativeDerivationCommands.withKey(
            state = { NativeWalletVault.State.Ready(eoa) },
            unlock = { key.copyOf().also { unlockedKey = it } },
            body = { k, e ->
                seenEoa = e
                seenKey = k.copyOf()
                NativeDerivationCommands.Outcome.ok(org.json.JSONObject().put("v", 1))
            },
        )
        assertTrue(out.ok)
        assertEquals(eoa, seenEoa)
        assertArrayEquals(key, seenKey)
        assertTrue("the key is zeroed after the body", unlockedKey!!.all { it == 0.toByte() })
    }

    @Test
    fun noKeyRecordIsALockNotAnUnknown() {
        assertLocked(NativeWalletVault.State.NoKey)
    }

    @Test
    fun aRealLockedReasonIsLocked() {
        for (reason in listOf("rollback_pending", "record_missing", "marker_missing", "marker_mismatch", NativeWalletVault.PHRASE_ONLY)) {
            assertLocked(NativeWalletVault.State.Locked(reason))
        }
    }

    @Test
    fun anUnreadableLockedStateIsNotReadyNotLocked() {
        val out = assertNotReady(state = { NativeWalletVault.State.Locked("unreadable") }, unlock = { key.copyOf() })
        assertEquals(NativeDerivationCommands.UNREADABLE, out.reason)
    }

    @Test
    fun aThrownStateReadIsNotReady() {
        val out = assertNotReady(state = { null }, unlock = { key.copyOf() })
        assertEquals(NativeDerivationCommands.UNREADABLE, out.reason)
    }

    @Test
    fun anUnreadableUnlockIsNotReadyAndTheBodyDoesNotRun() {
        var ran = false
        val out = NativeDerivationCommands.withKey(
            state = { NativeWalletVault.State.Ready(eoa) },
            unlock = { null },
            body = { _, _ ->
                ran = true
                NativeDerivationCommands.Outcome.ok(org.json.JSONObject())
            },
        )
        assertFalse(ran)
        assertFalse(out.ok)
        assertEquals(NativeDerivationCommands.NOT_READY, out.error)
        assertEquals(NativeDerivationCommands.UNREADABLE, out.reason)
    }

    @Test
    fun aLockedAnswerCarriesNoReason() {
        val out = NativeDerivationCommands.withKey(state = { NativeWalletVault.State.NoKey }, unlock = { key.copyOf() }, body = { _, _ -> throw AssertionError("must not run") })
        assertEquals(NativeDerivationCommands.LOCKED, out.error)
        assertNull(out.reason)
        assertTrue(out.error != NativeDerivationCommands.NOT_READY)
    }

    private fun assertLocked(s: NativeWalletVault.State) {
        var unlocked = false
        val out = NativeDerivationCommands.withKey(
            state = { s },
            unlock = {
                unlocked = true
                key.copyOf()
            },
            body = { _, _ -> throw AssertionError("must not run") },
        )
        assertFalse(unlocked)
        assertEquals(NativeDerivationCommands.LOCKED, out.error)
        assertNull(out.reason)
    }

    private fun assertNotReady(
        state: () -> NativeWalletVault.State?,
        unlock: () -> ByteArray?,
    ): NativeDerivationCommands.Outcome {
        var unlocked = false
        var ran = false
        val out = NativeDerivationCommands.withKey(
            state = state,
            unlock = {
                unlocked = true
                unlock()
            },
            body = { _, _ ->
                ran = true
                NativeDerivationCommands.Outcome.ok(org.json.JSONObject())
            },
        )
        assertFalse("the key must not be read when the state is unknown", unlocked)
        assertFalse(ran)
        assertFalse(out.ok)
        assertEquals(NativeDerivationCommands.NOT_READY, out.error)
        assertTrue(out.error != NativeDerivationCommands.LOCKED)
        return out
    }
}
