package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Data-safety gate of account creation (PM ruling; the refusal is `not_available`, no page). A create must never overwrite a wallet held
 * elsewhere. Only: no native key, legacy store confirmed `absent`, no pointer, no page copy, no migration pending.
 */
class AccountCreateGuardTest {
    private fun inputs(
        key: KeyState = KeyState.NONE,
        legacy: String? = "absent",
        legacyUnreadable: Boolean = false,
        pointer: Boolean = false,
        pageCopy: Boolean = false,
        migrating: Boolean = false,
    ) = CreateGuardInputs(key, legacy, legacyUnreadable, pointer, pageCopy, migrating)

    @Test
    fun aFreshDeviceMayCreate() {
        assertNull(AccountCreateGuard.denial(inputs()))
    }

    @Test
    fun aReadableKeyWithAbsentLegacyIsNotAllowedToCreate() {
        // Key held, legacy confirmed absent, create mode: must not create (the replica path only).
        assertEquals(AccountCreateGuard.REPLICA_PRESENT, AccountCreateGuard.denial(inputs(key = KeyState.READABLE)))
    }

    @Test
    fun anUnreadableKeyNeedsNativeRecovery() {
        assertEquals(AccountCreateGuard.NEEDS_NATIVE_RECOVERY, AccountCreateGuard.denial(inputs(key = KeyState.UNREADABLE)))
    }

    @Test
    fun aPendingMigrationOrAnUnconfirmedLegacyStoreIsMigrating() {
        // No key, but the legacy store is not confirmed empty (found, unreadable, never reported, or the marker is set).
        assertEquals(AccountCreateGuard.MIGRATING, AccountCreateGuard.denial(inputs(legacy = "found")))
        assertEquals(AccountCreateGuard.MIGRATING, AccountCreateGuard.denial(inputs(legacy = "unreadable")))
        assertEquals(AccountCreateGuard.MIGRATING, AccountCreateGuard.denial(inputs(legacy = null)))
        assertEquals(AccountCreateGuard.MIGRATING, AccountCreateGuard.denial(inputs(legacyUnreadable = true)))
        // A write or migration in progress holds the create back even when the legacy report reads absent.
        assertEquals(AccountCreateGuard.MIGRATING, AccountCreateGuard.denial(inputs(migrating = true)))
    }

    @Test
    fun aSetPointerOrAPageCopyRefusesTheCreate() {
        assertEquals(AccountCreateGuard.POINTER_SET, AccountCreateGuard.denial(inputs(pointer = true)))
        assertEquals(AccountCreateGuard.REPLICA_PRESENT, AccountCreateGuard.denial(inputs(pageCopy = true)))
    }

    @Test
    fun aRefusedCreateNeverOpensThePage() {
        // The bridge answer is the existing not_available, the host is not called, and no result is sent (PM ruling).
        var opened = 0
        NativeAccountCreateHost.launcher = { opened++; true }
        val r = NativeOpenRules.accountCreateOpen(
            listOf("type", "reqId", "account"), "N-G", "alice", NoKeyGate.Gate.G0, NativeOpenRules.accountHost,
            guardDenial = AccountCreateGuard.REPLICA_PRESENT,
        )
        assertEquals("not_available", r.error)
        assertEquals(0, opened)
        NativeAccountCreateHost.launcher = null
    }
}
