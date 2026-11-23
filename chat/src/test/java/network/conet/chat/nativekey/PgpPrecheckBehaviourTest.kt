package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Behaviour of the legacy PGP adoption precheck (2026-11-20; F2 review FAIL on the armor read, F3 ).
 * A failed armor read is unknown, never "no armor"; no armor is nothing; an orphan armor with a confirmed no-wallet state is nothing;
 * an armor with a wallet that is not NoKey continues to the adoption; a wallet read fault propagates (unknown).
 */
class PgpPrecheckBehaviourTest {
    private val armor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nTEST-FIXTURE\n-----END PGP PRIVATE KEY BLOCK-----"

    @Test
    fun aFailedArmorReadIsUnknownNotNothing() {
        // The secure store could not be read: null. Never RESOLVED_NOTHING (that would skip a legacy armor that still exists).
        assertEquals(NativeWalletMigration.UNKNOWN, legacyPgpPrecheck(null) { true })
        assertEquals(NativeWalletMigration.UNKNOWN, legacyPgpPrecheck(null) { false })
    }

    @Test
    fun aStoreWithNoArmorIsNothing() {
        assertEquals(NativeWalletMigration.NOTHING, legacyPgpPrecheck("") { false })
        assertEquals(NativeWalletMigration.NOTHING, legacyPgpPrecheck("not an armor") { false })
    }

    @Test
    fun anOrphanArmorWithAConfirmedNoWalletIsNothing() {
        assertEquals(NativeWalletMigration.NOTHING, legacyPgpPrecheck(armor) { true })
    }

    @Test
    fun anArmorWithAWalletThatIsNotNoKeyContinuesToTheAdoption() {
        assertNull(legacyPgpPrecheck(armor) { false })
    }

    @Test
    fun aWalletReadFaultPropagatesAsUnknown() {
        assertThrows(java.io.IOException::class.java) {
            legacyPgpPrecheck(armor) { throw java.io.IOException("wallet read failed") }
        }
    }
}

/** Test-side names for the precheck outcomes (the production enum is MigrationGate.Outcome). */
private object NativeWalletMigration {
    val UNKNOWN = MigrationGate.Outcome.UNKNOWN
    val NOTHING = MigrationGate.Outcome.RESOLVED_NOTHING
}
