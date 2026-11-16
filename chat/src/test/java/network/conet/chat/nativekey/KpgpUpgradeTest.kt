package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/** The runtime upgrade of K_pgp from the native record L (§25.52Y.59 第 3 项): L first, never deleted, no silent new key. */
class KpgpUpgradeTest {
    private val eoa = "0x" + "ab".repeat(20)

    private fun validRecord(): KpgpUpgrade.LRecord {
        val gen = NativePgpKeyGen.generate(eoa, SecureRandom())
        val keyId = NativePgp.parseSecret(gen.privateArmor)!!.let { NativePgpBackup.subkeyKeyId(it)!! }
        return KpgpUpgrade.LRecord(gen.privateArmor, keyId)
    }

    @Test
    fun aValidNativeRecordWritesKFromItAndKeepsIt() {
        val backend = MemoryAccountPgpKBackend()
        val k = AccountPgpK(backend)
        val rec = validRecord()
        val r = KpgpUpgrade.upgrade(k, eoa, rec, userClick = false, nowSec = 1L)
        assertEquals("upgraded_from_L", r.action)
        val item = k.read(eoa, PgpMigrationPolicy.WORKSPACE)!!
        assertEquals(rec.subkeyKeyId, item.getString("keyId"))
        assertEquals(eoa, item.getString("eoa"))
    }

    @Test
    fun anExistingKIsKeptAndNotOverwritten() {
        val backend = MemoryAccountPgpKBackend()
        val k = AccountPgpK(backend)
        k.write(eoa, PgpMigrationPolicy.WORKSPACE, "EXISTING", "PUB", "PRIV", 1L)
        val before = backend.items.toMap()
        val r = KpgpUpgrade.upgrade(k, eoa, validRecord(), userClick = false, nowSec = 2L)
        assertEquals("keep_existing", r.action)
        assertEquals(before, backend.items.toMap())
    }

    @Test
    fun noRecordAndNoClickIsRetryAndNeverGenerates() {
        val backend = MemoryAccountPgpKBackend()
        val r = KpgpUpgrade.upgrade(AccountPgpK(backend), eoa, null, userClick = false, nowSec = 1L)
        assertEquals("pgp_migration_retry", r.action)
        assertTrue(backend.items.isEmpty())
    }

    @Test
    fun aRecordWhoseKeyIdDoesNotMatchIsNotValid() {
        val backend = MemoryAccountPgpKBackend()
        val good = validRecord()
        val bad = KpgpUpgrade.LRecord(good.privateArmor, "0000000000000000")
        val r = KpgpUpgrade.upgrade(AccountPgpK(backend), eoa, bad, userClick = false, nowSec = 1L)
        assertEquals("pgp_migration_retry", r.action)
        assertTrue(backend.items.isEmpty())
    }

    @Test
    fun noRecordWithTheConfirmedClickIsTheGenerateActionOnly() {
        // The function reports the action; generating and registering the new key is the caller's step, never done here.
        val backend = MemoryAccountPgpKBackend()
        val r = KpgpUpgrade.upgrade(AccountPgpK(backend), eoa, null, userClick = true, nowSec = 1L, nativeConfirm = true)
        assertEquals("generated_on_user_click", r.action)
        assertTrue(backend.items.isEmpty())
    }

    @Test
    fun aClickWithoutTheNativeConfirmationNeverGenerates() {
        val backend = MemoryAccountPgpKBackend()
        val r = KpgpUpgrade.upgrade(AccountPgpK(backend), eoa, null, userClick = true, nowSec = 1L, nativeConfirm = false)
        assertEquals("pgp_migration_retry", r.action)
        assertTrue(backend.items.isEmpty())
    }
}
