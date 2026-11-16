package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The creation transaction (§25.52Y.1 第 6 项, PM ruling): W and K are written together, and a failure leaves no half account. */
class CreateAccountKTest {
    private val zero = ByteArray(16)

    /** A K backend whose writes do not complete (the write fails and the removal works). */
    private class FailingPut : AccountPgpKBackend {
        val items = mutableMapOf<String, String>()
        override fun get(name: String): String? = items[name]
        override fun put(name: String, value: String): Boolean = false
        override fun names(): Set<String> = items.keys.toSet()
        override fun remove(name: String): Boolean {
            items.remove(name)
            return true
        }
    }

    @Test
    fun aCreationWritesOneKForTheNewAccountWithItsSubkeyKeyId() {
        val vault = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val backend = MemoryAccountPgpKBackend()
        val pgp = AccountPgpK(backend)
        val r = NativeAccountCreate.create(vault, pgp, zero)
        assertEquals(NativeAccountCreate.Code.OK, r.code)
        val eoa = r.eoa!!
        val k = pgp.read(eoa, PgpMigrationPolicy.WORKSPACE)!!
        assertEquals(eoa, k.getString("eoa"))
        assertEquals(PgpMigrationPolicy.WORKSPACE, k.getString("workspace"))
        assertTrue(k.getString("privateKeyArmor").contains("PRIVATE KEY BLOCK"))
        assertTrue(k.getString("publicKeyArmor").contains("PUBLIC KEY BLOCK"))
        assertEquals(1, backend.items.size)
        // The keyId is the subkey key ID of the armor it was written with.
        val secret = NativePgp.parseSecret(k.getString("privateKeyArmor"))!!
        assertEquals(NativePgpBackup.subkeyKeyId(secret), k.getString("keyId"))
        assertTrue(vault.state() is NativeWalletVault.State.Ready)
    }

    @Test
    fun aFailedKWriteRemovesTheNewWalletAndLeavesNoKey() {
        val vault = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val r = NativeAccountCreate.create(vault, AccountPgpK(FailingPut()), zero)
        assertEquals(NativeAccountCreate.Code.WRITE_FAILED, r.code)
        assertTrue(vault.state() is NativeWalletVault.State.NoKey)
    }

    @Test
    fun anExistingKIsNeverOverwrittenAndTheNewWalletIsRemoved() {
        val vault = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val backend = MemoryAccountPgpKBackend()
        val pgp = AccountPgpK(backend)
        // The item of the account that this creation would produce: the entropy is zero, so the EOA is the one below. Create once to learn it.
        val probe = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val first = NativeAccountCreate.create(probe, AccountPgpK(MemoryAccountPgpKBackend()), zero)
        val eoa = first.eoa!!
        pgp.write(eoa, PgpMigrationPolicy.WORKSPACE, "EXISTING", "PUB", "PRIV", 1L)
        val before = backend.items.toMap()
        val r = NativeAccountCreate.create(vault, pgp, zero)
        assertEquals(NativeAccountCreate.Code.ALREADY_EXISTS, r.code)
        assertTrue(vault.state() is NativeWalletVault.State.NoKey)
        assertEquals(before, backend.items.toMap())
        assertFalse(backend.items.isEmpty())
    }
}
