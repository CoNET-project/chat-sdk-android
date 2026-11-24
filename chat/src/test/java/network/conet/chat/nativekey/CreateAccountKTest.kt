package network.conet.chat.nativekey

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The creation transaction after A creation writes the wallet W only. It generates no PGP key and writes no K; the first
 * identity is made by [FirstIdentityCoordinator], and only when the chain confirms no record.
 */
class CreateAccountKTest {
    private val zero = ByteArray(16)

    @Test
    fun aCreationWritesTheWalletOnlyAndNoKeyOfAnyKindIsGenerated() {
        val files = NativeTestFiles()
        val vault = NativeWalletVault(NativeTestWrap(), files)
        val r = NativeAccountCreate.create(vault, zero)
        assertEquals(NativeAccountCreate.Code.OK, r.code)
        assertNotNull(r.eoa)
        assertTrue(vault.state() is NativeWalletVault.State.Ready)
        // No PGP file of any slot was written beside the wallet record.
        assertTrue("no pgp.v1 file: ${files.map.keys}", files.map.keys.none { it.startsWith("pgp.v1.") })
    }

    @Test
    fun theCreationSourceNamesNoKeyGeneratorAndNoKStore() {
        val src = File("src/main/java/network/conet/chat/nativekey/NativeAccountCreate.kt").readText()
        assertFalse("no key generator", src.contains("NativePgpKeyGen"))
        assertFalse("no K store", src.contains("AccountPgpK"))
        assertFalse("no K write log", src.contains("kpgp.write:create"))
    }

    @Test
    fun aSecondCreationOnTheSameDeviceIsAlreadyExistsAndWritesNothingMore() {
        val files = NativeTestFiles()
        val vault = NativeWalletVault(NativeTestWrap(), files)
        assertEquals(NativeAccountCreate.Code.OK, NativeAccountCreate.create(vault, zero).code)
        val before = files.map.toMap().mapValues { it.value.toList() }
        assertEquals(NativeAccountCreate.Code.ALREADY_EXISTS, NativeAccountCreate.create(vault, ByteArray(16) { 7 }).code)
        assertEquals(before, files.map.toMap().mapValues { it.value.toList() })
    }
}
