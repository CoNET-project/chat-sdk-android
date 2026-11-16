package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 25.52X.4 (rc2.2-qa, coordinator ruling): `already_exists` carries the public lower-case `eoa` when the native derivation and storage both
 * succeed. Other answers carry none, and the key itself is never returned. In memory only.
 */
class AlreadyExistsEoaTest {
    private val eoa = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    private val key = ByteArray(32).also { it[31] = 1 }

    /** A readable key: the public lower-case EOA is returned, and it is the account of the record. */
    @Test
    fun readableKeyGivesItsPublicLowerCaseEoa() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, key))

        assertEquals(eoa, NativeWalletVault(wrap, files).publicEoaIfReadable())
    }

    /** A key that cannot be read gives no EOA: the answer carries none, so the page does not enter the existing account. */
    @Test
    fun unreadableKeyGivesNoEoa() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, key))
        wrap.deleteKey()

        assertNull(NativeWalletVault(wrap, files).publicEoaIfReadable())
    }

    /** No key on the device gives no EOA. */
    @Test
    fun noKeyGivesNoEoa() {
        assertNull(NativeWalletVault(NativeTestWrap(), NativeTestFiles()).publicEoaIfReadable())
    }

    /** `already_exists` from the recovery path carries the EOA; any other recovery answer carries none. */
    @Test
    fun recoveryAlreadyExistsCarriesEoaAndOtherAnswersDoNot() {
        val exists = RecoveryOutcome.existing(eoa)
        assertEquals("already_exists", exists.code)
        assertEquals(eoa, exists.eoa)
        assertNull(RecoveryOutcome.existing(null).eoa)
        assertNull(RecoveryOutcome.fail("invalid_format").eoa)
        assertNull(RecoveryOutcome.fail("write_failed").eoa)
    }

    /** The account-create result carries the EOA on `already_exists` only when it is given. */
    @Test
    fun createAlreadyExistsCarriesEoaOnlyWhenGiven() {
        assertEquals(eoa, NativeAccountCreate.Result(NativeAccountCreate.Code.ALREADY_EXISTS, eoa).eoa)
        assertNull(NativeAccountCreate.Result(NativeAccountCreate.Code.ALREADY_EXISTS).eoa)
        assertNull(NativeAccountCreate.Result(NativeAccountCreate.Code.WRITE_FAILED).eoa)
    }
}
