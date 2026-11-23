package network.conet.chat.passcode

import network.conet.chat.nativekey.MnemonicDerivation
import network.conet.chat.nativekey.NativeTestFiles
import network.conet.chat.nativekey.WalletAddress
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The passcodeProvision and passcodeUnlock rules (protocol §3.1, §3.2): a provision writes only a verified record, a wrong passcode is answered and
 * never counted, a missing or unreadable record is its own code, and another account's record is never overwritten.
 */
class PasscodeCommandFlowTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val eoa = checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(phrase)))).lowercase()
    private val otherPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val otherEoa = checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(otherPhrase)))).lowercase()
    private val passcode = "51738642"

    @Test
    fun aProvisionWritesAVerifiedRecordAndReportsTheReadBackAddress() {
        val files = NativeTestFiles()
        val store = PasscodeRecordStore(files)
        val r = PasscodeCommandFlow.provision(phrase, passcode, eoa, store, pointerEoa = null, files = files)
        assertTrue(r is PasscodeCommandFlow.Provision.Set)
        r as PasscodeCommandFlow.Provision.Set
        assertEquals(eoa, r.verifiedAddress)
        assertTrue(store.read(eoa) is PasscodeRecordStore.Read.Record)
    }

    @Test
    fun aPhraseThatDoesNotDeriveToTheAccountIsEoaMismatchAndNothingIsWritten() {
        val files = NativeTestFiles()
        val store = PasscodeRecordStore(files)
        val r = PasscodeCommandFlow.provision(otherPhrase, passcode, eoa, store, null, files) as PasscodeCommandFlow.Provision.Fail
        assertEquals("eoa_mismatch", r.code)
        assertTrue(store.read(eoa) is PasscodeRecordStore.Read.Absent)
    }

    @Test
    fun aWeakPasscodeIsRefused() {
        val files = NativeTestFiles()
        val r = PasscodeCommandFlow.provision(phrase, "12345678", eoa, PasscodeRecordStore(files), null, files) as PasscodeCommandFlow.Provision.Fail
        assertEquals("weak_passcode", r.code)
    }

    @Test
    fun aPointerToAnotherAccountIsEoaMismatch() {
        val files = NativeTestFiles()
        val r = PasscodeCommandFlow.provision(phrase, passcode, eoa, PasscodeRecordStore(files), pointerEoa = otherEoa, files = files)
        assertEquals("eoa_mismatch", (r as PasscodeCommandFlow.Provision.Fail).code)
    }

    @Test
    fun aSecondProvisionForTheSameAccountIsAlreadySetAndDoesNotOverwrite() {
        val files = NativeTestFiles()
        val store = PasscodeRecordStore(files)
        PasscodeCommandFlow.provision(phrase, passcode, eoa, store, null, files)
        val before = files.map[eoa]!!.copyOf()
        val r = PasscodeCommandFlow.provision(phrase, "62840159", eoa, store, null, files) as PasscodeCommandFlow.Provision.Fail
        assertEquals("already_set", r.code)
        assertArrayEquals(before, files.map[eoa])
    }

    @Test
    fun anotherAccountsRecordIsNeverOverwritten() {
        val files = NativeTestFiles()
        val store = PasscodeRecordStore(files)
        // The other account already has a record in this directory.
        val other = checkNotNull(MnemonicDerivation.deriveKey(otherPhrase))
        assertEquals(PasscodeRecordStore.Write.OK, store.writeVerified(otherEoa, passcode, otherPhrase.toByteArray()))
        other.fill(0)
        val before = files.map[otherEoa]!!.copyOf()
        val r = PasscodeCommandFlow.provision(phrase, "62840159", eoa, store, null, files) as PasscodeCommandFlow.Provision.Fail
        assertEquals("other_account_present", r.code)
        assertArrayEquals(before, files.map[otherEoa])
    }

    @Test
    fun aWrongPasscodeIsAnsweredAndNeverCounted() {
        val files = NativeTestFiles()
        val store = PasscodeRecordStore(files)
        PasscodeCommandFlow.provision(phrase, passcode, eoa, store, null, files)
        for (i in 1..5) {
            val r = PasscodeCommandFlow.unlock(eoa, "62840159", store) as PasscodeCommandFlow.Unlock.Fail
            assertEquals("wrong_passcode", r.code)
        }
        // The right passcode still opens it: nothing was locked out natively.
        val ok = PasscodeCommandFlow.unlock(eoa, passcode, store)
        assertTrue(ok is PasscodeCommandFlow.Unlock.Unlocked)
    }

    @Test
    fun theRightPasscodeReturnsThePhraseOfTheAccount() {
        val files = NativeTestFiles()
        val store = PasscodeRecordStore(files)
        PasscodeCommandFlow.provision(phrase, passcode, eoa, store, null, files)
        val u = PasscodeCommandFlow.unlock(eoa, passcode, store) as PasscodeCommandFlow.Unlock.Unlocked
        assertArrayEquals(phrase.toByteArray(Charsets.UTF_8), u.phrase)
        assertEquals(eoa, u.eoa)
        u.phrase.fill(0)
    }

    @Test
    fun aMissingRecordIsNoRecord() {
        val r = PasscodeCommandFlow.unlock(eoa, passcode, PasscodeRecordStore(NativeTestFiles())) as PasscodeCommandFlow.Unlock.Fail
        assertEquals("no_record", r.code)
    }

    @Test
    fun anUnreadableRecordIsRecordInvalid() {
        val files = NativeTestFiles()
        files.map[eoa] = byteArrayOf(1, 2, 3)
        val r = PasscodeCommandFlow.unlock(eoa, passcode, PasscodeRecordStore(files)) as PasscodeCommandFlow.Unlock.Fail
        assertEquals("record_invalid", r.code)
    }
}
