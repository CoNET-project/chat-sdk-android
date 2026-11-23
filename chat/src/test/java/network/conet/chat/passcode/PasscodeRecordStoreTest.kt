package network.conet.chat.passcode

import network.conet.chat.nativekey.NativeTestFiles
import network.conet.chat.nativekey.VaultFiles
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic values only. Covers the write order (new file, readback, replace) and the rule that a failed write keeps the old record. */
class PasscodeRecordStoreTest {
    private val eoa = "0x1111111111111111111111111111111111111111"
    private val pass = "24681357"
    private val inner = "fixture-account-key".toByteArray(Charsets.UTF_8)

    @Test
    fun aVerifiedWriteOpensWithThePasscodeAndLeavesNoFreshFile() {
        val files = NativeTestFiles()
        val store = PasscodeRecordStore(files)
        assertEquals(PasscodeRecordStore.Write.OK, store.writeVerified(eoa, pass, inner))
        assertArrayEquals(inner, store.unlock(eoa, pass))
        assertNull("the fresh file is removed after the replace", files.map[eoa.lowercase() + ".new"])
        assertTrue(files.map.containsKey(eoa.lowercase()))
    }

    @Test
    fun aWrongPasscodeDoesNotUnlock() {
        val files = NativeTestFiles()
        val store = PasscodeRecordStore(files)
        store.writeVerified(eoa, pass, inner)
        assertNull(store.unlock(eoa, "13572468"))
    }

    @Test
    fun aFailedNewWriteKeepsTheOldRecord() {
        val files = NativeTestFiles()
        val store = PasscodeRecordStore(files)
        assertEquals(PasscodeRecordStore.Write.OK, store.writeVerified(eoa, pass, inner))
        val before = files.map[eoa.lowercase()]!!.copyOf()
        files.failWrite = eoa.lowercase() + ".new"
        assertEquals(PasscodeRecordStore.Write.WRITE_FAILED, store.writeVerified(eoa, "11223355", "other-key".toByteArray()))
        assertArrayEquals("the old record bytes are unchanged", before, files.map[eoa.lowercase()])
        assertArrayEquals(inner, store.unlock(eoa, pass))
    }

    @Test
    fun aReadbackMismatchKeepsTheOldRecord() {
        val files = NativeTestFiles()
        val store = PasscodeRecordStore(files)
        store.writeVerified(eoa, pass, inner)
        val before = files.map[eoa.lowercase()]!!.copyOf()
        // The read of the fresh file returns a corrupted copy: the verification must refuse it.
        val corrupting = object : VaultFiles by files {
            override fun read(name: String): ByteArray? {
                val bytes = files.read(name) ?: return null
                return if (name.endsWith(".new")) bytes.copyOf().also { it[it.size - 3] = (it[it.size - 3] + 1).toByte() } else bytes
            }
        }
        val refused = PasscodeRecordStore(corrupting).writeVerified(eoa, "11223355", "other-key".toByteArray())
        assertEquals(PasscodeRecordStore.Write.READBACK_MISMATCH, refused)
        assertArrayEquals(before, files.map[eoa.lowercase()])
        assertTrue("the corrupted fresh file is removed", !files.map.containsKey(eoa.lowercase() + ".new"))
    }

    @Test
    fun aMalformedRecordIsInvalidNotAbsent() {
        val files = NativeTestFiles()
        files.map[eoa.lowercase()] = "not a record".toByteArray()
        assertEquals(PasscodeRecordStore.Read.Invalid, PasscodeRecordStore(files).read(eoa))
        assertEquals(PasscodeRecordStore.Read.Absent, PasscodeRecordStore(NativeTestFiles()).read(eoa))
    }
}
