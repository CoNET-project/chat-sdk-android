package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import network.conet.chat.nativekey.NativeWalletVault.Import
import network.conet.chat.nativekey.NativeWalletVault.State
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

/**
 * Acceptance groups for the native wallet key: new install, upgrade with a key, upgrade without a key
 * (locked, import guidance), native import success, native import failure. The Keystore is replaced by
 * an in-memory AES-GCM key and the files by a map, so the write order and crash points can be driven.
 */
class NativeWalletVaultTest {
    private fun scalar(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        val n = minOf(raw.size, 32)
        System.arraycopy(raw, raw.size - n, out, 32 - n, n)
        return out
    }

    private val keyA = scalar(BigInteger.ONE)
    private val eoaA = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    private val keyB = scalar(BigInteger.TWO)
    private val eoaB = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"

    private fun vault(wrap: NativeTestWrap, files: NativeTestFiles) = NativeWalletVault(wrap, files)

    // ---- A. new install -------------------------------------------------------------------

    @Test
    fun newInstallHasNoKeyNothingToUnlockAndNothingOnDisk() {
        val files = NativeTestFiles()
        val v = vault(NativeTestWrap(), files)
        assertTrue(v.state() is State.NoKey)
        assertNull(v.unlock())
        assertTrue(files.map.isEmpty())
    }

    // ---- B. upgrade with an existing key (legacy record adopted natively) ------------------

    @Test
    fun upgradeAdoptsTheExistingKeyNativelyAndKeepsItAcrossRestart() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val v = vault(wrap, files)
        assertEquals(Import.OK, v.importKey(eoaA, keyA, NativeWalletVault.SOURCE_LEGACY))
        assertEquals(eoaA, (v.state() as State.Ready).eoa)
        assertArrayEquals(keyA, v.unlock())

        val restarted = vault(wrap, files)
        assertEquals(eoaA, (restarted.state() as State.Ready).eoa)
        assertArrayEquals(keyA, restarted.unlock())
    }

    @Test
    fun repeatedAdoptionOfTheSameWalletIsAlreadyPresentAndChangesNothing() {
        val files = NativeTestFiles()
        val v = vault(NativeTestWrap(), files)
        assertEquals(Import.OK, v.importKey(eoaA, keyA, NativeWalletVault.SOURCE_LEGACY))
        val before = files.map.mapValues { it.value.copyOf() }
        assertEquals(Import.ALREADY_PRESENT, v.importKey(eoaA, keyA, NativeWalletVault.SOURCE_LEGACY))
        assertEquals(before.keys, files.map.keys)
        before.forEach { (k, bytes) -> assertArrayEquals(bytes, files.map[k]) }
    }

    // ---- C. upgrade without a key: locked, import guidance -------------------------------

    @Test
    fun upgradeWithoutAKeyStaysLockedAndCannotSign() {
        val v = vault(NativeTestWrap(), NativeTestFiles())
        assertTrue(v.state() is State.NoKey)
        assertNull(v.unlock())
    }

    @Test
    fun legacyKeyThatDoesNotMatchItsAddressIsNotAdopted() {
        val files = NativeTestFiles()
        val v = vault(NativeTestWrap(), files)
        assertEquals(Import.ADDRESS_MISMATCH, v.importKey(eoaB, keyA, NativeWalletVault.SOURCE_LEGACY))
        assertTrue(v.state() is State.NoKey)
        assertTrue(files.map.isEmpty())
    }

    // ---- D. native import succeeds ---------------------------------------------------------

    @Test
    fun nativeImportSucceedsReadsBackAndPersists() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val v = vault(wrap, files)
        assertEquals(Import.OK, v.importKey(eoaA, keyA))
        assertTrue(files.map.containsKey(NativeWalletVault.REC))
        assertTrue(files.map.containsKey(NativeWalletVault.MARK))
        assertEquals(eoaA, (vault(wrap, files).state() as State.Ready).eoa)
    }

    @Test
    fun recordNeverContainsThePlaintextKey() {
        val files = NativeTestFiles()
        val v = vault(NativeTestWrap(), files)
        assertEquals(Import.OK, v.importKey(eoaA, keyA))
        val text = String(files.map.getValue(NativeWalletVault.REC), Charsets.UTF_8)
        assertFalse(text.contains(ConetChatCryptoUtil.toHex(keyA)))
        assertFalse(text.contains(ConetChatCryptoUtil.toHex(keyA).uppercase()))
    }

    @Test
    fun aSecondWalletIsRefusedAndTheFirstIsNotOverwritten() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val v = vault(wrap, files)
        assertEquals(Import.OK, v.importKey(eoaA, keyA))
        val before = files.map.getValue(NativeWalletVault.REC).copyOf()
        assertEquals(Import.RECORD_EXISTS, v.importKey(eoaB, keyB))
        assertArrayEquals(before, files.map.getValue(NativeWalletVault.REC))
        assertEquals(eoaA, (v.state() as State.Ready).eoa)
    }

    @Test
    fun forgetRemovesRecordMarkerAndKeySoTheVaultIsEmptyAgain() {
        val files = NativeTestFiles()
        val v = vault(NativeTestWrap(), files)
        assertEquals(Import.OK, v.importKey(eoaA, keyA))
        v.forget()
        assertTrue(files.map.isEmpty())
        assertTrue(v.state() is State.NoKey)
        assertNull(v.unlock())
    }

    // ---- E. native import fails: nothing usable is left behind -----------------------------

    @Test
    fun wrongKeyForTheAddressWritesNothing() {
        val files = NativeTestFiles()
        val v = vault(NativeTestWrap(), files)
        assertEquals(Import.ADDRESS_MISMATCH, v.importKey(eoaB, keyA))
        assertTrue(files.map.isEmpty())
        assertTrue(v.state() is State.NoKey)
    }

    @Test
    fun malformedEoaAndKeysAreRejectedBeforeAnyWrite() {
        val files = NativeTestFiles()
        val v = vault(NativeTestWrap(), files)
        assertEquals(Import.BAD_EOA, v.importKey(eoaA.uppercase().replaceFirst("0X", "0x"), keyA))
        assertEquals(Import.BAD_EOA, v.importKey(eoaA.removePrefix("0x"), keyA))
        assertEquals(Import.BAD_KEY, v.importKey(eoaA, ByteArray(31) { 1 }))
        assertEquals(Import.BAD_KEY, v.importKey(eoaA, ByteArray(32)))
        assertTrue(files.map.isEmpty())
    }

    @Test
    fun sealFailureWritesNothing() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap().apply { failSeal = true }
        val v = vault(wrap, files)
        assertEquals(Import.STORE_FAILED, v.importKey(eoaA, keyA))
        assertTrue(files.map.isEmpty())
        assertTrue(v.state() is State.NoKey)
    }

    @Test
    fun recordWriteFailureLeavesNothing() {
        val files = NativeTestFiles().apply { failWrite = NativeWalletVault.REC }
        val v = vault(NativeTestWrap(), files)
        assertEquals(Import.STORE_FAILED, v.importKey(eoaA, keyA))
        assertTrue(files.map.isEmpty())
    }

    @Test
    fun markerWriteFailureRemovesTheUnconfirmedRecord() {
        val files = NativeTestFiles().apply { failWrite = NativeWalletVault.MARK }
        val v = vault(NativeTestWrap(), files)
        assertEquals(Import.STORE_FAILED, v.importKey(eoaA, keyA))
        assertTrue(files.map.isEmpty())
        assertTrue(v.state() is State.NoKey)
    }

    @Test
    fun readbackThatReturnsAnotherKeyRemovesTheRecord() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap().apply { openOverride = { keyB } }
        val v = vault(wrap, files)
        assertEquals(Import.READBACK_FAILED, v.importKey(eoaA, keyA))
        assertTrue(files.map.isEmpty())
        assertTrue(v.state() is State.NoKey)
    }

    @Test
    fun crashAfterTheRecordIsRecoveredToNoKeyOnNextOpen() {
        val files = NativeTestFiles().apply { crashAfterWrite = NativeWalletVault.REC }
        val wrap = NativeTestWrap()
        assertThrows(NativeTestCrash::class.java) { vault(wrap, files).importKey(eoaA, keyA) }
        assertTrue(files.map.containsKey(NativeWalletVault.REC))
        files.crashAfterWrite = null

        val restarted = vault(wrap, files)
        assertTrue(restarted.state() is State.NoKey)
        assertFalse(files.map.containsKey(NativeWalletVault.REC))
        assertNull(restarted.unlock())
    }

    /** r3nw 第 4 项: the commit record is written last, so a crash after the marker is still uncommitted and is rolled back. */
    @Test
    fun crashAfterTheMarkerIsRolledBackBecauseTheCommitIsLast() {
        val files = NativeTestFiles().apply { crashAfterWrite = NativeWalletVault.MARK }
        val wrap = NativeTestWrap()
        assertThrows(NativeTestCrash::class.java) { vault(wrap, files).importKey(eoaA, keyA) }
        files.crashAfterWrite = null

        val restarted = vault(wrap, files)
        assertTrue(restarted.state() is State.NoKey)
        assertFalse(files.map.containsKey(NativeWalletVault.REC))
        assertFalse(files.map.containsKey(NativeWalletVault.INTENT))
    }

    /** A crash after the commit record leaves a usable wallet; the intent is removed on the next start. */
    @Test
    fun crashAfterTheCommitLeavesAUsableWallet() {
        val files = NativeTestFiles().apply { crashAfterWrite = NativeWalletVault.COMMIT }
        val wrap = NativeTestWrap()
        assertThrows(NativeTestCrash::class.java) { vault(wrap, files).importKey(eoaA, keyA) }
        files.crashAfterWrite = null

        val restarted = vault(wrap, files)
        assertEquals(eoaA, (restarted.state() as State.Ready).eoa)
        assertArrayEquals(keyA, restarted.unlock())
        assertFalse(files.map.containsKey(NativeWalletVault.INTENT))
    }

    // ---- F. damaged storage locks instead of deleting ------------------------------------

    @Test
    fun markerThatDoesNotMatchLocksAndKeepsTheRecord() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val v = vault(wrap, files)
        assertEquals(Import.OK, v.importKey(eoaA, keyA))
        files.map[NativeWalletVault.MARK] = "00".toByteArray()

        val restarted = vault(wrap, files)
        assertEquals("marker_mismatch", (restarted.state() as State.Locked).reason)
        assertTrue(files.map.containsKey(NativeWalletVault.REC))
        assertNull(restarted.unlock())
        assertEquals(Import.RECORD_EXISTS, restarted.importKey(eoaB, keyB))
    }

    @Test
    fun recordThatCanNoLongerBeOpenedLocksAndKeepsTheRecord() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val v = vault(wrap, files)
        assertEquals(Import.OK, v.importKey(eoaA, keyA))
        wrap.deleteKey() // the wrapping key is gone, as after a Keystore reset

        assertEquals("unreadable", (v.state() as State.Locked).reason)
        assertTrue(files.map.containsKey(NativeWalletVault.REC))
        assertNotNull(files.map[NativeWalletVault.MARK])
    }
}
