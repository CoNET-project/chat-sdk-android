package network.conet.chat.nativekey

import network.conet.chat.nativekey.NativeWalletVault.MnemonicRead
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The save-recovery-phrase read (spec 25.52PY.14, PY.16, r3rq, r3rt): the phrase goes only to the native view, is unavailable for any
 * other purpose or account, is cleared on close, and a failed read sets no backup flag.
 */
class BackupDisplayTest {
    private val eoa = "0x" + "a".repeat(40)
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    @Test
    fun theStoredPhraseIsReturnedForTheAccountAndThePurpose() {
        val h = readBackupPhrase(eoa, RecoveryPhraseForBackup.PURPOSE) { MnemonicRead.Stored(eoa, phrase) }
        assertNotNull(h)
        assertEquals(phrase, String(h!!.chars()!!))
    }

    @Test
    fun closeClearsTheBufferAndTheHandle() {
        val h = readBackupPhrase(eoa, RecoveryPhraseForBackup.PURPOSE) { MnemonicRead.Stored(eoa, phrase) }!!
        val buffer = h.chars()!!
        h.close()
        assertTrue("the buffer is zeroed", buffer.all { it == '\u0000' })
        assertNull("the handle no longer holds the phrase", h.chars())
        assertEquals("BackupPhrase(redacted)", h.toString())
    }

    @Test
    fun anotherPurposeIsUnavailableAndNeverReadsTheVault() {
        var read = false
        val h = readBackupPhrase(eoa, "export") {
            read = true
            MnemonicRead.Stored(eoa, phrase)
        }
        assertNull(h)
        assertFalse("the vault is not read for another purpose", read)
    }

    @Test
    fun anotherAccountIsUnavailable() {
        val other = "0x" + "b".repeat(40)
        assertNull(readBackupPhrase(eoa, RecoveryPhraseForBackup.PURPOSE) { MnemonicRead.Stored(other, phrase) })
    }

    @Test
    fun aKeyOnlyOrUnreadableAccountIsUnavailable() {
        assertNull("a key-only account has no phrase", readBackupPhrase(eoa, RecoveryPhraseForBackup.PURPOSE) { MnemonicRead.Missing })
        assertNull("an unverifiable record is unavailable", readBackupPhrase(eoa, RecoveryPhraseForBackup.PURPOSE) { MnemonicRead.Unavailable })
    }

    @Test
    fun aFailedReadSetsNoBackupFlag() {
        val files = NativeTestFiles()
        val h = readBackupPhrase(eoa, RecoveryPhraseForBackup.PURPOSE) { MnemonicRead.Unavailable }
        assertNull(h)
        assertTrue("the read failed, so nothing was written and the flag stays unset", files.map.isEmpty())
        assertFalse(ClearFlagFiles(files).recoveryBackupConfirmed(eoa))
    }

    @Test
    fun theLegacyReportKeepsOnlyTheThreeValues() {
        val files = NativeTestFiles()
        val flags = ClearFlagFiles(files)
        for (v in listOf("found", "absent", "unreadable")) {
            assertEquals("ok", reportLegacyValue(flags, v))
            assertEquals(v, String(files.map[ClearFlagFiles.LEGACY_REPORT]!!, Charsets.UTF_8))
        }
        assertEquals("bad_request", reportLegacyValue(flags, "Found"))
        assertEquals("bad_request", reportLegacyValue(flags, "present"))
        assertEquals("the last valid report stays", "unreadable", String(files.map[ClearFlagFiles.LEGACY_REPORT]!!, Charsets.UTF_8))
    }
}
