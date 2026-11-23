package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The QA reason codes of an unreadable record (VaultDiagnostic). The keystore is not touched: the alias presence is an input. QA build only. */
class VaultDiagnosticTest {
    private val eoa = "0x" + "ab".repeat(20)

    @Test
    fun anUnreadableRecordWithoutTheAliasIsWrapKeyMissing() {
        assertEquals(VaultDiagnostic.WRAP_KEY_MISSING, VaultDiagnostic.classify(NativeWalletVault.State.Locked("unreadable"), aliasPresent = false, recordShapeOk = true))
        assertEquals(VaultDiagnostic.WRAP_KEY_MISSING, VaultDiagnostic.classify(NativeWalletVault.State.Locked("unreadable"), aliasPresent = false, recordShapeOk = false))
    }

    @Test
    fun anUnreadableRecordWithTheAliasAndAValidShapeIsAeadFailed() {
        assertEquals(VaultDiagnostic.AEAD_FAILED, VaultDiagnostic.classify(NativeWalletVault.State.Locked("unreadable"), aliasPresent = true, recordShapeOk = true))
    }

    @Test
    fun anUnreadableRecordWithAnInvalidShapeIsOther() {
        assertEquals(VaultDiagnostic.OTHER, VaultDiagnostic.classify(NativeWalletVault.State.Locked("unreadable"), aliasPresent = true, recordShapeOk = false))
    }

    @Test
    fun markerMismatchIsItsOwnCode() {
        assertEquals(VaultDiagnostic.MARKER_MISMATCH, VaultDiagnostic.classify(NativeWalletVault.State.Locked("marker_mismatch"), aliasPresent = true, recordShapeOk = true))
    }

    /** An unknown keystore answer is never a missing key: only a normal enumeration that answers false is wrap_key_missing. */
    @Test
    fun aKeystoreThatCannotBeQueriedIsReadFailedNeverWrapKeyMissing() {
        assertEquals(VaultDiagnostic.READ_FAILED, VaultDiagnostic.classify(NativeWalletVault.State.Locked("unreadable"), aliasPresent = null, recordShapeOk = true))
        assertEquals(VaultDiagnostic.READ_FAILED, VaultDiagnostic.classify(NativeWalletVault.State.Locked("unreadable"), aliasPresent = null, recordShapeOk = null))
        assertEquals(VaultDiagnostic.WRAP_KEY_MISSING, VaultDiagnostic.classify(NativeWalletVault.State.Locked("unreadable"), aliasPresent = false, recordShapeOk = null))
    }

    /** A record that cannot be read is unknown with an alias present: read_failed, never aead_failed or other. */
    @Test
    fun aRecordThatCannotBeReadIsReadFailed() {
        assertEquals(VaultDiagnostic.READ_FAILED, VaultDiagnostic.classify(NativeWalletVault.State.Locked("unreadable"), aliasPresent = true, recordShapeOk = null))
        assertEquals(VaultDiagnostic.READ_FAILED, VaultDiagnostic.classify(null, aliasPresent = false, recordShapeOk = null))
    }

    @Test
    fun aReadableOrAbsentRecordIsNone() {
        assertEquals(VaultDiagnostic.NONE, VaultDiagnostic.classify(NativeWalletVault.State.Ready(eoa), aliasPresent = true, recordShapeOk = true))
        assertEquals(VaultDiagnostic.NONE, VaultDiagnostic.classify(NativeWalletVault.State.NoKey, aliasPresent = false, recordShapeOk = false))
    }

    @Test
    fun anUnknownSnapshotIsReadFailedAndOtherLocksAreOther() {
        assertEquals(VaultDiagnostic.READ_FAILED, VaultDiagnostic.classify(null, aliasPresent = true, recordShapeOk = true))
        assertEquals(VaultDiagnostic.OTHER, VaultDiagnostic.classify(NativeWalletVault.State.Locked("rollback_pending"), aliasPresent = true, recordShapeOk = true))
    }

    @Test
    fun theRecordShapeCheckAcceptsOnlyTheStoredFormat() {
        val good = JSONObject().put("record", NativeWalletVault.RECORD_VERSION).put("eoa", eoa).put("sealed", "00ff").toString().toByteArray()
        assertEquals(true, VaultDiagnostic.recordShapeOk(good))
        assertEquals(false, VaultDiagnostic.recordShapeOk(null))
        assertEquals(false, VaultDiagnostic.recordShapeOk("not json".toByteArray()))
        assertEquals(false, VaultDiagnostic.recordShapeOk(JSONObject().put("record", 99).put("eoa", eoa).put("sealed", "00").toString().toByteArray()))
        assertEquals(false, VaultDiagnostic.recordShapeOk(JSONObject().put("record", NativeWalletVault.RECORD_VERSION).put("eoa", "0xABC").put("sealed", "00").toString().toByteArray()))
        assertEquals(false, VaultDiagnostic.recordShapeOk(JSONObject().put("record", NativeWalletVault.RECORD_VERSION).put("eoa", eoa).put("sealed", "zz").toString().toByteArray()))
    }

    /** A read that throws is named by its exception class only: no message, no path, no content. */
    @Test
    fun aFileCategoryNamesTheExceptionClassAndNeverTheContent() {
        assertEquals("absent", VaultDiagnostic.fileCategory(FakeFiles(null), NativeWalletVault.REC))
        assertEquals("fail:IOException", VaultDiagnostic.fileCategory(FakeFiles(NativeWalletVault.REC), NativeWalletVault.REC))
    }

    /** A vault file store where one name throws on read and every other name is absent. */
    private class FakeFiles(private val failOn: String?) : VaultFiles {
        override fun read(name: String): ByteArray? {
            if (name == failOn) throw java.io.IOException("fake")
            return null
        }

        override fun write(name: String, bytes: ByteArray) = Unit

        override fun delete(name: String) = Unit
    }

    /** The probe's state codes carry the kind or the reason only: never the EOA. */
    @Test
    fun theStateCodeNeverCarriesTheEoa() {
        assertEquals("ready", VaultDiagnostic.describe(NativeWalletVault.State.Ready(eoa)))
        assertEquals("nokey", VaultDiagnostic.describe(NativeWalletVault.State.NoKey))
        assertEquals("locked:unreadable", VaultDiagnostic.describe(NativeWalletVault.State.Locked("unreadable")))
        assertFalse(VaultDiagnostic.describe(NativeWalletVault.State.Ready(eoa)).contains("ab"))
    }
}
