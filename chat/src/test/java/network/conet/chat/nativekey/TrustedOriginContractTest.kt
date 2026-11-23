package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/**
 * The trustedOrigin contract (next-version typed channel noted): a request is trusted only when the marker is the boolean
 * `true`. A missing marker, `false`, a string, or any other value is refused for the three page-sync commands, before any read or write. The shell
 * strips the page's own value on every page entry; these tests fix the SDK side of that contract.
 */
class TrustedOriginContractTest {

    private val eoa = "0x1111111111111111111111111111111111111111"
    private val phrase = "SYNTHETIC-TEST-PHRASE-NOT-A-WALLET"

    @Before
    fun baseline() {
        MnemonicPreread.resetForTests()
        assertTrue(MnemonicPreread.accept(0L))
    }

    private fun body(marker: Any?): JSONObject {
        val b = JSONObject().put("type", "nativeMnemonicPreread").put("reqId", "np").put("seq", 1)
        when (marker) {
            null -> Unit
            else -> b.put("trustedOrigin", marker)
        }
        return b
    }

    /** Positive: only the boolean true passes admit; a missing marker is refused. */
    @Test
    fun onlyTheBooleanTrueIsTrusted() {
        assertTrue(NativeSyncAck.trusted(body(true)))
        assertNull(NativeSyncAck.admit(body(true)))
        assertFalse(NativeSyncAck.trusted(body(null)))
        assertEquals(NativeSyncAck.UNTRUSTED_SOURCE, NativeSyncAck.admit(body(null)))
    }

    /** Negative: `false`, a string "true", and a number 1 are all refused with untrusted_source. */
    @Test
    fun falseAndNonBooleanMarkersAreRefused() {
        for (marker in listOf(false, "true", 1)) {
            assertFalse("marker $marker", NativeSyncAck.trusted(body(marker)))
            assertEquals("marker $marker", NativeSyncAck.UNTRUSTED_SOURCE, NativeSyncAck.admit(body(marker)))
        }
    }

    /** Negative: nativeMnemonicPreread with a missing or false marker answers untrusted_source and reads nothing. */
    @Test
    fun preReadWithoutATrueMarkerReadsNothing() {
        for (marker in listOf(null, false)) {
            var reads = 0
            val p = NativeSyncAck.prereadStorePayload("np", body(marker), current = {
                reads++
                MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, phrase, 1)
            })
            assertFalse(p.getBoolean("ok"))
            assertEquals(NativeSyncAck.UNTRUSTED_SOURCE, p.getString("error"))
            assertEquals(0, reads)
            assertFalse(p.toString().contains(phrase))
        }
    }

    /** Source guard: pwaWalletSync and pwaEmptySignal call admit before any credential check, store write or vault access. */
    @Test
    fun theTwoWriteCommandsAdmitBeforeAnyWork() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        val sync = module.substring(module.indexOf("private fun pwaWalletSyncCommand("), module.indexOf("private fun pwaWalletSyncCipher("))
        val admitAt = sync.indexOf("NativeSyncAck.admit(body)")
        assertTrue("pwaWalletSync admits the trusted marker", admitAt >= 0)
        assertTrue("admit precedes the credential check", admitAt < sync.indexOf("NativeSyncAck.credentialRefusal("))
        assertTrue("admit precedes the store write", admitAt < sync.indexOf("MnemonicSetStore(File("))
        val empty = module.substring(module.indexOf("private fun pwaEmptySignalCommand("), module.indexOf("private fun pwaEmptySignalCommand(") + 400)
        assertTrue("pwaEmptySignal admits first", empty.indexOf("NativeSyncAck.admit(body)") < empty.indexOf("credentialRefusal("))
    }
}
