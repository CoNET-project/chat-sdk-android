package network.conet.chat.nativekey

import network.conet.chat.nativekey.NativeImport.Code
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The import page's result to the PWA (rc2.2-qa, spec 25.52X.4): one `nativeImportResult` per submission for the open page's reqId. `eoa` is
 * carried only by `ok` and by `already_exists` when the vault can read the record (the address was derived and persisted). No key or phrase.
 * The vault is in memory; nothing touches a device or real data.
 */
class NativeImportResultTest {
    private val keyA = ByteArray(32).also { it[31] = 1 }
    private val keyAHex = "0".repeat(63) + "1"
    private val eoaA = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    private val eoaB = "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"

    private val events = mutableListOf<JSONObject>()

    @Before
    fun resetHost() {
        // Close any page left by an earlier test, then capture this test's events.
        NativeImportHost.launcher = { false }
        NativeImportHost.open("reset")
        NativeImportHost.launcher = { true }
        NativeImportHost.events = { events.add(it) }
    }

    @After
    fun detachHost() {
        NativeImportHost.launcher = null
        NativeImportHost.events = null
    }

    private fun openPage(reqId: String) {
        assertTrue("the page opens", NativeImportHost.open(reqId))
    }

    private fun assertOneEvent(code: String): JSONObject {
        assertEquals("exactly one nativeImportResult", 1, events.size)
        val e = events.single()
        assertEquals("nativeImportResult", e.getString("type"))
        assertEquals(code, e.getString("code"))
        return e
    }

    @Test
    fun okCarriesTheLowercaseEoaOfTheSavedKeyAndEndsThePage() {
        openPage("r1")
        val result = NativeImport.submit(keyAHex, null, NativeWalletVault(NativeTestWrap(), NativeTestFiles()))

        assertEquals(Code.OK, result.code)
        val e = assertOneEvent("ok")
        assertEquals("r1", e.getString("reqId"))
        assertEquals(eoaA, e.getString("eoa"))
        assertNull("the page is closed after ok", NativeImportHost.currentReqId())
    }

    @Test
    fun alreadyExistsWithAReadableRecordCarriesThePublicEoa() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoaA, keyA))
        openPage("r2")

        val result = NativeImport.submit(keyAHex, null, NativeWalletVault(wrap, files))

        assertEquals(Code.ALREADY_EXISTS, result.code)
        val e = assertOneEvent("already_exists")
        assertEquals(eoaA, e.getString("eoa"))
        assertNull("the page is closed after already_exists", NativeImportHost.currentReqId())
    }

    @Test
    fun alreadyExistsWithAnUnreadableRecordCarriesNoEoa() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoaA, keyA))
        wrap.deleteKey() // the wrapping key is gone: the record is present but cannot be read
        openPage("r3")

        val result = NativeImport.submit(keyAHex, null, NativeWalletVault(wrap, files))

        assertEquals(Code.ALREADY_EXISTS, result.code)
        val e = assertOneEvent("already_exists")
        assertFalse("no eoa when the address was not derived and read back", e.has("eoa"))
    }

    @Test
    fun aRefusedInputCarriesNoEoaAndKeepsThePageOpenForARetry() {
        openPage("r4")
        val result = NativeImport.submit("zz", null, NativeWalletVault(NativeTestWrap(), NativeTestFiles()))

        assertEquals(Code.INVALID_FORMAT, result.code)
        val e = assertOneEvent("invalid_format")
        assertFalse(e.has("eoa"))
        assertEquals("r4", NativeImportHost.currentReqId())
    }

    @Test
    fun anAddressMismatchCarriesNoEoa() {
        openPage("r5")
        val result = NativeImport.submit(keyAHex, eoaB, NativeWalletVault(NativeTestWrap(), NativeTestFiles()))

        assertEquals(Code.ADDRESS_MISMATCH, result.code)
        val e = assertOneEvent("address_mismatch")
        assertFalse(e.has("eoa"))
    }

    @Test
    fun aCancelledSubmissionEndsThePageWithCancelled() {
        openPage("r6")
        NativeImport.submit("", null, NativeWalletVault(NativeTestWrap(), NativeTestFiles()), cancelled = true)

        assertOneEvent("cancelled")
        assertNull(NativeImportHost.currentReqId())
    }

    @Test
    fun noEventIsSentWhenNoPageIsOpen() {
        NativeImport.submit(keyAHex, null, NativeWalletVault(NativeTestWrap(), NativeTestFiles()))

        assertTrue("no page, no result event", events.isEmpty())
    }

    @Test
    fun aRefusedLauncherOpensNoPageAndSendsNothing() {
        NativeImportHost.launcher = { false }
        assertFalse(NativeImportHost.open("r7"))
        assertNull(NativeImportHost.currentReqId())

        NativeImport.submit(keyAHex, null, NativeWalletVault(NativeTestWrap(), NativeTestFiles()))
        assertTrue(events.isEmpty())
    }
}
