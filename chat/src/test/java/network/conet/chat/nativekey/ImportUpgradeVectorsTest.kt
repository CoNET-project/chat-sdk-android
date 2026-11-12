package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import network.conet.chat.x21.X21Retired
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Upgrade, no-key and native import groups against `spec/import-upgrade-vectors.v1.json` (sha256 0e0a5c88…,
 * spec §25.25.6). 19 cases in five groups. The vault and the import flow are the production code; only the
 * Keystore and the files are replaced by test doubles.
 */
class ImportUpgradeVectorsTest {
    private val bytes = File(System.getenv("IMPORT_UPGRADE_VECTORS") ?: "../spec/import-upgrade-vectors.v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))
    private val cases = v.getJSONArray("cases")
    private val testEoa = v.getString("testEoa")

    private fun caseById(id: String): JSONObject {
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("id") == id) return c
        }
        throw AssertionError("no case $id")
    }

    /** The synthetic test key is the one in the import input I-1 (hex, with 0x). */
    private fun testKey(): ByteArray {
        val hex = caseById("I-1").getString("input").removePrefix("0x")
        return ConetChatCryptoUtil.hexToBytes(hex)!!
    }

    private fun presentRecord(vault: NativeWalletVault, files: NativeTestFiles) {
        assertEquals(NativeWalletVault.Import.OK, vault.importKey(testEoa, testKey()))
        assertTrue(files.map.containsKey(NativeWalletVault.REC))
    }

    @Test
    fun vectorFileIsTheCanonicalOne() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("0e0a5c88657f1a519254aae8ef9b0218614430d006fd84e58c3415493a5e928b", sha)
    }

    @Test
    fun nineteenCasesInFiveGroups() {
        assertEquals(19, cases.length())
        assertEquals(5, v.getJSONArray("groups").length())
        assertEquals(setOf("walletTransferOnce", "walletTransferStatus", "walletTransferSwitched"), X21Retired.COMMANDS)
    }

    @Test
    fun everyUpgradeAndNoKeyCaseMatches() {
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val group = c.getString("group")
            if (group == "fresh-install" || group == "upgrade-native-key" || group == "upgrade-no-key") {
                runUpgradeCase(c)
            }
        }
    }

    private fun runUpgradeCase(c: JSONObject) {
        val id = c.getString("id")
        val files = NativeTestFiles()
        val vault = NativeWalletVault(NativeTestWrap(), files)
        val hasNative = c.getJSONObject("state").getString("native") == "present"
        if (hasNative) presentRecord(vault, files)
        val before = files.map[NativeWalletVault.REC]?.copyOf()
        val expect = c.getJSONObject("expect")
        val action = c.getString("action")

        val reply: NativeOutcome = if (X21Retired.handles(action)) {
            // X-21 is retired: the three commands answer not_supported and touch nothing.
            NativeOutcome(X21Retired.ERROR)
        } else {
            assertEquals("$id action", "walletAddress", action)
            NativeWalletCommands.walletAddress(vault)
        }

        assertEquals("$id code", expect.getString("code"), reply.code)
        if (expect.has("address")) assertEquals("$id address", expect.getString("address"), reply.address)
        if (expect.has("dataReturned") && !expect.getBoolean("dataReturned")) {
            assertNull("$id returned data", reply.address)
            assertNull("$id returned value", reply.value)
        }
        if (expect.has("signed") && !expect.getBoolean("signed")) assertNull("$id signed", reply.value)

        val after = files.map[NativeWalletVault.REC]
        when (expect.optString("nativeRecordAfter", "")) {
            "present" -> {
                assertTrue("$id record should remain", after != null)
                if (before != null) assertArrayEquals("$id record must not change", before, after)
            }
            "none" -> assertNull("$id record should not exist", after)
        }
        // No key bytes in any reply.
        val keyHex = ConetChatCryptoUtil.toHex(testKey())
        assertFalse("$id key in reply", (reply.value ?: "").contains(keyHex))
        assertFalse("$id key in reply", (reply.address ?: "").contains(keyHex))
    }

    @Test
    fun everyImportCaseMatches() {
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val group = c.getString("group")
            if (group == "import-success" || group == "import-failure") runImportCase(c)
        }
    }

    private fun runImportCase(c: JSONObject) {
        val id = c.getString("id")
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = NativeWalletVault(wrap, files)
        val ctx = c.optJSONObject("ctx") ?: JSONObject()
        val expect = c.getJSONObject("expect")

        if (ctx.optBoolean("nativeRecord", false)) presentRecord(vault, files)
        val before = files.map[NativeWalletVault.REC]?.copyOf()
        if (ctx.optBoolean("writeFail", false)) files.failWrite = NativeWalletVault.REC
        if (ctx.optBoolean("readbackFail", false)) wrap.openOverride = { ByteArray(32) { 1 } }

        val result = NativeImport.submit(
            raw = c.getString("input"),
            expectedEoa = if (ctx.has("expectedEoa")) ctx.getString("expectedEoa") else null,
            vault = vault,
            cancelled = ctx.optBoolean("cancelled", false),
        )

        assertEquals("$id code", expect.getString("code"), result.code.wire)
        if (expect.has("eoa")) assertEquals("$id eoa", expect.getString("eoa"), result.eoa)

        val after = files.map[NativeWalletVault.REC]
        when (expect.getString("record")) {
            "written" -> {
                assertTrue("$id record missing", after != null)
                val state = vault.state()
                assertTrue("$id readback", state is NativeWalletVault.State.Ready)
                assertEquals("$id readback eoa", expect.getString("eoa"), (state as NativeWalletVault.State.Ready).eoa)
            }
            "none" -> {
                if (before == null) assertNull("$id leftover record", after)
            }
        }
        if (expect.optString("nativeRecordAfter") == "present") {
            assertTrue("$id original record removed", after != null)
            assertArrayEquals("$id original record changed", before, after)
        }
        if (expect.optBoolean("rollback", false)) {
            assertNull("$id rollback left a record", after)
            assertNull("$id rollback left a marker", files.map[NativeWalletVault.MARK])
        }
        // The result carries only the code and the derived EOA, never the input.
        assertFalse("$id input echoed", (result.eoa ?: "").contains(c.getString("input").trim()))
    }
}
