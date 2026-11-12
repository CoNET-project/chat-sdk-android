package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Spec §25.26.3 and T-159: the mnemonic import group (MI-1 to MI-8) in `spec/mnemonic-derivation-vectors.v1.json`.
 * The vault and the import flow are the production code; the Keystore and the files are test doubles. A phrase
 * must never reach any stored byte in the clear, and the stored key must be the derived key.
 */
class NativeMnemonicImportTest {
    private val v = JSONObject(
        String(File(System.getenv("MNEMONIC_VECTORS") ?: "../spec/mnemonic-derivation-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val cases = v.getJSONArray("importMnemonicMode")

    private fun contains(hay: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || hay.size < needle.size) return false
        for (i in 0..hay.size - needle.size) {
            var ok = true
            for (j in needle.indices) {
                if (hay[i + j] != needle[j]) {
                    ok = false
                    break
                }
            }
            if (ok) return true
        }
        return false
    }

    @Test
    fun eightImportCasesMatch() {
        assertEquals(8, cases.length())
        for (i in 0 until cases.length()) runCase(cases.getJSONObject(i))
    }

    private fun runCase(c: JSONObject) {
        val id = c.getString("id")
        val input = c.getString("input")
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = NativeWalletVault(wrap, files)
        val ctx = c.optJSONObject("ctx") ?: JSONObject()
        val expect = c.getJSONObject("expect")

        if (ctx.optBoolean("nativeRecord", false)) {
            // An existing record for the same account: the phrase's own key, imported in key mode.
            val k = MnemonicDerivation.deriveKey(input)!!
            try {
                val eoa = WalletAddress.fromPrivateKey(k)!!
                assertEquals("$id setup", NativeWalletVault.Import.OK, vault.importKey(eoa, k))
            } finally {
                k.fill(0)
            }
        }
        val before = files.map[NativeWalletVault.REC]?.copyOf()
        if (ctx.optBoolean("writeFail", false)) files.failWrite = NativeWalletVault.REC
        if (ctx.optBoolean("readbackFail", false)) wrap.openOverride = { ByteArray(32) { 1 } }

        val result = NativeImport.submitMnemonic(
            raw = input,
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
                // The stored key is the derived key, byte for byte (25.26.3).
                val derived = MnemonicDerivation.deriveKey(input)!!
                val unlocked = vault.unlock()!!
                try {
                    assertArrayEquals("$id stored key", derived, unlocked)
                } finally {
                    derived.fill(0)
                    unlocked.fill(0)
                }
            }
            "none" -> if (before == null) assertNull("$id leftover record", after)
        }
        when (expect.optString("nativeRecordAfter", "")) {
            "present" -> {
                assertTrue("$id record missing after import", after != null)
                // When a record existed before the call, it must be the same bytes afterwards (MI-4).
                if (before != null) assertArrayEquals("$id original record changed", before, after)
            }
            "none" -> if (before == null) assertNull("$id record should not exist", after)
        }
        if (expect.optBoolean("rollback", false)) {
            assertNull("$id rollback left a record", after)
            assertNull("$id rollback left a marker", files.map[NativeWalletVault.MARK])
        }

        // mnemonicPersisted=false: no stored byte contains the phrase in the clear, and nothing echoes it back.
        val phrase = input.toByteArray(Charsets.UTF_8)
        for ((name, stored) in files.map) {
            assertFalse("$id phrase stored in $name", contains(stored, phrase))
        }
        assertFalse("$id phrase echoed", (result.eoa ?: "").contains("abandon"))
    }
}
