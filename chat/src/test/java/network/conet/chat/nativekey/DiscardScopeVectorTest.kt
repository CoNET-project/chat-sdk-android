package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * DR cases of account-select-vectors.v2.json (sha256 a9b8d563…, original, not changed), with the DR override (sha256 f0f7f002…) laid over the
 * same ids: the override's new_expect replaces the original expect for DR-01, 06, 07, 09, 10. Read from test resources.
 *
 * The SDK holds one native account, so each case's native side is one key-only record (or one phrase account for DR-05). Its signal is derived
 * from the case's native and PWA reads. Expectations checked: the store bytes are unchanged (the override's rule: nothing is deleted on this
 * path) and the private records are retained. Atomic-delete cases (DR-09, DR-10) run the same signal: the store must not change.
 * The original's deletedIds for DR-01, 06, 07 are replaced by the override ([]); DR-02, 03, 04, 05, 08 are unchanged and must also delete nothing.
 */
class DiscardScopeVectorTest {
    private val wrap = NativeTestWrap()
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private fun load(file: String): JSONObject =
        JSONObject(javaClass.classLoader!!.getResourceAsStream("spec-vectors/$file")!!.bufferedReader(Charsets.UTF_8).use { it.readText() })

    private fun caseById(doc: JSONObject, id: String): JSONObject {
        val arr = doc.getJSONArray("cases")
        return (0 until arr.length()).map { arr.getJSONObject(it) }.first { it.getString("id") == id }
    }

    /** The override's new_expect for [id], or the original expect when the override does not name it. */
    private fun effectiveExpect(orig: JSONObject, override: JSONObject, id: String): JSONObject {
        val ov = override.getJSONArray("overrides")
        for (i in 0 until ov.length()) {
            val o = ov.getJSONObject(i)
            if (o.getString("id") == id) return o.getJSONObject("new_expect")
        }
        return caseById(orig, id).getJSONObject("expect")
    }

    private fun keyOnlyStore(): NativeTestFiles {
        val files = NativeTestFiles()
        val k = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(checkNotNull(WalletAddress.fromPrivateKey(k)), k))
        files.map.remove(NativeWalletVault.MNEM)
        return files
    }

    private fun phraseStore(): NativeTestFiles {
        val files = NativeTestFiles()
        val k = checkNotNull(MnemonicDerivation.deriveKey(phrase))
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(checkNotNull(WalletAddress.fromPrivateKey(k)), k, phrase))
        return files
    }

    /** The explicit-empty signal of the PWA side and the native state label, from the case's reads. */
    private fun signal(input: JSONObject): Pair<Boolean, String> {
        // DR-07 and DR-08 are simulations: "x" holds the two sides as words ("empty", "unknown").
        input.optJSONObject("x")?.let { x ->
            val nativeState = if (x.getString("native") == "unknown") "unknown" else "explicit_empty"
            return (x.getString("pwa") == "empty") to nativeState
        }
        val native = input.getJSONObject("native")
        val pwa = input.getJSONObject("pwa")
        val nativeState = when {
            !native.getBoolean("readOk") -> "unknown"
            native.getJSONArray("mn").length() > 0 -> "valid"
            else -> "explicit_empty"
        }
        val pwaExplicitEmpty = pwa.getBoolean("readOk") && pwa.getJSONArray("mn").length() == 0
        return pwaExplicitEmpty to nativeState
    }

    @Test fun drCasesDeleteNothingAndKeepTheRecords() {
        val orig = load("account-select-vectors.v2.json")
        val override = load("alignment-DR-override.json")
        for (id in listOf("DR-01", "DR-02", "DR-03", "DR-04", "DR-05", "DR-06", "DR-07", "DR-08")) {
            val c = caseById(orig, id)
            val input = c.getJSONObject("input")
            val expect = effectiveExpect(orig, override, id)
            val hasPhrase = input.optJSONObject("native")?.optJSONArray("mn")?.length()?.let { it > 0 } == true ||
                input.optJSONObject("pwa")?.optJSONArray("mn")?.length()?.let { it > 0 } == true
            val files = if (hasPhrase) phraseStore() else keyOnlyStore()
            val before = files.names().associateWith { files.read(it)!! }
            val (pwaEmpty, nativeState) = signal(input)
            val outcome = NativeWalletVault(wrap, files).discardPrivateOnly(pwaExplicitEmpty = pwaEmpty, nativeState = nativeState)
            assertEquals("$id outcome", NativeWalletVault.DiscardOutcome.NOT_DROPPED, outcome)
            // Every expect of this group deletes nothing: the original's [] for DR-02..05 and 08, the override's [] for DR-01, 06, 07.
            assertEquals("$id deletedIds", 0, expect.getJSONArray("deletedIds").length())
            before.forEach { (n, b) -> assertArrayEquals("$id $n unchanged", b, files.read(n)) }
            assertTrue("$id the private record is retained", files.names().any { it == NativeWalletVault.REC } || hasPhrase)
        }
    }

    @Test fun atomicDeleteCasesLeaveTheStoreUnchanged() {
        val orig = load("account-select-vectors.v2.json")
        val override = load("alignment-DR-override.json")
        for (id in listOf("DR-09", "DR-10")) {
            val expect = effectiveExpect(orig, override, id)
            assertEquals("$id: no deletion is performed", false, expect.getBoolean("deletion_performed"))
            val files = keyOnlyStore()
            val before = files.names().associateWith { files.read(it)!! }
            val outcome = NativeWalletVault(wrap, files).discardPrivateOnly(pwaExplicitEmpty = true, nativeState = "explicit_empty")
            assertEquals("$id outcome", NativeWalletVault.DiscardOutcome.NOT_DROPPED, outcome)
            before.forEach { (n, b) -> assertArrayEquals("$id $n unchanged", b, files.read(n)) }
            assertNotNull("$id private record kept", files.read(NativeWalletVault.REC))
        }
    }
}
