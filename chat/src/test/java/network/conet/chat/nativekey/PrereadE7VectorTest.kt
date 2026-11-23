package network.conet.chat.nativekey

import network.conet.chat.nativekey.MnemonicPreread.Answer
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * Data-driven E7 and E7.1 (spec-59e-synthetic-vectors.v3.3.1-E7-add.json, ...E7.1-add.json, read from test resources). For each native case the
 * pre-state is built from the vector's pre fields, the pre-read answer is taken from MnemonicPreread.vaultAnswerOrUnknown, and it is compared with
 * expect.native_answer. The keep-everything rule is checked on the bytes. PWA-side and route cases (P-01..P-03, P-06..P-08, E71 PWA steps) have no
 * native answer and are listed as not applicable to the SDK.
 */
class PrereadE7VectorTest {
    private val goodPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val badPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    private val wrap = NativeTestWrap()

    private fun cases(file: String): Map<String, JSONObject> {
        val text = javaClass.classLoader!!.getResourceAsStream("spec-vectors/$file")!!.bufferedReader(Charsets.UTF_8).use { it.readText() }
        val arr = JSONObject(text).getJSONArray("cases")
        return (0 until arr.length()).map { arr.getJSONObject(it) }.associateBy { it.getString("id") }
    }

    private fun digest(b: ByteArray) = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private class ScriptedFiles(val inner: NativeTestFiles, val onMnemRead: (Int) -> ByteArray?, val failAll: Boolean) : VaultFiles {
        var mnemReads = 0
        override fun read(name: String): ByteArray? {
            if (failAll) throw IOException("enumeration failed")
            if (name == NativeWalletVault.MNEM) {
                mnemReads++
                return onMnemRead(mnemReads)
            }
            return inner.read(name)
        }
        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)
        override fun delete(name: String) = inner.delete(name)
        override fun names(): List<String> = inner.names()
        override fun rename(from: String, to: String) = inner.rename(from, to)
    }

    private fun mnemItem(eoa: String, phrase: String): ByteArray {
        val m = NativeWalletVault::class.java.getDeclaredMethod("encodeMnemonic", String::class.java, ByteArray::class.java)
        m.isAccessible = true
        val sealed = wrap.seal(NativeWalletVault.mnemAad(eoa), phrase.toByteArray(Charsets.UTF_8))
        return m.invoke(NativeWalletVault(wrap, NativeTestFiles()), eoa, sealed) as ByteArray
    }

    /** The answer for one native case, and the bytes that must survive it. */
    private fun run(c: JSONObject): Pair<Answer, Map<String, String>> {
        val pre = c.getJSONObject("pre")
        val inner = NativeTestFiles()
        val (eoa, key) = checkNotNull(MnemonicDerivation.deriveKey(goodPhrase)).let { k -> checkNotNull(WalletAddress.fromPrivateKey(k)) to k }
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, inner).importKey(eoa, key))
        val rec = inner.map[NativeWalletVault.REC]!!
        val before = inner.map.mapValues { digest(it.value) }
        MnemonicPreread.resetForTests()
        NativeWalletVault.resetLaunchForTests()
        if (pre.getString("native") == "private_key_only") {
            val failAll = pre.has("enumeration_ok") && !pre.getBoolean("enumeration_ok")
            val files = ScriptedFiles(inner, { inner.map[NativeWalletVault.MNEM] }, failAll)
            return MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)) to before
        }
        // mnemonic_item_present: build the item the vector describes, with its marker, then script the reads.
        // The defect the vector names: checksum (bip39 or bip39_checksum), word list, or word count. The fields name the defect, not the result.
        val phrase = when {
            pre.has("bip39_checksum") || pre.has("bip39") -> badPhrase
            pre.has("wordlist") -> "notaword " + badPhrase.substringAfter(" ")
            pre.has("word_count") -> "abandon abandon abandon"
            else -> goodPhrase
        }
        val badItem = mnemItem(eoa, phrase)
        val goodItem = mnemItem(eoa, goodPhrase)
        inner.map[NativeWalletVault.MNEM] = badItem
        inner.map[NativeWalletVault.MARK] = NativeWalletVault.markerOf(rec, badItem)
        if (pre.optString("marker") == "unsettled_or_locked_or_snapshot_unknown") inner.map[NativeWalletVault.PENDING] = "{}".toByteArray()
        val beforeAll = inner.map.mapValues { digest(it.value) }
        val reread1 = pre.optString("reread_1", "")
        val reread2 = pre.optString("reread_2", "")
        val failRead = pre.optString("read") == "exception"
        // Read order of one pre-read: 1 = the first phrase read, 2 = the second phrase read (N5). The pre-read reads no record (E9.1).
        val script: (Int) -> ByteArray? = { n ->
            when {
                failRead -> throw IOException("read failed")
                n == 2 && reread2 == "ok_valid" -> goodItem
                else -> badItem
            }
        }
        val files = ScriptedFiles(inner, script, false)
        val answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files))
        return answer to beforeAll
    }

    private fun assertCase(id: String, c: JSONObject) {
        val (answer, _) = run(c)
        // P-14 is superseded by the decision of 2026-11-17 (a half-written window is ignorable): an unsettled marker alone is not unknown.
        val want = if (id == "P-14") "absent" else nativeWanted(c)!!
        val got = when (answer) {
            Answer.Absent -> "absent"
            Answer.Unknown -> "unknown"
            is Answer.Valid -> "valid"
        }
        assertEquals("$id native answer", want, got)
    }

    /** The expected native answer: native_answer, or the judgement word of the P-04/P-05 cases (explicit_no_valid_mnemonic → absent). */
    private fun nativeWanted(c: JSONObject): String? {
        val e = c.optJSONObject("expect") ?: return null
        if (e.has("native_answer")) return e.getString("native_answer")
        return when (e.optString("native_judgement")) {
            "explicit_no_valid_mnemonic" -> "absent"
            "unknown" -> "unknown"
            else -> null
        }
    }

    private val notForTheSdk = setOf("P-01", "P-02", "P-03", "P-06", "P-07", "P-08", "E71-03")

    @Test fun e7VectorsForTheNativeAnswer() {
        val doc = cases("spec-59e-synthetic-vectors.v3.3.1-E7-add.json")
        for ((id, c) in doc) {
            if (id in notForTheSdk) continue
            if (c.optJSONObject("expect")?.has("native_answer") != true) continue
            if (c.getJSONObject("pre").optString("native") == "" ) continue
            assertCase(id, c)
        }
    }

    @Test fun e71VectorsForTheNativeAnswer() {
        val doc = cases("spec-59e-synthetic-vectors.v3.3.1-E7.1-add.json")
        for ((id, c) in doc) {
            if (id in notForTheSdk) continue
            if (nativeWanted(c) == null) continue
            if (c.getJSONObject("pre").optString("native") == "") continue
            assertCase(id, c)
        }
    }
}
