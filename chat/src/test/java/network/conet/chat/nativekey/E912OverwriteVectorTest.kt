package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * E912-02-OW (project 2026-11-18): the same scenario as E912-02, built on the real overwrite path and carrying the new overwrite marker. The
 * vector file is read from the resources; the shared 2026-11-17 file is not changed and E912-02 keeps its valid expectation there.
 */
class E912OverwriteVectorTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val wrap = NativeTestWrap()
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))
    private val presentWrap: KeyWrap = object : KeyWrap by wrap {
        override fun presence(): WrapKeyPresence = WrapKeyPresence.PRESENT
    }

    private fun mnemRecord(eoa: String, text: String?, corrupt: Boolean): ByteArray {
        val sealed = if (corrupt) "00".repeat(40) else ConetChatCryptoUtil.toHex(wrap.seal(NativeWalletVault.mnemAad(eoa), text!!.toByteArray(Charsets.UTF_8)))
        return JSONObject().put("record", NativeWalletVault.RECORD_VERSION).put("eoa", eoa).put("sealed", sealed).toString().toByteArray(Charsets.UTF_8)
    }

    /** The real overwrite window: replaceWithIsolation crashes after the new record is written. */
    private fun overwriteWindowAfterCrash(): NativeTestFiles {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(phraseA), keyOf(phraseA), phraseA))
        files.crashAfterWrite = NativeWalletVault.REC
        try {
            NativeWalletVault(wrap, files).syncPhrase(eoaOf(phraseB), keyOf(phraseB), phraseB)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        return files
    }

    @Test fun e912OwOverwriteVectorMatchesItsFileExpectationAndIsBuiltOnTheRealPath() {
        val text = javaClass.getResourceAsStream("/spec-vectors/spec-59e-synthetic-vectors.v3.3.1-E9.1.2-v3.3-add.json")!!.bufferedReader(Charsets.UTF_8).readText()
        val cases = JSONObject(text).getJSONArray("cases")
        val c = (0 until cases.length()).map { cases.getJSONObject(it) }.single { it.getString("id") == "E912-02-OW" }
        val expected = c.getJSONObject("expect").getString("classification")
        val files = overwriteWindowAfterCrash()
        // The listed isolated phrase copy is corrupt (deterministic, the key is present); another isolated copy holds A's valid phrase.
        val listed = files.map.keys.single { it.startsWith("${NativeWalletVault.MNEM}.isolated.") }
        files.map[listed] = mnemRecord(eoaOf(phraseA), null, corrupt = true)
        files.map["${NativeWalletVault.MNEM}.isolated.20261118T000000Z.feedface"] = mnemRecord(eoaOf(phraseA), phraseA, corrupt = false)
        val marker = JSONObject(String(files.map.getValue(NativeWalletVault.PENDING), Charsets.UTF_8))
        assertTrue("the real path wrote the overwrite field", marker.optBoolean("overwrite", false))
        // The expectation is read from the vector file, not hard-coded: unknown, valid, or absent.
        val answer = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(presentWrap, files))
        val actual = when (answer) {
            is MnemonicPreread.Answer.Unknown -> "unknown"
            is MnemonicPreread.Answer.Valid -> "valid"
            is MnemonicPreread.Answer.Absent -> "absent"
        }
        assertEquals("E912-02-OW: the answer equals the file's expectation", expected, actual)
    }
}
