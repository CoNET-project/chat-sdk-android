package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import network.conet.chat.nativekey.MnemonicPreread.Answer
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * Data-driven E9.1.2 vectors (erratum 2026-11-17, spec-59e-synthetic-vectors.v3.3.1-E9.1.2-add.json, vendored): a listed entry's read failure is
 * ignored only when it is deterministic (E912-02, E912-03); a temporary failure (locked device, keystore unavailable, key missing with the record
 * present) is unknown (E912-01, E912-04). Nothing is deleted.
 */
class E912VectorsTest {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))

    /** A present key: an authentication failure is deterministic. */
    private val presentWrap: KeyWrap = object : KeyWrap by wrap {
        override fun presence(): WrapKeyPresence = WrapKeyPresence.PRESENT
    }

    /** The key is missing while the record exists: open returns null and the presence is confirmed absent. */
    private val keyMissingWrap: KeyWrap = object : KeyWrap by wrap {
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = null
        override fun presence(): WrapKeyPresence = WrapKeyPresence.CONFIRMED_ABSENT
    }

    private fun mnemRecord(eoa: String, text: String?, corrupt: Boolean): ByteArray {
        val sealed = if (corrupt) "00".repeat(40) else ConetChatCryptoUtil.toHex(wrap.seal(NativeWalletVault.mnemAad(eoa), text!!.toByteArray(Charsets.UTF_8)))
        return JSONObject().put("record", NativeWalletVault.RECORD_VERSION).put("eoa", eoa).put("sealed", sealed).toString().toByteArray(Charsets.UTF_8)
    }

    /** A pending marker that lists the fixed mnemonic entry (not a keep-only residue). */
    private fun markedFiles(mnem: ByteArray?): NativeTestFiles {
        val files = NativeTestFiles()
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-17T00:00:00Z").put("eoa", eoaOf(phraseA))
            .put("preWriteAliasAbsent", false).put("newRecordSha", JSONObject.NULL)
            .put("items", JSONArray().put(JSONObject().put("name", NativeWalletVault.MNEM).put("isolated", "${NativeWalletVault.MNEM}.isolated.20261117T000000Z.00000000")
                .put("oldSha", "00".repeat(32))))
            .toString().toByteArray(Charsets.UTF_8)
        if (mnem != null) files.map[NativeWalletVault.MNEM] = mnem
        return files
    }

    @Test fun everyE912CaseHoldsItsExpectation() {
        val text = javaClass.getResourceAsStream("/spec-vectors/spec-59e-synthetic-vectors.v3.3.1-E9.1.2-add.json")!!.bufferedReader(Charsets.UTF_8).readText()
        val cases = JSONObject(text).getJSONArray("cases")
        assertEquals(4, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val expect = c.getJSONObject("expect").getString("classification")
            val answer: Answer = when (id) {
                "E912-01" -> {
                    // Locked device / keystore unavailable: the listed fixed entry's read throws (temporary).
                    val files = markedFiles(mnemRecord(eoaOf(phraseA), phraseA, corrupt = false))
                    val failing = object : VaultFiles by files {
                        override fun read(name: String): ByteArray? = if (name == NativeWalletVault.MNEM) throw IOException("device locked") else files.read(name)
                    }
                    MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(presentWrap, failing))
                }
                "E912-02" -> {
                    // Deterministic corruption of the listed entry (authentication fails, the key is present); another position holds the valid phrase.
                    val files = markedFiles(mnemRecord(eoaOf(phraseA), null, corrupt = true))
                    files.map["${NativeWalletVault.MNEM}.isolated.20261117T000000Z.feedface"] = mnemRecord(eoaOf(phraseA), phraseA, corrupt = false)
                    MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(presentWrap, files))
                }
                "E912-03" -> {
                    val files = markedFiles(mnemRecord(eoaOf(phraseA), null, corrupt = true))
                    MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(presentWrap, files))
                }
                "E912-04" -> {
                    // The key is missing while the record exists (temporary).
                    val files = markedFiles(mnemRecord(eoaOf(phraseA), phraseA, corrupt = false))
                    MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(keyMissingWrap, files))
                }
                else -> error("unexpected case $id")
            }
            when (expect) {
                "unknown" -> assertTrue("$id: unknown, got $answer", answer is Answer.Unknown)
                "valid" -> assertTrue("$id: valid, got $answer", answer is Answer.Valid)
                "confirmed_no_valid_mnemonic" -> assertTrue("$id: absent (onboarding), got $answer", answer is Answer.Absent)
                else -> error("unexpected expectation $expect")
            }
        }
    }

    /** E9.1.2-1 (a) (2026-11-17, independent review adopted): a first authentication failure followed by a valid read is not confirmed: unknown. */
    @Test fun aListedCorruptionThenAValidReadIsUnknown() {
        val corrupt = mnemRecord(eoaOf(phraseA), null, corrupt = true)
        val good = mnemRecord(eoaOf(phraseA), phraseA, corrupt = false)
        val files = markedFiles(corrupt)
        var reads = 0
        val changing = object : VaultFiles by files {
            override fun read(name: String): ByteArray? {
                if (name == NativeWalletVault.MNEM) { reads++; return if (reads == 1) corrupt else good }
                return files.read(name)
            }
        }
        val a = MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(presentWrap, changing))
        assertTrue("the two reads disagree, so unknown (not the second read's value): $a", a is Answer.Unknown)
    }

    /** E9.1.2-1 (a): two different authentication failures are not confirmed deterministic: unknown. */
    @Test fun aListedCorruptionThenADifferentCorruptionIsUnknown() {
        val first = mnemRecord(eoaOf(phraseA), null, corrupt = true)
        val second = JSONObject().put("record", NativeWalletVault.RECORD_VERSION).put("eoa", eoaOf(phraseA)).put("sealed", "11".repeat(40)).toString().toByteArray(Charsets.UTF_8)
        val files = markedFiles(first)
        var reads = 0
        val changing = object : VaultFiles by files {
            override fun read(name: String): ByteArray? {
                if (name == NativeWalletVault.MNEM) { reads++; return if (reads == 1) first else second }
                return files.read(name)
            }
        }
        assertTrue(MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(presentWrap, changing)) is Answer.Unknown)
    }
}
