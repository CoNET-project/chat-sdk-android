package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * The recovery record and the code format against `spec/recovery-record-vectors.v1.json`, generated from the PWA's own
 * record layout with synthetic inputs (gen-recovery-record-vectors.mjs). The phrase is the BIP-39 public test vector.
 */
class RecoveryRecordVectorsTest {
    private val raw = File(System.getenv("RECOVERY_RECORD_VECTORS") ?: "../spec/recovery-record-vectors.v1.json").readBytes()
    private val doc = JSONObject(String(raw, Charsets.UTF_8))
    private val testEoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

    @Test
    fun vectorFileIsPinned() {
        val sha = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it) }
        assertEquals("539661701eb6ae6e708c69b90b0c4c0623d52e170b6e1d2cb6eb4c78e83bd8ae", sha)
    }

    @Test
    fun everyCaseParsesDecryptsAndDerivesTheTestAccount() {
        val cases = doc.getJSONArray("cases")
        assertTrue(cases.length() >= 2)
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val code = c.getString("code").toByteArray(Charsets.UTF_8)
            assertTrue(name, RecoveryCode.isValid(code))
            // The index the registry is read by: keccak256 of the code's UTF-8 bytes.
            val index = "0x" + ConetChatCryptoUtil.keccak256(code).joinToString("") { "%02x".format(it) }
            assertEquals(name, c.getString("index"), index)

            val parsed = RecoveryRecord.parse(c.getString("record"))
            assertNotNull(name, parsed)
            val p = c.getJSONObject("params")
            assertEquals(name, p.getInt("m"), parsed!!.stored.m)
            assertEquals(name, p.getInt("t"), parsed.stored.t)
            assertEquals(name, p.getInt("p"), parsed.stored.p)

            val phrase = RecoveryRecord.decryptMnemonic(parsed.stored, parsed.imgBase64, code)
            assertNotNull(name, phrase)
            assertEquals(name, c.getString("mnemonic"), String(phrase!!, Charsets.UTF_8))
            val key = MnemonicDerivation.deriveKey(String(phrase, Charsets.UTF_8))
            assertNotNull(name, key)
            assertEquals(name, testEoa, WalletAddress.fromPrivateKey(key!!))
            phrase.fill(0)
            key.fill(0)
        }
    }

    @Test
    fun aWrongCodeDoesNotDecrypt() {
        val neg = doc.getJSONArray("negatives").getJSONObject(0)
        val good = doc.getJSONArray("cases").getJSONObject(1)
        val parsed = RecoveryRecord.parse(good.getString("record"))!!
        val wrong = neg.getString("code").toByteArray(Charsets.UTF_8)
        assertTrue(RecoveryCode.isValid(wrong))
        assertNull(RecoveryRecord.decryptMnemonic(parsed.stored, parsed.imgBase64, wrong))
    }

    @Test
    fun aTamperedRecordDoesNotDecrypt() {
        val c = doc.getJSONArray("cases").getJSONObject(1)
        val parsed = RecoveryRecord.parse(c.getString("record"))!!
        // Flip one character of the image (inside the GCM tag or ciphertext): authentication must fail.
        val img = parsed.imgBase64.toCharArray()
        img[img.size - 4] = if (img[img.size - 4] == 'A') 'B' else 'A'
        val code = c.getString("code").toByteArray(Charsets.UTF_8)
        assertNull(RecoveryRecord.decryptMnemonic(parsed.stored, String(img), code))
    }

    @Test
    fun aMalformedRecordIsRejectedBeforeAnyKeyDerivation() {
        assertNull(RecoveryRecord.parse("not base64 at all!"))
        assertNull(RecoveryRecord.parse(java.util.Base64.getEncoder().encodeToString("{}".toByteArray())))
        // Parameters above the bounds are refused before Argon2 runs.
        val huge = """{"stored":{"algo":"argon2id","v":19,"m":${RecoveryRecord.MAX_M_KB + 1},"t":3,"p":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA=="},"img":"AAAA"}"""
        assertNull(RecoveryRecord.parse(java.util.Base64.getEncoder().encodeToString(huge.toByteArray())))
    }

    @Test
    fun recoveryCodeFormatIsTheUuid62Shape() {
        // A valid code is 22 base62 characters whose value fits in 128 bits (uuid62.v4 output).
        assertTrue(RecoveryCode.isValid("0wcFtOGNXQnQFZ8QRh12Uh".toByteArray()))
        assertTrue(RecoveryCode.isValid("0000000000000000000000".toByteArray()))
        assertFalse22("not-a-code-at-all")
        assertFalse22("0wcFtOGNXQnQFZ8QRh12U")   // 21 characters
        assertFalse22("0wcFtOGNXQnQFZ8QRh12Uhh") // 23 characters
        assertFalse22("0wcFtOGNXQnQFZ8QRh12U!")  // outside the alphabet
        assertFalse22("zzzzzzzzzzzzzzzzzzzzzz")  // 22 characters, but the value is above 2^128
    }

    private fun assertFalse22(code: String) {
        assertTrue("accepted: $code", !RecoveryCode.isValid(code.toByteArray(Charsets.UTF_8)))
    }
}
