package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.Base64

/**
 * The record layout and the recovery-code shape against `spec/recovery-record-vectors.v1.json`, generated from the PWA's own
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
    fun everyCaseParsesOpensAndDerivesTheTestAccount() {
        val cases = doc.getJSONArray("cases")
        assertTrue(cases.length() >= 2)
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val code = c.getString("code").toByteArray(Charsets.UTF_8)
            assertNotNull(name, RecoveryCode.normalize(code))
            // The index the registry is read by: keccak256 of the code's UTF-8 bytes.
            val index = "0x" + ConetChatCryptoUtil.keccak256(code).joinToString("") { "%02x".format(it) }
            assertEquals(name, c.getString("index"), index)

            // A record below the r3ab floor (8192 KB) is refused before any decryption (§25.47.6): it is not opened.
            if (c.getJSONObject("params").getInt("m") < RecoveryRecord.MIN_M_KB) {
                assertNull(name, RecoveryRecord.parse(c.getString("record")))
                continue
            }
            val parsed = RecoveryRecord.parse(c.getString("record"))
            assertNotNull(name, parsed)
            val p = c.getJSONObject("params")
            assertEquals(name, p.getInt("m"), parsed!!.stored.m)
            assertEquals(name, p.getInt("t"), parsed.stored.t)
            assertEquals(name, p.getInt("p"), parsed.stored.p)

            val opened = RecoveryRecord.open(parsed.stored, parsed.imgBase64, code)
            assertTrue(name, opened is RecoveryRecord.Opened.Ok)
            val phrase = (opened as RecoveryRecord.Opened.Ok).phrase
            assertEquals(name, c.getString("mnemonic"), String(phrase, Charsets.UTF_8))
            val key = MnemonicDerivation.deriveKey(String(phrase, Charsets.UTF_8))
            assertNotNull(name, key)
            assertEquals(name, testEoa, WalletAddress.fromPrivateKey(key!!))
            phrase.fill(0)
            key.fill(0)
        }
    }

    @Test
    fun aWrongCodeIsAWrongPasswordNotAPhrase() {
        val good = doc.getJSONArray("cases").getJSONObject(0)
        val parsed = RecoveryRecord.parse(good.getString("record"))!!
        val wrong = doc.getJSONArray("negatives").getJSONObject(0).getString("code").toByteArray(Charsets.UTF_8)
        assertEquals(RecoveryRecord.Opened.WrongPassword, RecoveryRecord.open(parsed.stored, parsed.imgBase64, wrong))
    }

    @Test
    fun aTamperedImageIsNotAPhrase() {
        val c = doc.getJSONArray("cases").getJSONObject(0)
        val parsed = RecoveryRecord.parse(c.getString("record"))!!
        val img = parsed.imgBase64.toCharArray()
        img[img.size - 4] = if (img[img.size - 4] == 'A') 'B' else 'A'
        val opened = RecoveryRecord.open(parsed.stored, String(img), c.getString("code").toByteArray(Charsets.UTF_8))
        assertTrue(opened !is RecoveryRecord.Opened.Ok)
    }

    @Test
    fun aMalformedRecordIsRejectedBeforeAnyKeyDerivation() {
        assertNull(RecoveryRecord.parse("not base64 at all!"))
        assertNull(RecoveryRecord.parse(Base64.getEncoder().encodeToString("{}".toByteArray())))
        // The PIN hash is part of the stored block (§25.42.5 step 5): without it the record is refused.
        val noHash = """{"stored":{"algo":"argon2id","v":19,"m":1024,"t":1,"p":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA=="},"img":"AAAA"}"""
        assertNull(RecoveryRecord.parse(Base64.getEncoder().encodeToString(noHash.toByteArray())))
        // Parameters above the bounds are refused before Argon2 runs.
        val huge = """{"stored":{"algo":"argon2id","v":19,"m":${RecoveryRecord.MAX_M_KB + 1},"t":3,"p":1,"hash":"AAAA","salt":"AAAAAAAAAAAAAAAAAAAAAA=="},"img":"AAAA"}"""
        assertNull(RecoveryRecord.parse(Base64.getEncoder().encodeToString(huge.toByteArray())))
    }

    /** The r3ab floor, checked at the parser only (no Argon2 runs): 8191 KB is refused, 8192 KB is the lowest accepted. */
    @Test
    fun theMemoryFloorIs8192KibAndIsCheckedBeforeDecryption() {
        fun record(m: Int): String {
            val json = """{"stored":{"algo":"argon2id","v":19,"m":$m,"t":1,"p":1,"hash":"AAAA","salt":"AAAAAAAAAAAAAAAAAAAAAA=="},"img":"AAAA"}"""
            return Base64.getEncoder().encodeToString(json.toByteArray())
        }
        assertNull(RecoveryRecord.parse(record(8_191)))
        assertNotNull(RecoveryRecord.parse(record(8_192)))
        assertNull(RecoveryRecord.parse(record(RecoveryRecord.MAX_M_KB + 1)))
        assertEquals(8_192, RecoveryRecord.MIN_M_KB)
    }

    @Test
    fun theCodeShapeIsTwentyTwoBase62CharactersAfterTrimming() {
        fun ok(s: String) = RecoveryCode.normalize(s.toByteArray(Charsets.UTF_8)) != null
        assertTrue(ok("0wcFtOGNXQnQFZ8QRh12Uh"))
        assertTrue(ok("  0wcFtOGNXQnQFZ8QRh12Uh\t\n"))
        assertTrue(!ok("0wcFtOGNXQnQFZ8QRh12U"))   // 21 characters
        assertTrue(!ok("0wcFtOGNXQnQFZ8QRh12Uhh")) // 23 characters
        assertTrue(!ok("0wcFtOGNXQnQFZ8QRh12U!"))  // outside the alphabet
        assertTrue(!ok("abcd-efghijklmnopqrstuv")) // a hyphen
    }
}
