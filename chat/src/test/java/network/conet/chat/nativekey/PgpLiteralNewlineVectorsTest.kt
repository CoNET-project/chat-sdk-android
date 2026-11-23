package network.conet.chat.nativekey

import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * The PGP literal newline rule (spec r3n §25.32; `pgp-literal-newline-vectors.v1.json`, sha256 b5653576…, synthetic). For a
 * text literal (format `u` or `t`) CRLF becomes LF and a lone CR stays; for a binary literal (`b`) nothing changes. Each case
 * is checked three ways: the literal inside the ciphertext is the raw bytes the vector names (so the conversion is really
 * exercised), its format is the vector's, and the native decrypt returns the expected bytes.
 */
class PgpLiteralNewlineVectorsTest {
    private val raw = File(System.getenv("PGP_LITERAL_VECTORS") ?: "../spec/pgp-literal-newline-vectors.v1.json").readBytes()
    private val vectors = JSONObject(String(raw, Charsets.UTF_8))

    private fun sha256Hex(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun hex(h: String): ByteArray = ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun utf8Of(h: String): String = String(hex(h), Charsets.UTF_8)

    /** The rule as the vector states it, applied to raw literal bytes. */
    private fun ruleApplied(format: String, bytes: ByteArray): ByteArray {
        if (format == "b") return bytes
        val out = java.io.ByteArrayOutputStream(bytes.size)
        var i = 0
        while (i < bytes.size) {
            if (bytes[i] == 0x0D.toByte() && i + 1 < bytes.size && bytes[i + 1] == 0x0A.toByte()) {
                out.write(0x0A)
                i += 2
            } else {
                out.write(bytes[i].toInt())
                i++
            }
        }
        return out.toByteArray()
    }

    /** The literal the ciphertext carries, before any conversion: decrypted with bcpg, compressed wrapper removed. */
    private fun rawLiteral(armor: String, secretArmor: String): Pair<String, ByteArray> {
        val secretRing = PGPSecretKeyRing(PGPUtil.getDecoderStream(secretArmor.toByteArray(Charsets.UTF_8).inputStream()), BcKeyFingerprintCalculator())
        val list = PGPObjectFactory(PGPUtil.getDecoderStream(armor.toByteArray(Charsets.UTF_8).inputStream()), BcKeyFingerprintCalculator())
            .nextObject() as PGPEncryptedDataList
        val enc = list.encryptedDataObjects.asSequence().filterIsInstance<PGPPublicKeyEncryptedData>().first {
            secretRing.getSecretKey(it.keyID) != null
        }
        val priv = secretRing.getSecretKey(enc.keyID)
            .extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)))
        var obj = PGPObjectFactory(enc.getDataStream(BcPublicKeyDataDecryptorFactory(priv)), BcKeyFingerprintCalculator()).nextObject()
        if (obj is PGPCompressedData) {
            obj = PGPObjectFactory(obj.dataStream, BcKeyFingerprintCalculator()).nextObject()
        }
        val literal = obj as PGPLiteralData
        // The format is the byte's code ('u' is 117), not a Char.
        return literal.format.toChar().toString() to literal.inputStream.readBytes()
    }

    private fun recipientArmor(): String = vectors.getJSONObject("recipient").getString("privateArmor")

    @Test
    fun theVectorFileIsTheHashedCopy() {
        assertEquals("b5653576ccd422f3780c7daeb346b0e588d34e2db474c7921cc52e9b52bb19b5", sha256Hex(raw))
        assertEquals(6, vectors.getJSONArray("cases").length())
    }

    @Test
    fun theRecipientKeyIsTheVectorsSyntheticKey() {
        val secret = NativePgp.parseSecret(recipientArmor())
        assertNotNull("recipient key parses", secret)
        assertEquals(vectors.getJSONObject("recipient").getString("primaryFingerprint"), secret!!.fingerprint.uppercase())
    }

    @Test
    fun everyCaseCarriesTheRawLiteralTheVectorNames() {
        val cases = vectors.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val (format, bytes) = rawLiteral(c.getString("armoredCiphertext"), recipientArmor())
            assertEquals(c.getString("id") + " format", c.getString("literalFormat"), format)
            assertEquals(c.getString("id") + " raw literal", c.getString("rawLiteralHex"), bytes.joinToString("") { "%02x".format(it) })
        }
    }

    @Test
    fun theExpectedBytesFollowTheRule() {
        val cases = vectors.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val expected = ruleApplied(c.getString("literalFormat"), hex(c.getString("rawLiteralHex")))
            assertEquals(c.getString("id") + " expected", c.getString("expectedNativeHex"), expected.joinToString("") { "%02x".format(it) })
        }
    }

    @Test
    fun theNativeDecryptReturnsTheExpectedBytesForEveryCase() {
        val secret = NativePgp.parseSecret(recipientArmor())!!
        val cases = vectors.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val out = NativePgp.decryptMessage(secret, "", c.getString("armoredCiphertext"))
            assertEquals(c.getString("id") + " code", "ok", out.code)
            assertEquals(c.getString("id") + " bytes", utf8Of(c.getString("expectedNativeHex")), out.value)
        }
    }
}
