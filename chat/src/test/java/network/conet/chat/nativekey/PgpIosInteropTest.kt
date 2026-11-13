package network.conet.chat.nativekey

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Date

/**
 * Interoperability with the iOS (gopenpgp v3.5.2) and the PWA (openpgp.js 6.3.0) vector file `pgp-native-interop-vectors.v1.json`
 * (copy at `spec/`, sha256 pinned). Synthetic keys only, curve25519 legacy, no passphrase.
 *
 * Direction 1 (this test, the vector file): bcpg reads the iOS and PWA ciphertexts, verifies the detached and the cleartext
 * signatures, and fails the tampered case. Decryption goes through the production path (`NativePgp.decryptMessage`).
 * Direction 2: bcpg writes ciphertexts and detached signatures in the `returnFormat` shape to `INTEROP_RETURN_OUT` (default
 * `build/interop/android-bcpg-returns.v1.json`); the test then checks them itself. The iOS and PWA checks are run by those
 * sides on the written file.
 *
 * Signature choices in direction 2: binary document signatures (type 0x00) over the exact UTF-8 bytes, SHA-256. The iOS
 * vectors use the same type for detached signatures; the PWA's cleartext and detached signatures use canonical text (0x01).
 */
class PgpIosInteropTest {
    private val raw = File(System.getenv("PGP_INTEROP_VECTORS") ?: "../spec/pgp-native-interop-vectors.v1.json").readBytes()
    private val vectors = JSONObject(String(raw, Charsets.UTF_8))

    private fun sha256Hex(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun byId(array: String, id: String): JSONObject {
        val arr = vectors.getJSONArray(array)
        return (0 until arr.length()).map { arr.getJSONObject(it) }.first { it.getString("id") == id }
    }

    private fun publicRing(armor: String): PGPPublicKeyRing =
        PGPPublicKeyRing(PGPUtil.getDecoderStream(armor.toByteArray(Charsets.UTF_8).inputStream()), BcKeyFingerprintCalculator())

    private fun signatureList(armor: String): PGPSignatureList =
        PGPObjectFactory(PGPUtil.getDecoderStream(armor.toByteArray(Charsets.UTF_8).inputStream()), BcKeyFingerprintCalculator())
            .nextObject() as PGPSignatureList

    /** RFC 4880 canonical text: CRLF line endings, trailing spaces and tabs removed from each line. */
    private fun canonical(text: String): ByteArray =
        text.split("\r\n", "\n").joinToString("\r\n") { it.trimEnd(' ', '\t') }.toByteArray(Charsets.UTF_8)

    /** Verifies a detached signature with the public key only (the key is looked up by the signature's key ID). */
    @Suppress("DEPRECATION")
    private fun verifyDetached(publicArmor: String, data: ByteArray, sigArmor: String): Boolean {
        val ring = publicRing(publicArmor)
        val sig = signatureList(sigArmor)[0]
        val pub: PGPPublicKey = ring.getPublicKey(sig.keyID) ?: return false
        sig.init(BcPGPContentVerifierBuilderProvider(), pub)
        sig.update(data)
        return sig.verify()
    }

    /** The cleartext body of a clearsigned message (between the header and the signature armor), as written. */
    private fun cleartextBody(message: String): String {
        val start = message.indexOf("\n\n", message.indexOf("Hash:")) + 2
        val end = message.indexOf("\n-----BEGIN PGP SIGNATURE-----")
        assertTrue("cleartext framing", start > 1 && end > start)
        return message.substring(start, end)
    }

    private fun cleartextSignature(message: String): String = message.substring(message.indexOf("-----BEGIN PGP SIGNATURE-----"))

    private fun recipientPrivate(): String = vectors.getJSONObject("keys").getJSONObject("recipient").getString("privateArmored")
    private fun recipientPublic(): String = vectors.getJSONObject("keys").getJSONObject("recipient").getString("publicArmored")
    private fun signerPublic(): String = vectors.getJSONObject("keys").getJSONObject("signer").getString("publicArmored")
    private fun signerPrivate(): String = vectors.getJSONObject("keys").getJSONObject("signer").getString("privateArmored")

    @Test
    fun theVectorFileIsTheHashedCopy() {
        assertEquals("edf7f7f8aa137f5813b160018b6ff09affd228e877ee080fe8d8ad97e04366fb", sha256Hex(raw))
        assertEquals("v3.5.2", vectors.getJSONObject("versions").getString("gopenpgp").substringBefore(" ("))
        assertEquals("6.3.0", vectors.getJSONObject("versions").getString("openpgpjs"))
    }

    @Test
    fun theSyntheticKeysAreWhatTheVectorsSay() {
        val r = NativePgp.parseSecret(recipientPrivate())
        assertNotNull("recipient private", r)
        assertEquals("1d6aa46a179b2780721b1c40f5b097ce4f164fe1", r!!.fingerprint)
        assertEquals("1d6aa46a179b2780721b1c40f5b097ce4f164fe1", publicRing(recipientPublic()).publicKey.fingerprint.joinToString("") { "%02x".format(it) })
        val s = NativePgp.parseSecret(signerPrivate())
        assertNotNull("signer private", s)
        assertEquals("71e2ed32a9f2b430de95ff7c9ebf9b32fb261078", s!!.fingerprint)
    }

    /** Direction 1: iOS (gopenpgp) ciphertexts decrypt with bcpg through the production path. */
    @Test
    fun gopenpgpCiphertextsDecryptWithBcpg() {
        val secret = NativePgp.parseSecret(recipientPrivate())!!
        val arr = vectors.getJSONArray("gopenpgpEncryptedToAndroid")
        assertEquals(2, arr.length())
        for (i in 0 until arr.length()) {
            val it = arr.getJSONObject(i)
            val out = NativePgp.decryptMessage(secret, "", it.getString("ciphertextArmored"))
            assertEquals(it.getString("id"), "ok", out.code)
            assertEquals(it.getString("id"), it.getString("plaintext"), out.value)
        }
    }

    /** Direction 1: PWA (openpgp.js 6.3.0) ciphertexts decrypt with bcpg; their detached signatures verify over canonical text. */
    @Test
    fun openpgpjsCiphertextsDecryptAndTheirSignaturesVerify() {
        val secret = NativePgp.parseSecret(recipientPrivate())!!
        val arr = vectors.getJSONArray("openpgpjsToAndroid")
        assertEquals(2, arr.length())
        for (i in 0 until arr.length()) {
            val it = arr.getJSONObject(i)
            val id = it.getString("id")
            val out = NativePgp.decryptMessage(secret, "", it.getString("ciphertextArmored"))
            assertEquals(id, "ok", out.code)
            assertEquals(id, it.getString("plaintext"), out.value)
            assertTrue("$id detached", verifyDetached(signerPublic(), canonical(it.getString("plaintext")), it.getString("detachedSignatureArmored")))
        }
    }

    /** Direction 1: iOS detached binary signatures verify; the tampered plaintext must not. */
    @Test
    fun gopenpgpDetachedSignaturesVerifyAndTheTamperedOneFails() {
        val arr = vectors.getJSONArray("gopenpgpDetachedSignaturesToAndroid")
        assertEquals(3, arr.length())
        for (i in 0 until arr.length()) {
            val it = arr.getJSONObject(i)
            val id = it.getString("id")
            val ok = verifyDetached(signerPublic(), it.getString("plaintext").toByteArray(Charsets.UTF_8), it.getString("detachedSignatureArmored"))
            assertEquals(id, it.getJSONObject("expect").getBoolean("verify"), ok)
        }
        val tamper = byId("gopenpgpDetachedSignaturesToAndroid", "GO-S-TAMPER")
        assertFalse("tampered must not verify", verifyDetached(signerPublic(), tamper.getString("plaintext").toByteArray(Charsets.UTF_8), tamper.getString("detachedSignatureArmored")))
    }

    /** Direction 1: the PWA's cleartext signatures verify over the canonical body; a changed body must not. */
    @Test
    fun openpgpjsCleartextSignaturesVerify() {
        val arr = vectors.getJSONArray("openpgpjsToAndroid")
        for (i in 0 until arr.length()) {
            val it = arr.getJSONObject(i)
            val id = it.getString("id")
            val cleartext = it.getString("cleartextArmored")
            val body = cleartextBody(cleartext)
            assertTrue("$id cleartext body equals the plaintext", canonical(body).contentEquals(canonical(it.getString("plaintext"))))
            assertTrue("$id cleartext signature", verifyDetached(signerPublic(), canonical(body), cleartextSignature(cleartext)))
            assertFalse("$id changed body must not verify", verifyDetached(signerPublic(), canonical(body + "x"), cleartextSignature(cleartext)))
        }
    }

    /** Direction 1 (negative): an unrelated key must not verify the PWA's detached signature. */
    @Test
    fun aSignatureDoesNotVerifyUnderTheOtherKey() {
        val it = byId("openpgpjsToAndroid", "JS-E1")
        assertFalse(verifyDetached(recipientPublic(), canonical(it.getString("plaintext")), it.getString("detachedSignatureArmored")))
    }

    /** Direction 2: bcpg writes the returnFormat shape. The test checks its own output; openpgp.js and iOS check the file. */
    @Test
    fun bcpgWritesCiphertextsAndDetachedSignaturesInTheReturnFormat() {
        val plaintexts = listOf(
            "AN-1" to "synthetic interop v1 plaintext",
            "AN-2" to "synthetic interop v2: line one\nline two, 中文一行",
        )
        val random = SecureRandom()
        val recipient = publicRing(recipientPublic())
        val encKey = recipient.publicKeys.asSequence().toList().first { !it.isMasterKey && it.isEncryptionKey }
        val signer = PGPSecretKeyRing(PGPUtil.getDecoderStream(signerPrivate().toByteArray(Charsets.UTF_8).inputStream()), BcKeyFingerprintCalculator())
        val signerKey = signer.secretKey
        val out = JSONArray()
        for ((id, text) in plaintexts) {
            val bytes = text.toByteArray(Charsets.UTF_8)
            val cipher = encrypt(encKey, bytes, PGPLiteralData.UTF8, random)
            val sig = detachedBinary(signerKey, bytes)
            // Self-check: the same production and public-key paths the other sides will use.
            assertEquals(id, "ok", NativePgp.decryptMessage(NativePgp.parseSecret(recipientPrivate())!!, "", cipher).code)
            assertEquals(id, text, NativePgp.decryptMessage(NativePgp.parseSecret(recipientPrivate())!!, "", cipher).value)
            assertTrue(id, verifyDetached(signerPublic(), bytes, sig))
            out.put(
                JSONObject()
                    .put("id", id)
                    .put("plaintext", text)
                    .put("ciphertextArmored", cipher)
                    .put("detachedSignatureArmored", sig),
            )
        }
        val target = File(System.getenv("INTEROP_RETURN_OUT") ?: "build/interop/android-bcpg-returns.v1.json")
        target.parentFile?.mkdirs()
        target.writeText(out.toString(2), Charsets.UTF_8)
        assertTrue("written", target.length() > 0)
    }

    private fun encrypt(key: PGPPublicKey, literal: ByteArray, format: Char, random: SecureRandom): String {
        val compressedOut = ByteArrayOutputStream()
        val compressor = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZLIB)
        val cOut: OutputStream = compressor.open(compressedOut)
        val lOut: OutputStream = PGPLiteralDataGenerator().open(cOut, format, "", literal.size.toLong(), Date())
        lOut.write(literal)
        lOut.close()
        compressor.close()
        val compressed = compressedOut.toByteArray()
        val armoredOut = ByteArrayOutputStream()
        val armorOut = ArmoredOutputStream.builder().clearHeaders().build(armoredOut)
        val encryptor = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true).setSecureRandom(random),
        )
        encryptor.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(key).setSecureRandom(random))
        val eOut: OutputStream = encryptor.open(armorOut, compressed.size.toLong())
        eOut.write(compressed)
        eOut.close()
        armorOut.close()
        return armoredOut.toString(Charsets.UTF_8.name())
    }

    /** Detached binary document signature (0x00, SHA-256) over [data], armored. No passphrase (synthetic key). */
    private fun detachedBinary(signerKey: org.bouncycastle.openpgp.PGPSecretKey, data: ByteArray): String {
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0))
        val priv = signerKey.extractPrivateKey(decryptor)
        val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(signerKey.publicKey.algorithm, PGPUtil.SHA256))
        gen.init(PGPSignature.BINARY_DOCUMENT, priv)
        gen.update(data)
        val sig = gen.generate()
        val out = ByteArrayOutputStream()
        ArmoredOutputStream.builder().clearHeaders().build(out).use { armor -> sig.encode(armor) }
        return out.toString(Charsets.UTF_8.name())
    }
}
