package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPMarker
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream

/**
 * OpenPGP inside the native wallet boundary (spec §25.22.2, C3 and C4; spec 25.26.4 table W6). Bouncy Castle's
 * lightweight OpenPGP API only: no JCA provider is registered, so the Android "BC" provider conflict does not apply.
 *
 * Nothing here logs, returns key material, or accepts a key from a caller other than the vault. The private key and
 * the passphrase come in as arguments from the vault and are never stored here.
 *
 * Decryption follows the behaviour of the WebView host it replaces: the recipient key is picked by key ID, the
 * message is decrypted and its integrity checked, and the literal data is returned as UTF-8 text. The sender's
 * signature is not checked (the old host did not check it either).
 */
internal object NativePgp {
    /** Document signature types allowed for C4 (§25.22.2). Certification signatures 0x10 and 0x13 are refused. */
    const val SIG_BINARY_DOCUMENT = 0x00
    const val SIG_CANONICAL_TEXT = 0x01
    val ALLOWED_SIG_TYPES: Set<Int> = setOf(SIG_BINARY_DOCUMENT, SIG_CANONICAL_TEXT)

    private val PURPOSE_RE = Regex("^[A-Za-z][A-Za-z0-9_]{0,31}$")

    /** A parsed private key block: its ring and the master-key fingerprint (lower-case hex). */
    class Secret internal constructor(internal val ring: PGPSecretKeyRing, val fingerprint: String)

    /** Outcome of a native operation. [code] is "ok" or a refusal code; [value] is set only for "ok". */
    class Outcome private constructor(val code: String, val value: String?) {
        val ok: Boolean get() = code == "ok"

        companion object {
            fun ok(value: String) = Outcome("ok", value)
            fun fail(code: String) = Outcome(code, null)
        }
    }

    /** The private key block: exactly one secret key ring. `null` for anything else. */
    fun parseSecret(armor: String): Secret? {
        if (!armor.contains("BEGIN PGP PRIVATE KEY BLOCK")) return null
        return try {
            val input = PGPUtil.getDecoderStream(ByteArrayInputStream(armor.toByteArray(Charsets.UTF_8)))
            val rings = PGPSecretKeyRingCollection(input, BcKeyFingerprintCalculator())
            val it = rings.keyRings
            if (!it.hasNext()) return null
            val ring = it.next()
            if (it.hasNext()) return null
            Secret(ring, hex(ring.publicKey.fingerprint))
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Decrypts an armored OpenPGP message to the recipient [secret]. [passphrase] unlocks the key in memory only.
     * Refusals: `bad_message`, `not_recipient`, `bad_passphrase`, `decrypt_failed`, `integrity_failed`.
     */
    /** A decrypted literal: `ok` with its OpenPGP [format] (the char code) and [bytes], or a refusal [code]. */
    class LiteralResult private constructor(val code: String, val format: Int, val bytes: ByteArray?) {
        val ok: Boolean get() = code == "ok"

        companion object {
            fun ok(format: Int, bytes: ByteArray) = LiteralResult("ok", format, bytes)
            fun fail(code: String) = LiteralResult(code, -1, null)
        }
    }

    fun decryptMessage(secret: Secret, passphrase: String, armoredMessage: String): Outcome {
        val literal = decryptLiteral(secret, passphrase, armoredMessage)
        return if (literal.ok) Outcome.ok(String(literal.bytes!!, Charsets.UTF_8)) else Outcome.fail(literal.code)
    }

    /**
     * The literal of the first public-key packet this ring can open, with its format. Refusal codes as [decryptMessage].
     */
    fun decryptLiteral(secret: Secret, passphrase: String, armoredMessage: String): LiteralResult {
        if (!armoredMessage.contains("BEGIN PGP MESSAGE")) return LiteralResult.fail("bad_message")
        val list = encryptedList(armoredMessage) ?: return LiteralResult.fail("bad_message")
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(passphrase.toCharArray())
        val candidates = encryptionKeys(secret.ring)
        var recipientFound = false
        var lastCode = "not_recipient"
        for (enc in list) {
            if (enc !is PGPPublicKeyEncryptedData) continue
            val matching = candidates.filter { enc.keyID == 0L || it.keyID == enc.keyID }
            if (matching.isEmpty()) continue
            recipientFound = true
            for (sk in matching) {
                val priv: PGPPrivateKey = try {
                    sk.extractPrivateKey(decryptor)
                } catch (_: PGPException) {
                    return LiteralResult.fail("bad_passphrase")
                }
                val part = try {
                    literalPart(enc.getDataStream(BcPublicKeyDataDecryptorFactory(priv)))
                } catch (_: Exception) {
                    lastCode = "decrypt_failed"
                    continue
                }
                if (part == null) {
                    lastCode = "decrypt_failed"
                    continue
                }
                if (enc.isIntegrityProtected && !enc.verify()) return LiteralResult.fail("integrity_failed")
                return LiteralResult.ok(part.format, part.bytes)
            }
        }
        return LiteralResult.fail(if (recipientFound) lastCode else "not_recipient")
    }

    /**
     * The key IDs of the public-key packets, for the recipient check (spec 25.34.2, step 4). An anonymous packet is 0.
     * `null` when the text is not an OpenPGP encrypted message with an integrity-protected data packet.
     */
    internal fun recipientKeyIds(armoredMessage: String): List<Long>? {
        if (!armoredMessage.contains("BEGIN PGP MESSAGE")) return null
        val list = encryptedList(armoredMessage) ?: return null
        if (list.isEmpty() || list.none { it.isIntegrityProtected }) return null
        return list.filterIsInstance<PGPPublicKeyEncryptedData>().map { it.keyID }
    }

    /**
     * Document signature (C4) over `label || message`, where [label] is the native domain tag added by the caller
     * (`beamio.pgp.<purposeId>.v1\n`). Returns the armored signature, or a refusal code.
     * Refusals: `sig_type_not_allowed`, `bad_passphrase`, `sign_failed`.
     */
    fun signDocument(secret: Secret, passphrase: String, label: String, message: ByteArray, sigType: Int): Outcome {
        if (sigType !in ALLOWED_SIG_TYPES) return Outcome.fail("sig_type_not_allowed")
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(passphrase.toCharArray())
        val signer = secret.ring.secretKeys.asSequence().firstOrNull { it.isSigningKey }
            ?: return Outcome.fail("sign_failed")
        val priv = try {
            signer.extractPrivateKey(decryptor)
        } catch (_: PGPException) {
            return Outcome.fail("bad_passphrase")
        }
        return try {
            val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(signer.publicKey.algorithm, PGPUtil.SHA256))
            gen.init(sigType, priv)
            gen.update(label.toByteArray(Charsets.UTF_8))
            gen.update(message)
            val sig = gen.generate()
            val out = ByteArrayOutputStream()
            ArmoredOutputStream(out).use { armor ->
                sig.encode(armor)
            }
            Outcome.ok(String(out.toByteArray(), Charsets.US_ASCII))
        } catch (_: Exception) {
            Outcome.fail("sign_failed")
        }
    }

    /**
     * Checks a detached signature made by [signDocument] or by another OpenPGP implementation. Used by the tests only.
     * The signing key is the one whose key ID is in the signature.
     */
    internal fun verifyDocument(secret: Secret, label: String, message: ByteArray, armoredSignature: String): Boolean {
        return try {
            val input = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredSignature.toByteArray(Charsets.UTF_8)))
            val sigs = org.bouncycastle.openpgp.PGPObjectFactory(input, BcKeyFingerprintCalculator()).nextObject()
            val sig: PGPSignature = (sigs as? PGPSignatureList)?.get(0) ?: return false
            val pub = secret.ring.getPublicKey(sig.keyID) ?: return false
            sig.init(BcPGPContentVerifierBuilderProvider(), pub)
            sig.update(label.toByteArray(Charsets.UTF_8))
            sig.update(message)
            sig.verify()
        } catch (_: Exception) {
            false
        }
    }

    /** Encrypted-data packets of an armored message, skipping marker packets. */
    private fun encryptedList(armoredMessage: String): List<PGPEncryptedData>? {
        return try {
            val input = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredMessage.toByteArray(Charsets.UTF_8)))
            val factory = PGPObjectFactory(input, BcKeyFingerprintCalculator())
            var obj = factory.nextObject()
            while (obj is PGPMarker) obj = factory.nextObject()
            val list = obj as? PGPEncryptedDataList ?: return null
            list.encryptedDataObjects.asSequence().toList()
        } catch (_: Exception) {
            null
        }
    }

    /** Encryption-capable secret keys of the ring (the subkeys, or the master key for RSA-only keys). */
    private fun encryptionKeys(ring: PGPSecretKeyRing): List<PGPSecretKey> =
        ring.secretKeys.asSequence().filter { it.publicKey.isEncryptionKey }.toList()

    /** Replaces each CRLF with LF. A lone CR is kept. */
    private fun crlfToLf(bytes: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(bytes.size)
        var i = 0
        while (i < bytes.size) {
            if (bytes[i] == 0x0D.toByte() && i + 1 < bytes.size && bytes[i + 1] == 0x0A.toByte()) {
                i++
                continue
            }
            out.write(bytes[i].toInt())
            i++
        }
        return out.toByteArray()
    }

    private class LiteralPart(val format: Int, val bytes: ByteArray)

    /** The literal data inside an optional compression layer, with its format. Signature packets are skipped. `null` if absent. */
    private fun literalPart(clear: InputStream): LiteralPart? {
        val factory = PGPObjectFactory(clear, BcKeyFingerprintCalculator())
        var obj = factory.nextObject()
        while (obj != null) {
            when (obj) {
                is PGPCompressedData -> return literalPart(obj.dataStream)
                is PGPLiteralData -> {
                    val bytes = obj.inputStream.use { it.readBytes() }
                    // A text literal is stored with CRLF line endings (RFC 4880 canonical text). openpgp.js and gopenpgp
                    // return the native LF form; so does this, for text literals only (interop, §41). Binary is untouched.
                    val text = obj.format == PGPLiteralData.UTF8.code || obj.format == PGPLiteralData.TEXT.code
                    return LiteralPart(obj.format, if (text) crlfToLf(bytes) else bytes)
                }
                is PGPOnePassSignatureList, is PGPSignatureList -> Unit
                else -> return null
            }
            obj = factory.nextObject()
        }
        return null
    }

    /** `0x` + keccak256 of the UTF-8 armor text: the `_beamioPgpArmorHash` the chat layer expects (same as the old host). */
    fun armorHash(armored: String): String =
        "0x" + ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256(armored.toByteArray(Charsets.UTF_8)))

    private fun hex(bytes: ByteArray): String = ConetChatCryptoUtil.toHex(bytes)
}
