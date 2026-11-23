package network.conet.chat.nativekey

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import network.conet.chat.ConetChatCryptoUtil
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `voiceEphemeralTempSig` and `voiceEphemeralDecryptInner` (v113 §132, v109 §119.2): public Kotlin API, not bridge commands. The signature is recovered
 * from its EIP-191 hash and must give the temporary wallet address of the same sid. Decrypt is tested on its refusal paths here; the positive path
 * needs an encrypted vector (env-var suite).
 */
class VoiceEphemeralSigDecryptTest {
    private val sid = "sid-sig-decrypt-0001"

    private fun recoverAddress(text: String, sig: String): String {
        val raw = sig.removePrefix("0x")
        val r = BigInteger(raw.substring(0, 64), 16)
        val s = BigInteger(raw.substring(64, 128), 16)
        val v = raw.substring(128, 130).toInt(16)
        val hash = Eip191Signer.hashMessage(text.toByteArray(Charsets.UTF_8))
        val pub = Eip191Signer.recoverPublicKey(hash, r, s, v - 27) ?: error("no recovery")
        val digest = ConetChatCryptoUtil.keccak256(pub.copyOfRange(1, pub.size))
        return "0x" + ConetChatCryptoUtil.toHex(digest.copyOfRange(12, 32)).lowercase()
    }

    @Test
    fun theSignatureRecoversTheTemporaryWalletAddressOfTheSid() {
        VoiceChannelKeys.clear()
        val prepared = VoiceEphemeral.prepare("caller", sid, false, SecureRandom())
        val temp = prepared.getJSONObject("channel").getString("temp")
        val text = "voice_listen-text-0001"
        val r = VoiceEphemeral.tempSig(sid, text)
        assertTrue(r.getBoolean("ok"))
        val sig = r.getString("sig")
        assertTrue(Regex("^0x[0-9a-f]{130}$").matches(sig))
        assertEquals(temp, recoverAddress(text, sig))
        VoiceEphemeral.forget(sid)
        VoiceChannelKeys.clear()
    }

    @Test
    fun tempSigRefusesAnUnknownSidAndBadInput() {
        VoiceChannelKeys.clear()
        assertEquals("unknown_sid", VoiceEphemeral.tempSig("sid-never-prepared", "text").getString("error"))
        VoiceChannelKeys.clear()
        VoiceEphemeral.prepare("caller", sid, false, SecureRandom())
        assertEquals("bad_request", VoiceEphemeral.tempSig(sid, "").getString("error"))
        assertEquals("bad_request", VoiceEphemeral.tempSig(null, "text").getString("error"))
        VoiceEphemeral.forget(sid)
        VoiceChannelKeys.clear()
    }

    @Test
    fun tempSigAfterForgetIsUnknownSid() {
        VoiceChannelKeys.clear()
        VoiceEphemeral.prepare("caller", sid, false, SecureRandom())
        VoiceEphemeral.forget(sid)
        assertEquals("unknown_sid", VoiceEphemeral.tempSig(sid, "text").getString("error"))
        VoiceChannelKeys.clear()
    }

    @Test
    fun decryptInnerRefusesAnUnknownSidAndGarbage() {
        VoiceChannelKeys.clear()
        assertEquals("unknown_sid", VoiceEphemeral.decryptInner("sid-never-prepared", "-----BEGIN PGP MESSAGE-----").getString("error"))
        VoiceEphemeral.prepare("callee", sid, true, SecureRandom())
        // A non-PGP text, and a PGP-shaped text that is not a message for this key, both give decrypt_failed.
        assertEquals("decrypt_failed", VoiceEphemeral.decryptInner(sid, "not an armor").getString("error"))
        assertEquals("decrypt_failed", VoiceEphemeral.decryptInner(sid, "-----BEGIN PGP MESSAGE-----\nAAAA\n-----END PGP MESSAGE-----").getString("error"))
        assertEquals("bad_request", VoiceEphemeral.decryptInner(sid, "").getString("error"))
        VoiceEphemeral.forget(sid)
        VoiceChannelKeys.clear()
    }

    /** Encrypts [plain] to the public armor of a temporary PGP key (the same key the SDK holds for the sid), as an ASCII-armored message. */
    private fun encryptTo(publicArmor: String, plain: String): String {
        val ring = PGPPublicKeyRing(PGPUtil.getDecoderStream(ByteArrayInputStream(publicArmor.toByteArray(Charsets.UTF_8))), BcKeyFingerprintCalculator())
        val key: PGPPublicKey = ring.publicKeys.asSequence().first { it.isEncryptionKey }
        val gen = PGPEncryptedDataGenerator(BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true))
        gen.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(key))
        val out = ByteArrayOutputStream()
        val armored = ArmoredOutputStream(out)
        val encOut = gen.open(armored, ByteArray(4096))
        val data = plain.toByteArray(Charsets.UTF_8)
        val litOut = PGPLiteralDataGenerator().open(encOut, PGPLiteralData.BINARY, "", data.size.toLong(), Date())
        litOut.write(data)
        litOut.close()
        encOut.close()
        armored.close()
        return out.toString(Charsets.UTF_8.name())
    }

    /** The positive path: a message encrypted to the sid's temporary PGP key decrypts to its plaintext; a message to another sid's key is decrypt_failed. */
    @Test
    fun decryptInnerReturnsThePlaintextOfAMessageToTheSidsTemporaryKey() {
        VoiceChannelKeys.clear()
        val prepared = VoiceEphemeral.prepare("callee", sid, true, SecureRandom())
        val publicArmor = prepared.getJSONObject("channel").getString("tempPgpArmor")
        val inner = "inner-plaintext-0001"
        val armor = encryptTo(publicArmor, inner)
        val ok = VoiceEphemeral.decryptInner(sid, armor)
        assertTrue(ok.getBoolean("ok"))
        assertEquals(inner, ok.getString("plaintext"))

        val otherSid = "sid-other-decrypt-0002"
        val other = VoiceEphemeral.prepare("callee", otherSid, true, SecureRandom())
        val otherArmor = other.getJSONObject("channel").getString("tempPgpArmor")
        assertEquals("decrypt_failed", VoiceEphemeral.decryptInner(sid, encryptTo(otherArmor, inner)).getString("error"))
        VoiceEphemeral.forget(sid)
        VoiceEphemeral.forget(otherSid)
        VoiceChannelKeys.clear()
    }

    @Test
    fun decryptInnerAfterForgetIsUnknownSid() {
        VoiceChannelKeys.clear()
        VoiceEphemeral.prepare("callee", sid, true, SecureRandom())
        VoiceEphemeral.forget(sid)
        assertFalse(VoiceEphemeral.holdsPgpFor(sid))
        assertEquals("unknown_sid", VoiceEphemeral.decryptInner(sid, "-----BEGIN PGP MESSAGE-----").getString("error"))
        VoiceChannelKeys.clear()
    }

    /** v155 §175.4: text is non-empty, valid UTF-8 and at most 4096 bytes; the grammar is the shell's, not checked here. */
    @Test
    fun tempSigTextBoundsAreTheUtf8ByteLimit() {
        VoiceChannelKeys.clear()
        VoiceEphemeral.prepare("caller", sid, false, SecureRandom())
        assertTrue("4096 bytes is accepted", VoiceEphemeral.tempSig(sid, "a".repeat(4096)).getBoolean("ok"))
        assertEquals("4097 bytes is refused", "bad_request", VoiceEphemeral.tempSig(sid, "a".repeat(4097)).getString("error"))
        // Three-byte UTF-8 characters: 1365 of them are 4095 bytes (accepted), 1366 are 4098 bytes (refused).
        assertTrue(VoiceEphemeral.tempSig(sid, "\u4e2d".repeat(1365)).getBoolean("ok"))
        assertEquals("bad_request", VoiceEphemeral.tempSig(sid, "\u4e2d".repeat(1366)).getString("error"))
        assertEquals("an unpaired surrogate is not valid UTF-8", "bad_request", VoiceEphemeral.tempSig(sid, "x\uD800y").getString("error"))
        VoiceEphemeral.forget(sid)
        VoiceChannelKeys.clear()
    }
}
