package network.conet.chat

import java.io.File
import java.math.BigInteger
import network.conet.chat.nativekey.Eip191Signer
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The PWA control-signal vector (voice_end_v1, 2026-11-21): read from the environment variable VOICE_END_VECTOR, never committed. The envelope is
 * run through CallControlGate: the signed control signal is delivered with the verified sender, and a changed text is refused. The EIP-191 signer is
 * recovered natively over the text bytes; the JS verifyMessage host is not run here (the device path is the shell's).
 */
class VoiceEndVectorTest {
    private fun recoverSigner(message: ByteArray, signature: String): String? {
        val raw = ConetChatCryptoUtil.hexToBytes(signature.removePrefix("0x")) ?: return null
        if (raw.size != 65) return null
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        val recid = (raw[64].toInt() and 0xff) - 27
        if (recid !in 0..1) return null
        val pub = Eip191Signer.recoverPublicKey(Eip191Signer.hashMessage(message), r, s, recid) ?: return null
        val body = if (pub.size == 65) pub.copyOfRange(1, 65) else pub
        return "0x" + ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256(body).copyOfRange(12, 32))
    }

    @Test
    fun theSignedControlSignalIsDeliveredAndAChangedTextIsRefused() {
        val path = System.getenv("VOICE_END_VECTOR")
        assumeTrue("VOICE_END_VECTOR not set: the PWA control vector is not in the repository", !path.isNullOrBlank())
        val d = JSONObject(File(path!!).readText(Charsets.UTF_8))
        val text = d.getString("envelopeText")
        assertEquals(d.getString("envelopeTextUtf8Sha256"), java.security.MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) })
        val expected = d.getString("expectedOuterSigner").lowercase()
        val fullEnvelope = d.getString("fullEnvelopeJson")
        val recovered = recoverSigner(text.toByteArray(Charsets.UTF_8), d.getString("signMessage"))
        assertEquals(expected, recovered)

        val guard = CallControlGate.ReplayGuard()
        val v = CallControlGate.admit(fullEnvelope, recovered, "hash-voice-end-vector", guard)
        assertTrue("the signed control signal is delivered", v is CallControlGate.Verdict.Deliver)
        v as CallControlGate.Verdict.Deliver
        assertEquals("voice_end_v1", v.type)
        assertEquals(expected, v.from)

        // A changed character in the signed text: the signature recovers another signer, and the gate refuses the message.
        val changedText = text.replaceFirst(Regex("\"callId\":\"([^\"]+)\""), "\"callId\":\"x$1\"")
        assertNotEquals(text, changedText)
        val changedEnvelope = JSONObject(fullEnvelope).put("text", changedText).toString()
        val changedSigner = recoverSigner(changedText.toByteArray(Charsets.UTF_8), d.getString("signMessage"))
        assertNotEquals(expected, changedSigner)
        val refused = CallControlGate.admit(changedEnvelope, changedSigner, "hash-voice-end-changed", guard)
        assertEquals("signer_mismatch", (refused as CallControlGate.Verdict.Drop).reason)
    }
}
