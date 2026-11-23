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
 * EIP-191 recovery over the envelope text, byte for byte (2026-11-20). Two parts:
 *  1. the PWA envelope sample, read from the environment variable VOICE_ENVELOPE_VECTOR (never committed): its text hashes, the recovered signer
 *     equals expectedOuterSigner, and a one-character change to the text recovers another signer;
 *  2. a native round trip for a voice_end_v1 envelope, through CallControlGate: a delivered signal, and a refused one when the text is changed.
 * The JS verifyMessage path itself does not run in a JVM test. Part 1 proves the byte interpretation, not the JS host.
 */
class EnvelopeSignatureVectorTest {
    private val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

    /** The address that signed [message] (EIP-191), lower case, or null when the signature is malformed. */
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
    fun thePwaEnvelopeSampleRecoversItsSignerOverTheTextBytes() {
        val path = System.getenv("VOICE_ENVELOPE_VECTOR")
        assumeTrue("VOICE_ENVELOPE_VECTOR not set: the PWA sample is not in the repository", !path.isNullOrBlank())
        val d = JSONObject(File(path!!).readText(Charsets.UTF_8))
        val text = d.getString("envelopeText")
        val bytes = text.toByteArray(Charsets.UTF_8)
        // The recorded hashes must match the bytes that are signed.
        assertEquals(d.getString("envelopeTextUtf8Sha256"), java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) })
        val signer = recoverSigner(bytes, d.getString("signMessage"))
        assertEquals(d.getString("expectedOuterSigner").lowercase(), signer)
        // One character changed in the signed text: a different signer, so a forged text is never accepted.
        val changed = text.replaceFirst("\"proto\":3", "\"proto\":4").toByteArray(Charsets.UTF_8)
        assertNotEquals(bytes.toList(), changed.toList())
        assertNotEquals(d.getString("expectedOuterSigner").lowercase(), recoverSigner(changed, d.getString("signMessage")))
    }

    @Test
    fun aNativelySignedControlEnvelopeIsDeliveredAndAChangedTextIsRefused() {
        val key = ByteArray(32) { (it + 1).toByte() }
        val signer = recoverSigner("probe".toByteArray(), Eip191Signer.sign(key, "probe".toByteArray()) ?: error("sign")) ?: error("recover")
        val inner = JSONObject()
            .put("type", "voice_end_v1").put("callId", "call-native-0001").put("sessionId", "sess-native-0001").put("from", signer)
            .toString()
        val sig = Eip191Signer.sign(key, inner.toByteArray(Charsets.UTF_8)) ?: error("sign")
        val envelope = JSONObject().put("timestamp", 1763600000000L).put("text", inner).put("signMessage", sig).put("from", signer).toString()
        val guard = CallControlGate.ReplayGuard()
        val recovered = recoverSigner(inner.toByteArray(Charsets.UTF_8), sig)
        val ok = CallControlGate.admit(envelope, recovered, "hash-native-1", guard)
        assertTrue("the native round trip delivers", ok is CallControlGate.Verdict.Deliver)
        // A changed text: the signature no longer recovers the sender, so the gate refuses it.
        val changedInner = inner.replace("call-native-0001", "call-native-0002")
        val changedEnvelope = JSONObject().put("timestamp", 1763600000000L).put("text", changedInner).put("signMessage", sig).put("from", signer).toString()
        val changedSigner = recoverSigner(changedInner.toByteArray(Charsets.UTF_8), sig)
        val refused = CallControlGate.admit(changedEnvelope, changedSigner, "hash-native-2", guard)
        assertEquals("signer_mismatch", (refused as CallControlGate.Verdict.Drop).reason)
    }
}
