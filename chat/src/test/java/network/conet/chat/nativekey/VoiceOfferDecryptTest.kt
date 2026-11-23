package network.conet.chat.nativekey

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The narrow offer decrypt (VoiceOfferDecrypt, 2026-11-20). The classification and fail-closed rules are tested with a fixed decrypt outcome,
 * because the vectors carry no offer plaintext and the module has no native PGP encrypt. The refusal paths run through the real vault decrypt
 * (NativePgpVault.decryptInbound) with the spec vectors, so the vault's own refusals (no key, not recipient) reach the shell as fixed codes.
 */
class VoiceOfferDecryptTest {
    private val vectors = JSONObject(
        String(File(System.getenv("PGP_NATIVE_VECTORS") ?: "../spec/pgp-native-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
    private val offer = """{"type":"voice_call_offer_v1","callId":"call-offer-0001","sessionId":"sess-0001"}"""

    private fun decryptCase(id: String): JSONObject {
        val cases = vectors.getJSONArray("decrypt")
        return (0 until cases.length()).map { cases.getJSONObject(it) }.first { it.getString("id") == id }
    }

    private fun ok(text: String) = NativePgp.Outcome.ok(text)

    @Test
    fun anOfferPlaintextIsReturnedWithItsIdentifiers() {
        val r = VoiceOfferDecrypt.decryptVoiceOfferWith("armor") { ok(offer) }
        assertTrue(r is VoiceOfferDecrypt.Result.Ok)
        r as VoiceOfferDecrypt.Result.Ok
        assertEquals(offer, r.payload)
        assertEquals("call-offer-0001", r.callId)
        assertEquals("sess-0001", r.sessionId)
    }

    @Test
    fun aPlaintextThatIsNotAnOfferIsNotVoiceOffer() {
        val r = VoiceOfferDecrypt.decryptVoiceOfferWith("armor") { ok("hello, this is a chat line") }
        assertEquals(VoiceOfferDecrypt.NOT_VOICE_OFFER, (r as VoiceOfferDecrypt.Result.Fail).code)
    }

    @Test
    fun anotherCallSignalIsNotAnOffer() {
        val accept = """{"type":"voice_call_accept_v1","callId":"call-offer-0001","sessionId":"sess-0001"}"""
        val r = VoiceOfferDecrypt.decryptVoiceOfferWith("armor") { ok(accept) }
        assertEquals(VoiceOfferDecrypt.NOT_VOICE_OFFER, (r as VoiceOfferDecrypt.Result.Fail).code)
    }

    @Test
    fun anOfferWithoutItsCallIdIsRefused() {
        val noCallId = """{"type":"voice_call_offer_v1","sessionId":"sess-0001"}"""
        val r = VoiceOfferDecrypt.decryptVoiceOfferWith("armor") { ok(noCallId) }
        assertEquals(VoiceOfferDecrypt.NOT_VOICE_OFFER, (r as VoiceOfferDecrypt.Result.Fail).code)
    }

    @Test
    fun aRefusedDecryptPassesItsFixedCodeThrough() {
        for (code in listOf("not_recipient", "bad_passphrase", "no_pgp_key", "pgp_locked", "bad_message")) {
            val r = VoiceOfferDecrypt.decryptVoiceOfferWith("armor") { NativePgp.Outcome.fail(code) }
            assertEquals(code, (r as VoiceOfferDecrypt.Result.Fail).code)
        }
    }

    @Test
    fun aThrowingDecryptFailsClosedAsStoreUnreadable() {
        val r = VoiceOfferDecrypt.decryptVoiceOfferWith("armor") { throw IllegalStateException("injected") }
        assertEquals(VoiceOfferDecrypt.STORE_UNREADABLE, (r as VoiceOfferDecrypt.Result.Fail).code)
    }

    @Test
    fun aSuccessWithNoPlaintextFailsClosed() {
        val r = VoiceOfferDecrypt.decryptVoiceOfferWith("armor") { NativePgp.Outcome.ok("") }
        assertTrue(r is VoiceOfferDecrypt.Result.Fail)
    }

    @Test
    fun theVaultsOwnRefusalsReachTheShellAsFixedCodes() {
        // No record: the vault answers no_pgp_key, and nothing is returned.
        val empty = NativePgpVault(NativeTestWrap(), NativeTestFiles(), eoa)
        val none = VoiceOfferDecrypt.decryptVoiceOfferWith(decryptCase("D-1").getString("armor")) { empty.decryptInbound(it) }
        assertEquals("no_pgp_key", (none as VoiceOfferDecrypt.Result.Fail).code)

        // A key is stored; a message for another recipient is refused as not_recipient.
        val vault = NativePgpVault(NativeTestWrap(), NativeTestFiles(), eoa)
        val key = vectors.getJSONObject("keys").getJSONObject("ecc-pass")
        assertEquals(NativePgpVault.Put.OK, vault.put(eoa, key.getString("privateArmored"), key.getString("passphrase")))
        val other = VoiceOfferDecrypt.decryptVoiceOfferWith(decryptCase("D-7").getString("armor")) { vault.decryptInbound(it) }
        assertEquals("not_recipient", (other as VoiceOfferDecrypt.Result.Fail).code)

        // A readable message that is not an offer (D-1 is a chat line) is not_voice_offer, not a success.
        val chat = VoiceOfferDecrypt.decryptVoiceOfferWith(decryptCase("D-1").getString("armor")) { vault.decryptInbound(it) }
        assertEquals(VoiceOfferDecrypt.NOT_VOICE_OFFER, (chat as VoiceOfferDecrypt.Result.Fail).code)
    }

    /** The expanded signal JSON keeps the offer's own fields (the shell verifies them), and the payload is the plaintext unchanged. */
    @Test
    fun theSignalJsonKeepsTheOffersOwnFieldsAndThePayloadIsUnchanged() {
        val signed = """{"type":"voice_call_offer_v1","callId":"call-offer-0001","sessionId":"sess-0001","from":"0x39581c72b8c7d0de85ff22cf3ae178ae813957aa","callerSignature":"0xabc"}"""
        val r = VoiceOfferDecrypt.decryptVoiceOfferWith("armor") { ok(signed) } as VoiceOfferDecrypt.Result.Ok
        assertEquals(signed, r.payload)
        val kept = JSONObject(r.signalJson)
        assertEquals("0xabc", kept.getString("callerSignature"))
        assertEquals("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa", kept.getString("from"))
    }

    /** An envelope (base64 of JSON) whose `text` holds the offer: the signal JSON is the inner offer, found by the same rule. */
    @Test
    fun anEnvelopeYieldsTheInnerOfferAsTheSignalJson() {
        val inner = """{"type":"voice_call_offer_v1","callId":"call-offer-0002","sessionId":"sess-0002"}"""
        val envelope = """{"timestamp":1763600000000,"text":${JSONObject.quote(inner)},"from":"0x39581c72b8c7d0de85ff22cf3ae178ae813957aa","signMessage":"sig-text"}"""
        val b64 = java.util.Base64.getEncoder().encodeToString(envelope.toByteArray(Charsets.UTF_8))
        val r = VoiceOfferDecrypt.decryptVoiceOfferWith("armor") { ok(b64) } as VoiceOfferDecrypt.Result.Ok
        assertEquals(b64, r.payload)
        assertEquals("call-offer-0002", r.callId)
        assertEquals("voice_call_offer_v1", JSONObject(r.signalJson).getString("type"))
        // The outer envelope's from and signMessage are exposed for the shell's outer-signature check.
        assertEquals("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa", r.envelopeFrom)
        assertEquals("sig-text", r.envelopeSignMessage)
        // The envelope text is the inner offer string, byte for byte: it is what the signature covers.
        assertEquals(inner, r.envelopeText)
    }

    /** A bare signal JSON has no envelope: the envelope fields are empty. */
    @Test
    fun aBareSignalHasNoEnvelopeFields() {
        val r = VoiceOfferDecrypt.decryptVoiceOfferWith("armor") { ok(offer) } as VoiceOfferDecrypt.Result.Ok
        assertEquals("", r.envelopeFrom)
        assertEquals("", r.envelopeSignMessage)
        assertEquals("", r.envelopeText)
    }
}
