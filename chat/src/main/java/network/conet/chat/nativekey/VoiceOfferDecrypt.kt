package network.conet.chat.nativekey

import android.content.Context
import network.conet.chat.BeamioConetChatCallSignal

/**
 * The narrow decrypt the shell uses to resolve an incoming call offer (2026-11-20, plan B: a call is recognised while the wallet is locked).
 *
 * It decrypts one armored PGP message with the device's PGP record and accepts the plaintext only when it is a `voice_call_offer_v1` payload.
 * It returns that payload text, or a fixed failure code. It never returns a key, a passphrase or any session material, and it does not expose the
 * vault. The PGP record is sealed with the hardware wrap, not the passcode, so the decrypt does not depend on the passcode lock.
 *
 * Fail closed: an unreadable store, an exception, a refused decrypt, or a plaintext that is not an offer all give a [Result.Fail]. Nothing is
 * decided on a partial answer.
 *
 * UNVERIFIED (condition 1 and 2): a [Result.Ok] is NOT a verified offer. It does not check the offer's signature, its validity
 * period (validUntil), its duplicates, or the match of its R and from fields. The payload, callId and sessionId come from the unverified plaintext.
 * The caller must not use them as an identity, to bind a call, or to ring. Per §六 (G-3), what follows a verified offer is taken only
 * from the signed payload, which this function does not provide.
 */
object VoiceOfferDecrypt {
    /** The plaintext decrypted, but it is not a `voice_call_offer_v1` payload. */
    const val NOT_VOICE_OFFER = "not_voice_offer"

    /** The store could not be read, or the decrypt threw. Unknown, never a success. */
    const val STORE_UNREADABLE = "store_unreadable"

    private const val OFFER_TYPE = "voice_call_offer_v1"

    sealed class Result {
        /**
         * UNVERIFIED (see the class note). [payload] is the PGP-decrypted plaintext exactly as it came out of the message, not unwrapped and not
         * re-serialised. It is one of two shapes, depending on the sender:
         *  (a) the chat envelope, base64 of the JSON `{"timestamp":1763600000000,"text":"<inner>","from":"0x...","signMessage":"..."}`, where the
         *      offer sits inside `text`, and `text` is itself the signal JSON (or another wrapper);
         *  (b) the signal JSON directly: `{"type":"voice_call_offer_v1","callId":"<8-128 chars>","sessionId":"<id>", ...}`.
         * The offer is found by [BeamioConetChatCallSignal.classify], which accepts both shapes, base64, and nested `text`. So the caller must not
         * parse [payload] with one fixed rule; read [callId] and [sessionId] from this result instead. Example values are illustrative, not keys.
         * Do not bind a call or ring on these values until the offer is verified.
         */
        class Ok(
            val payload: String,
            val callId: String,
            val sessionId: String,
            /**
             * The expanded `voice_call_offer_v1` signal JSON, exactly as classify found it, with its own fields as sent (for example `callerSignature`
             * and `from`). Produced by the same rule as the classification, so the shell does not expand the payload itself. Still UNVERIFIED.
             */
            val signalJson: String,
            /** The outer envelope's `from`, when the plaintext is an envelope; empty when the plaintext is the signal JSON itself. Unverified. */
            val envelopeFrom: String = "",
            /** The outer envelope's `signMessage`, when the plaintext is an envelope; empty otherwise. Unverified. The shell checks the outer signature. */
            val envelopeSignMessage: String = "",
            /**
             * The envelope's `text` field, byte for byte as the JSON carries it: the text that the outer `signMessage` signs. Empty when the plaintext
             * is the signal JSON itself. Unverified; the shell recovers the signer of the signature over this text.
             */
            val envelopeText: String = "",
        ) : Result()

        /** [code] is a fixed word: a decrypt refusal (for example `not_recipient`), [NOT_VOICE_OFFER] or [STORE_UNREADABLE]. */
        class Fail(val code: String) : Result()
    }

    /** Decrypts [armoredCiphertext] with the device PGP record and returns the offer payload, or a failure code. */
    fun decryptVoiceOffer(app: Context, armoredCiphertext: String): Result =
        decryptVoiceOfferWith(armoredCiphertext) { armored ->
            try {
                NativeWallet.pgp(app).decryptInbound(armored)
            } catch (_: Exception) {
                NativePgp.Outcome.fail(STORE_UNREADABLE)
            }
        }

    /** The same rule with the decrypt supplied by the caller. The device path passes the vault; the tests pass a fixed outcome. */
    internal fun decryptVoiceOfferWith(armoredCiphertext: String, decrypt: (String) -> NativePgp.Outcome): Result {
        val outcome = try {
            decrypt(armoredCiphertext)
        } catch (_: Exception) {
            return Result.Fail(STORE_UNREADABLE)
        }
        val text = outcome.value
        if (!outcome.ok || text == null) return Result.Fail(outcome.code.ifEmpty { STORE_UNREADABLE })
        val signal = try {
            BeamioConetChatCallSignal.classify(text)
        } catch (_: Exception) {
            null
        }
        // An offer without its call identifier cannot be matched to a call, so it is refused (fail closed).
        if (signal == null || signal.kind != "offer" || signal.type != OFFER_TYPE || signal.callId.isEmpty()) {
            return Result.Fail(NOT_VOICE_OFFER)
        }
        val outer = outerEnvelope(text)
        // The envelope's own fields are taken from the outer object only when that object is an envelope, not the signal itself.
        val isEnvelope = outer != null && outer.optString("type") != OFFER_TYPE
        return Result.Ok(
            text,
            signal.callId,
            signal.sessionId,
            signal.signalJson ?: return Result.Fail(NOT_VOICE_OFFER),
            envelopeFrom = if (isEnvelope) outer!!.optString("from", "") else "",
            envelopeSignMessage = if (isEnvelope) outer!!.optString("signMessage", "") else "",
            envelopeText = if (isEnvelope) outer!!.optString("text", "") else "",
        )
    }

    /** The outermost JSON object of [text] (JSON, or base64 of JSON as UTF-8), or null. Only the outer layer; the nested offer is not read here. */
    private fun outerEnvelope(text: String): org.json.JSONObject? {
        val t = text.trim()
        if (t.startsWith("{")) return runCatching { org.json.JSONObject(t) }.getOrNull()
        val decoded = runCatching { String(java.util.Base64.getDecoder().decode(t.filter { !it.isWhitespace() }), Charsets.UTF_8) }.getOrNull()
        return decoded?.trim()?.takeIf { it.startsWith("{") }?.let { runCatching { org.json.JSONObject(it) }.getOrNull() }
    }
}
