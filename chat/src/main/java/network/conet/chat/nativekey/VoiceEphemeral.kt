package network.conet.chat.nativekey

import java.security.SecureRandom
import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject

/**
 * The shell-mode temporary voice material (v105 §112, 2026-11-21): the temporary wallet key and the channel keys are generated here with the platform
 * CSPRNG, never derived from the phrase, the main wallet or the long-term chat PGP key. The temporary wallet key stays in VoiceChannelKeys (in memory,
 * forgotten by sid). The temporary PGP private key stays in memory by sid and is never returned; only its public armor and fingerprint leave.
 * Nothing here is written to storage.
 *
 * Encoding (v113 §130, v124 §144.2): key and wk are standard base64 (RFC 4648 §4, with = padding) of 32 random bytes; temp is the lower-case 0x address.
 *
 * Erasure (one statement for both calls): the key copies made by tempSig and the held private armor and parsed secret of decryptInner cannot be erased on
 * the JVM, because String and object copies are not zeroable (a platform limit). The byte copies are zeroed where the code allows it. Each sid's held
 * material is dropped by [forget] and is never returned by any call.
 */
internal object VoiceEphemeral {
    const val NOT_READY = "not_ready"
    const val KEYGEN_FAILED = "keygen_failed"
    const val BAD_REQUEST = "bad_request"
    const val UNKNOWN_SID = "unknown_sid"
    const val DECRYPT_FAILED = "decrypt_failed"

    /** The bridge fields of voiceEphemeralPrepare and voiceEphemeralForget (envelope fields included). Not registered as bridge names yet. */
    val PREPARE_FIELDS: Set<String> = setOf("type", "reqId", "role", "sid", "needPgp")
    val FORGET_FIELDS: Set<String> = setOf("type", "reqId", "sid")

    private val ROLES = setOf("caller", "callee")
    private val SID_RE = Regex("^[A-Za-z0-9_-]{1,128}$")
    private const val KEY_ATTEMPTS = 8

    /** Temporary PGP private armor by sid, in memory only. Removed by forget. */
    private val tempPgp = HashMap<String, String>()

    /** Test seam: whether a temporary PGP private key is held for [sid]. Never returns the key. */
    @Synchronized
    internal fun holdsPgpFor(sid: String): Boolean = tempPgp.containsKey(sid)

    /**
     * The shell's prepare (v105 §112.3). Returns `{ok:true, channel:{sid, key, wk, temp, tempPgpFpr?, tempPgpArmor?}}` or `{ok:false, error}`.
     * [keygen] is the PGP generator (a seam for tests; production uses NativePgpKeyGen.generate).
     */
    @Synchronized
    fun prepare(
        role: Any?,
        sid: Any?,
        needPgp: Any?,
        random: SecureRandom = SecureRandom(),
        keygen: (String, SecureRandom) -> NativePgpKeyGen.Generated = { uid, rnd -> NativePgpKeyGen.generate(uid, rnd) },
    ): JSONObject {
        if (role !is String || role !in ROLES) return fail(BAD_REQUEST)
        if (sid !is String || !SID_RE.matches(sid)) return fail(BAD_REQUEST)
        if (needPgp !is Boolean) return fail(BAD_REQUEST)
        // The temporary wallet key: CSPRNG bytes, retried until they are a valid scalar. Never derived.
        var key: ByteArray? = null
        var address: String? = null
        for (i in 0 until KEY_ATTEMPTS) {
            val candidate = ByteArray(32).also { random.nextBytes(it) }
            val addr = WalletAddress.fromPrivateKey(candidate)?.lowercase()
            if (addr != null) {
                key = candidate
                address = addr
                break
            }
            candidate.fill(0)
        }
        val tk = key ?: return fail(KEYGEN_FAILED)
        val temp = address ?: return fail(KEYGEN_FAILED)
        val wk = ByteArray(32).also { random.nextBytes(it) }
        val channelKey = ByteArray(32).also { random.nextBytes(it) }
        var pgp: NativePgpKeyGen.Generated? = null
        if (needPgp) {
            pgp = try {
                keygen("beamio-voice-temp", random)
            } catch (_: Exception) {
                tk.fill(0); wk.fill(0); channelKey.fill(0)
                return fail(KEYGEN_FAILED)
            }
        }
        try {
            VoiceChannelKeys.register(sid, tk)
            if (pgp != null) tempPgp[sid] = pgp.privateArmor else tempPgp.remove(sid)
            val channel = JSONObject()
                .put("sid", sid)
                .put("key", java.util.Base64.getEncoder().encodeToString(channelKey))
                .put("wk", java.util.Base64.getEncoder().encodeToString(wk))
                .put("temp", temp)
            if (pgp != null) {
                channel.put("tempPgpFpr", pgp.fingerprint)
                channel.put("tempPgpArmor", pgp.publicArmor)
            }
            return JSONObject().put("ok", true).put("channel", channel)
        } finally {
            tk.fill(0)
            wk.fill(0)
            channelKey.fill(0)
        }
    }

    /**
     * The shell's forget (v105 §112.4): removes the temporary wallet key and the temporary PGP private key of [sid]. Idempotent: a sid with nothing held,
     * or already forgotten, is `ok:true`.
     */
    @Synchronized
    fun forget(sid: Any?): JSONObject {
        if (sid !is String || !SID_RE.matches(sid)) return fail(BAD_REQUEST)
        VoiceChannelKeys.forget(sid)
        tempPgp.remove(sid)
        return JSONObject().put("ok", true)
    }

    /**
     * `voiceEphemeralTempSig` (v113 §132, v109 §119.2): signs [text] (EIP-191 over its UTF-8 bytes) with the temporary wallet key of [sid]. Returns
     * `{ok:true, sig}` (0x hex) or `{ok:false, error}` with bad_request or unknown_sid. The key copy is zeroed on every path. Not a bridge command.
     *
     * Mapping and limits (interface seat , v155 §175.4): the primitive is the same one the voice_listen `tempSig` uses
     * ([NativeDerivation.voiceListenSignature]). The shell builds the text from the voice_listen canonical text; this side does not check its grammar.
     * It checks only that the text is non-empty, valid UTF-8 (no unpaired surrogate), and at most [MAX_TEXT_BYTES] (4096) bytes in UTF-8.
     */
    @Synchronized
    fun tempSig(sid: Any?, text: Any?): JSONObject {
        if (sid !is String || !SID_RE.matches(sid) || text !is String || text.isEmpty()) return fail(BAD_REQUEST)
        val bytes = textBytes(text) ?: return fail(BAD_REQUEST)
        val tk = VoiceChannelKeys.lookup(sid) ?: return fail(UNKNOWN_SID)
        try {
            val sig = network.conet.chat.nativekey.NativeDerivation.voiceListenSignature(tk, String(bytes, Charsets.UTF_8)) ?: return fail(BAD_REQUEST)
            return JSONObject().put("ok", true).put("sig", sig)
        } finally {
            tk.fill(0)
        }
    }

    /**
     * `voiceEphemeralDecryptInner` (v113 §132, v109 §119.2): decrypts the inner armor [armor] with the temporary PGP private key of [sid]. Returns
     * `{ok:true, plaintext}` or `{ok:false, error}` with bad_request, unknown_sid or decrypt_failed. The plaintext is not interpreted here.
      */
    @Synchronized
    fun decryptInner(sid: Any?, armor: Any?): JSONObject {
        if (sid !is String || !SID_RE.matches(sid) || armor !is String || armor.isEmpty()) return fail(BAD_REQUEST)
        val privateArmor = tempPgp[sid] ?: return fail(UNKNOWN_SID)
        val secret = NativePgp.parseSecret(privateArmor) ?: return fail(DECRYPT_FAILED)
        val out = NativePgp.decryptMessage(secret, "", armor)
        return if (out.code == "ok" && out.value != null) {
            JSONObject().put("ok", true).put("plaintext", out.value)
        } else {
            fail(DECRYPT_FAILED)
        }
    }

    /** The longest text tempSig accepts, in UTF-8 bytes (interface seat , v155 §175.4). */
    const val MAX_TEXT_BYTES = 4096

    /** UTF-8 bytes of [text], or null when it is not valid UTF-8 (an unpaired surrogate) or longer than [MAX_TEXT_BYTES]. */
    internal fun textBytes(text: String): ByteArray? {
        val encoder = Charsets.UTF_8.newEncoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        val bytes = try {
            val buf = encoder.encode(java.nio.CharBuffer.wrap(text))
            ByteArray(buf.remaining()).also { buf.get(it) }
        } catch (_: java.nio.charset.CharacterCodingException) {
            return null
        }
        return if (bytes.size in 1..MAX_TEXT_BYTES) bytes else null
    }

    private fun fail(code: String): JSONObject = JSONObject().put("ok", false).put("error", code)
}
