package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import java.security.MessageDigest

/**
 * The PGP private key, its passphrase and its public fingerprint, held in the native wallet boundary (spec §25.22.2,
 * §25.26.4 table W6). The record is sealed with the same hardware wrap as the EOA key, under its own AAD, in its own
 * files. Plain text exists only while an operation runs; nothing here returns key material to a caller.
 *
 * Record layout: `pgp.v1.rec` (JSON: record, eoa, fingerprint, sealed hex) and the completion marker `pgp.v1.ok`
 * (SHA-256 hex of the record bytes). A record without its marker is removed at the next state check.
 */
internal class NativePgpVault(private val wrap: KeyWrap, private val files: VaultFiles) {

    sealed class State {
        /** No PGP record. The native key is required first (G0 or no PGP import yet). */
        object NoKey : State()

        /** A record passed its marker check and opened. [fingerprint] is the master-key fingerprint. */
        class Ready(val fingerprint: String) : State()

        /** A record exists but cannot be used. [reason] is a code, never key material. */
        class Locked(val reason: String) : State()
    }

    enum class Put(val code: String) {
        OK("ok"),
        BAD_EOA("bad_eoa"),
        BAD_KEY("bad_pgp_key"),
        STORE_FAILED("write_failed"),
        READBACK_FAILED("readback_failed"),
    }

    /** The plain record content. Built and dropped inside one operation. */
    private class Unlocked(val fingerprint: String, val privateArmor: String, val passphrase: String)

    /** Reports the state. Removes a record that never reached its marker. */
    @Synchronized
    fun state(): State {
        val rec = files.read(REC)
        val mark = files.read(MARK)
        if (rec == null) {
            if (mark != null) files.delete(MARK)
            return State.NoKey
        }
        if (mark == null) {
            files.delete(REC)
            return State.NoKey
        }
        if (!mark.contentEquals(digestHex(rec).toByteArray(Charsets.US_ASCII))) return State.Locked("marker_mismatch")
        val parsed = parseRecord(rec) ?: return State.Locked("unreadable")
        val opened = open(parsed) ?: return State.Locked("unreadable")
        return State.Ready(opened.fingerprint)
    }

    /**
     * Stores the PGP key for [eoa]. Replaces an earlier record for the same account. The record is written, read back
     * and compared, then the marker is written. On any failure the earlier record is restored, or nothing is left.
     * The passphrase, if any, is sealed with the key and never leaves the vault.
     */
    @Synchronized
    fun put(eoa: String, privateArmor: String, passphrase: String): Put {
        if (!isCanonicalEoa(eoa)) return Put.BAD_EOA
        val secret = NativePgp.parseSecret(privateArmor) ?: return Put.BAD_KEY
        val plain = JSONObject()
            .put("v", 1)
            .put("fp", secret.fingerprint)
            .put("priv", privateArmor)
            .put("pass", passphrase)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val rec = try {
            encodeRecord(eoa, secret.fingerprint, wrap.seal(aad(eoa), plain))
        } catch (e: Exception) {
            return Put.STORE_FAILED
        } finally {
            plain.fill(0)
        }
        val prevRec = files.read(REC)
        val prevMark = files.read(MARK)
        try {
            files.write(REC, rec)
        } catch (e: Exception) {
            restore(prevRec, prevMark)
            return Put.STORE_FAILED
        }
        val back = files.read(REC)?.let { parseRecord(it) }?.let { open(it) }
        val confirmed = back != null && back.fingerprint == secret.fingerprint && back.privateArmor == privateArmor
        if (!confirmed) {
            restore(prevRec, prevMark)
            return Put.READBACK_FAILED
        }
        try {
            files.write(MARK, digestHex(rec).toByteArray(Charsets.US_ASCII))
        } catch (e: Exception) {
            restore(prevRec, prevMark)
            return Put.STORE_FAILED
        }
        return Put.OK
    }

    /**
     * Decrypts an armored message to the vault key (C3). The caller passes only the message. Refusals:
     * `no_pgp_key`, `pgp_locked`, and the codes of [NativePgp.decryptMessage].
     */
    @Synchronized
    fun decryptInbound(armoredMessage: String): NativePgp.Outcome {
        val unlocked = unlock() ?: return refusal()
        val secret = NativePgp.parseSecret(unlocked.privateArmor)
            ?: return NativePgp.Outcome.fail("bad_pgp_key")
        return NativePgp.decryptMessage(secret, unlocked.passphrase, armoredMessage)
    }

    /**
     * Document signature (C4) over `beamio.pgp.<purposeId>.v1\n || message`. The purpose must be in [registry], and the
     * signature type must be 0x00 or 0x01. Certification signatures are refused. Returns an armored signature.
     */
    @Synchronized
    fun sign(
        purposeId: String,
        sigType: Int,
        message: ByteArray,
        registry: Set<String> = REGISTERED_PURPOSES,
    ): NativePgp.Outcome {
        // Order (spec 25.27.6, r3i): the signature type is judged first, then the purpose.
        if (sigType !in NativePgp.ALLOWED_SIG_TYPES) return NativePgp.Outcome.fail("sig_type_not_allowed")
        if (!PURPOSE_RE.matches(purposeId) || purposeId !in registry) {
            return NativePgp.Outcome.fail("purpose_not_registered")
        }
        val unlocked = unlock() ?: return refusal()
        val secret = NativePgp.parseSecret(unlocked.privateArmor)
            ?: return NativePgp.Outcome.fail("bad_pgp_key")
        return NativePgp.signDocument(secret, unlocked.passphrase, domainLabel(purposeId), message, sigType)
    }

    /** Removes the PGP record and its marker. Used when the EOA record is removed. */
    @Synchronized
    fun forget() {
        runCatching { files.delete(MARK) }
        runCatching { files.delete(REC) }
    }

    /** Test seam: the verifier for a signature made by [sign], with the vault key only. */
    @Synchronized
    internal fun verifySignature(purposeId: String, message: ByteArray, armoredSignature: String): Boolean {
        val unlocked = unlock() ?: return false
        val secret = NativePgp.parseSecret(unlocked.privateArmor) ?: return false
        return NativePgp.verifyDocument(secret, domainLabel(purposeId), message, armoredSignature)
    }

    private fun refusal(): NativePgp.Outcome {
        val st = state()
        val code = when (st) {
            is State.NoKey -> "no_pgp_key"
            else -> "pgp_locked"
        }
        return NativePgp.Outcome.fail(code)
    }

    private fun unlock(): Unlocked? {
        val rec = files.read(REC) ?: return null
        val mark = files.read(MARK) ?: return null
        if (!mark.contentEquals(digestHex(rec).toByteArray(Charsets.US_ASCII))) return null
        val parsed = parseRecord(rec) ?: return null
        return open(parsed)
    }

    private class Parsed(val eoa: String, val sealed: ByteArray)

    private fun parseRecord(rec: ByteArray): Parsed? {
        return try {
            val o = JSONObject(String(rec, Charsets.UTF_8))
            if (o.optInt("record", 0) != RECORD_VERSION) return null
            val eoa = o.optString("eoa", "")
            if (!isCanonicalEoa(eoa)) return null
            val sealed = ConetChatCryptoUtil.hexToBytes(o.optString("sealed", "")) ?: return null
            Parsed(eoa, sealed)
        } catch (_: Exception) {
            null
        }
    }

    private fun open(p: Parsed): Unlocked? {
        val plain = wrap.open(aad(p.eoa), p.sealed) ?: return null
        return try {
            val o = JSONObject(String(plain, Charsets.UTF_8))
            Unlocked(
                fingerprint = o.optString("fp", ""),
                privateArmor = o.optString("priv", ""),
                passphrase = o.optString("pass", ""),
            ).takeIf { it.fingerprint.isNotEmpty() && it.privateArmor.isNotEmpty() }
        } catch (_: Exception) {
            null
        } finally {
            plain.fill(0)
        }
    }

    private fun restore(prevRec: ByteArray?, prevMark: ByteArray?) {
        runCatching {
            if (prevRec != null && prevMark != null) {
                files.write(REC, prevRec)
                files.write(MARK, prevMark)
            } else {
                files.delete(MARK)
                files.delete(REC)
            }
        }
    }

    private fun encodeRecord(eoa: String, fingerprint: String, sealed: ByteArray): ByteArray =
        JSONObject()
            .put("record", RECORD_VERSION)
            .put("eoa", eoa)
            .put("fingerprint", fingerprint)
            .put("sealed", ConetChatCryptoUtil.toHex(sealed))
            .toString()
            .toByteArray(Charsets.UTF_8)

    private fun digestHex(bytes: ByteArray): String =
        ConetChatCryptoUtil.toHex(MessageDigest.getInstance("SHA-256").digest(bytes))

    private fun isCanonicalEoa(eoa: String): Boolean = EOA_RE.matches(eoa)

    companion object {
        const val REC = "pgp.v1.rec"
        const val MARK = "pgp.v1.ok"
        const val RECORD_VERSION = 1

        /** C4 purposes. The interface owner has not yet listed them (spec 25.22.2 refers to the enumeration only). */
        val REGISTERED_PURPOSES: Set<String> = emptySet()

        private val EOA_RE = Regex("^0x[0-9a-f]{40}$")

        /** spec 25.27.6: ASCII, first character a letter, then letters or digits; 1 to 32 bytes. Used with `matches`. */
        private val PURPOSE_RE = Regex("[A-Za-z][A-Za-z0-9]{0,31}")

        /** The native domain tag (spec 25.27.2 / 25.27.7 A): the caller never supplies or omits it. */
        internal fun domainLabel(purposeId: String): String = "beamio.pgp.$purposeId.v1\n"

        /** AAD for the PGP record. It differs from the EOA record's AAD, so the two cannot be swapped. */
        fun aad(eoa: String): ByteArray = "beamio-native-pgp-v1|h|${eoa.lowercase()}".toByteArray(Charsets.UTF_8)
    }
}
