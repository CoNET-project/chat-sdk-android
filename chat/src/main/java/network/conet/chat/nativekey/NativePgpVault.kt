package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import java.security.MessageDigest

/**
 * The PGP private key of one account, its passphrase and its public fingerprint, held in the native wallet boundary (spec
 * §25.22.2, §25.26.4 table W6). Each account has its own record (`pgp.v1.<account>.rec` and marker `pgp.v1.<account>.ok`),
 * so accounts never overwrite each other (§41-P-IMP-PGP, multi-account rule). A pending record (`pgp.v1.pending.<account>.*`)
 * holds a newly generated key until its registration is confirmed; it is never used as the active identity.
 *
 * The record is sealed with the same hardware wrap as the EOA key, under its own AAD per slot. Plain text exists only while
 * an operation runs; nothing here returns key material to a caller. A record without its marker is removed at the next state
 * check: an unconfirmed record is not a key.
 */
internal class NativePgpVault(
    private val wrap: KeyWrap,
    private val files: VaultFiles,
    /** The account this vault serves: a canonical (lower-case) address, or [NO_ACCOUNT]. */
    val account: String,
    private val slot: Slot = Slot.ACTIVE,
) {
    init {
        require(EOA_RE.matches(account)) { "account must be a canonical address" }
    }

    enum class Slot(val fileTag: String, val aadTag: String) {
        /** The identity in use. */
        ACTIVE("", ""),

        /** A generated key awaiting its registration. Never the active identity. */
        PENDING("pending.", "|pending"),

        /** The pre-replacement backup, wrapped on this device before an explicit replacement (R3, §25.30.5). */
        OLD("old.", "|old"),
    }

    sealed class State {
        /** No PGP record for this account. The native key is required first (G0 or no PGP import yet). */
        object NoKey : State()

        /** A record passed its marker check and opened. [fingerprint] is the master-key fingerprint. */
        class Ready(val fingerprint: String) : State()

        /** A record exists but cannot be used. [reason] is a code, never key material. */
        class Locked(val reason: String) : State()
    }

    enum class Put(val code: String) {
        OK("ok"),
        /** put refused: a record or marker already exists (25.52Y.80, keep the user's data). Nothing is written. */
        EXISTS("exists"),
        BAD_EOA("bad_eoa"),
        BAD_KEY("bad_pgp_key"),
        STORE_FAILED("write_failed"),
        READBACK_FAILED("readback_failed"),
    }

    /**
     * The plain record content, held as bytes (long-lived key material is a ByteArray and is zeroed). One instance lives for one
     * operation; [close] zeroes it. Text views exist only for the call that needs a String, and are not kept.
     */
    private class Unlocked(val fingerprint: String, val privateArmor: ByteArray, val passphrase: ByteArray) : AutoCloseable {
        fun armorText(): String = String(privateArmor, Charsets.UTF_8)
        fun passphraseText(): String = String(passphrase, Charsets.UTF_8)
        override fun close() {
            privateArmor.fill(0)
            passphrase.fill(0)
        }
    }


    private val rec = recName(account, slot)
    private val mark = markName(account, slot)

    /**
     * Reports the state. A read never deletes anything (keep the user's data). A record without its marker is
     * Locked("marker_missing"), an unknown state that retries; it is not treated as absent, so nothing creates a new key over it. A marker
     * without a record is Locked("record_missing") for the same reason. Only a write's own rollback removes records (restore).
     */
    @Synchronized
    fun state(): State {
        val r = files.read(rec)
        val m = files.read(mark)
        if (r == null) {
            return if (m == null) State.NoKey else State.Locked("record_missing")
        }
        if (m == null) return State.Locked("marker_missing")
        if (!m.contentEquals(digestHex(r).toByteArray(Charsets.US_ASCII))) return State.Locked("marker_mismatch")
        val parsed = parseRecord(r) ?: return State.Locked("unreadable")
        if (parsed.eoa != account) return State.Locked("account_mismatch")
        val opened = open(parsed) ?: return State.Locked("unreadable")
        return State.Ready(opened.fingerprint)
    }

    /**
     * What one open of the record gives: the state, the identity and, when asked, a copy of the private armor, all from a single
     * Keystore decrypt. [state] is what [state] would have said; [identity] is what [identity] would have said (null when the key cannot be
     * parsed); [signature] is the plain-file signature of the record and marker as they were read for this open ([fileSignatureOf]).
     * The caller owns [armor] and zeroes it.
     */
    internal class Read(val state: State, val identity: PgpIdentity?, val armor: ByteArray?, val signature: String, val publicArmor: String? = null)

    /**
     * [state], [identity] and [armorForMove] with ONE decrypt instead of three (the S25 StrongBox operation is seconds long). The checks and their
     * order are those of [state]: a record without its marker, a mismatching marker, an unreadable or foreign record is Locked, never opened.
     * Nothing is deleted or written here. The public part also refreshes [PublicIdentitySnapshot] for an active slot.
     */
    @Synchronized
    internal fun readOnce(wantArmor: Boolean): Read {
        val r = files.read(rec)
        val m = files.read(mark)
        val sig = fileSignatureOf(r, m)
        fun locked(reason: String) = Read(State.Locked(reason), null, null, sig)
        if (r == null) return if (m == null) Read(State.NoKey, null, null, sig) else locked("record_missing")
        if (m == null) return locked("marker_missing")
        if (!m.contentEquals(digestHex(r).toByteArray(Charsets.US_ASCII))) return locked("marker_mismatch")
        val parsed = parseRecord(r) ?: return locked("unreadable")
        if (parsed.eoa != account) return locked("account_mismatch")
        val opened = open(parsed) ?: return locked("unreadable")
        return try {
            val identity = try {
                NativePgp.parseSecret(opened.armorText())?.let { secret ->
                    NativePgpBackup.subkeyKeyId(secret)?.let { PgpIdentity(secret.fingerprint.uppercase(), it) }
                }
            } catch (_: Exception) {
                null
            }
            // The public armor is derived from the open record here, so the snapshot never needs a second decrypt for it (only the public part is kept).
            val publicArmor = try {
                NativePgpKeyGen.publicArmorOf(opened.armorText())
            } catch (_: Exception) {
                null
            }
            Read(State.Ready(opened.fingerprint), identity, if (wantArmor) opened.privateArmor.copyOf() else null, sig, publicArmor)
        } finally {
            opened.close()
        }
    }

    /**
     * The plain-file signature of this slot's record and marker (no Keystore): a digest of each file's bytes, or `-` for an absent file. It changes
     * whenever either file is written, replaced or deleted by anything, so a cached public identity is valid only while it is unchanged.
     * Null when a file cannot be read (unknown: the cache is not used).
     */
    internal fun fileSignature(): String? = try {
        fileSignatureOf(files.read(rec), files.read(mark))
    } catch (_: Exception) {
        null
    }

    private fun fileSignatureOf(r: ByteArray?, m: ByteArray?): String =
        (r?.let { digestHex(it) } ?: "-") + ":" + (m?.let { digestHex(it) } ?: "-")

    /**
     * Stores the PGP key for [eoa], which must be this vault's account. Replaces an earlier record of this slot. The record
     * is written, read back and compared, then the marker is written. On any failure the earlier record is restored, or
     * nothing is left. The passphrase, if any, is sealed with the key and never leaves the vault.
     */
    /**
     * Writes the record (keep the user's data). Inside the lock: a record or a marker that already exists is refused
     * with [Put.EXISTS] and nothing is written, unless [overwrite] is set. Only the user's confirmed replacement and the restore rollback pass
     * [overwrite] = true.
     */
    @Synchronized
    fun put(eoa: String, privateArmor: String, passphrase: String, overwrite: Boolean = false): Put {
        // A write to the active slot drops the cached public identity before anything is touched and after it ends, so no reader sees an old one.
        if (slot == Slot.ACTIVE) PublicIdentitySnapshot.invalidate(account)
        try {
            return putLocked(eoa, privateArmor, passphrase, overwrite)
        } finally {
            if (slot == Slot.ACTIVE) PublicIdentitySnapshot.invalidate(account)
        }
    }

    private fun putLocked(eoa: String, privateArmor: String, passphrase: String, overwrite: Boolean): Put {
        if (!overwrite && (files.read(rec) != null || files.read(mark) != null)) return Put.EXISTS
        if (account == NO_ACCOUNT || eoa != account) return Put.BAD_EOA
        val secret = NativePgp.parseSecret(privateArmor) ?: return Put.BAD_KEY
        val plain = JSONObject()
            .put("v", 1)
            .put("fp", secret.fingerprint)
            .put("priv", privateArmor)
            .put("pass", passphrase)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val recBytes = try {
            encodeRecord(account, secret.fingerprint, wrap.seal(aad(account, slot), plain))
        } catch (e: Exception) {
            // The reason goes to the log as a class name only (never a message, a name or a byte): a wrap that cannot seal is told apart from a write.
            DiagTiming.log("vault.put:seal", DiagTiming.now(), e.javaClass.simpleName)
            return Put.STORE_FAILED
        } finally {
            plain.fill(0)
        }
        val prevRec = files.read(rec)
        val prevMark = files.read(mark)
        try {
            files.write(rec, recBytes)
        } catch (e: Exception) {
            DiagTiming.log("vault.put:write", DiagTiming.now(), e.javaClass.simpleName)
            restore(prevRec, prevMark)
            return Put.STORE_FAILED
        }
        val back = files.read(rec)?.let { parseRecord(it) }?.let { open(it) }
        val confirmed = try {
            back != null && back.fingerprint == secret.fingerprint && back.armorText() == privateArmor
        } finally {
            back?.close()
        }
        if (!confirmed) {
            restore(prevRec, prevMark)
            return Put.READBACK_FAILED
        }
        try {
            files.write(mark, digestHex(recBytes).toByteArray(Charsets.US_ASCII))
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
        return try {
            val secret = NativePgp.parseSecret(unlocked.armorText())
                ?: return NativePgp.Outcome.fail("bad_pgp_key")
            NativePgp.decryptMessage(secret, unlocked.passphraseText(), armoredMessage)
        } finally {
            unlocked.close()
        }
    }

    /**
     * The same decrypt as [decryptInbound], but returns the literal's format and bytes, so the caller can check the
     * UTF-8 rule (spec 25.34.2, step 6). Refusals: `no_pgp_key`, `pgp_locked`, and the codes of [NativePgp.decryptLiteral].
     */
    @Synchronized
    fun decryptInboundLiteral(armoredMessage: String): NativePgp.LiteralResult {
        val unlocked = unlock() ?: return NativePgp.LiteralResult.fail(refusal().code)
        return try {
            val secret = NativePgp.parseSecret(unlocked.armorText())
                ?: return NativePgp.LiteralResult.fail("bad_pgp_key")
            NativePgp.decryptLiteral(secret, unlocked.passphraseText(), armoredMessage)
        } finally {
            unlocked.close()
        }
    }

    /**
     * Document signature (C4) over `beamio.pgp.<purposeId>.v1\n || message`. The purpose must be in [registry], and the
     * signature type must be 0x00 or 0x01. Certification signatures are refused. Returns an armored signature.
     */
    @Synchronized
    /**
     * The stored record and its marker are both present, and the marker does not match: the record is locked (25.52CI.1). Unlike [state],
     * nothing is opened, decrypted or deleted here.
     */
    fun locked(): Boolean {
        val r = files.read(rec) ?: return false
        val m = files.read(mark) ?: return false
        return !m.contentEquals(digestHex(r).toByteArray(Charsets.US_ASCII))
    }

    fun sign(
        purposeId: String,
        sigType: Int,
        message: ByteArray,
        registry: Set<String> = REGISTERED_PURPOSES,
    ): NativePgp.Outcome {
        // 25.52CI.1 (r3eh): the lock is judged first. A locked record refuses with pgp_locked, before the signature type, the purpose and any key read.
        if (locked()) return NativePgp.Outcome.fail("pgp_locked")
        // Order (spec 25.27.6, r3i): the signature type is judged first, then the purpose.
        if (sigType !in NativePgp.ALLOWED_SIG_TYPES) return NativePgp.Outcome.fail("sig_type_not_allowed")
        if (!PURPOSE_RE.matches(purposeId) || purposeId !in registry) {
            return NativePgp.Outcome.fail("purpose_not_registered")
        }
        // 25.27.6 step 2a (r3em, CM.2): a text signature (0x01) must not carry a CR. The SDK builds the internal messages without one, so this
        // is an assertion. It comes before the key is opened.
        if (sigType == NativePgp.SIG_CANONICAL_TEXT && message.contains(0x0D.toByte())) {
            return NativePgp.Outcome.fail("message_contains_cr")
        }
        val unlocked = unlock() ?: return refusal()
        return try {
            val secret = NativePgp.parseSecret(unlocked.armorText())
                ?: return NativePgp.Outcome.fail("bad_pgp_key")
            NativePgp.signDocument(secret, unlocked.passphraseText(), domainLabel(purposeId), message, sigType)
        } finally {
            unlocked.close()
        }
    }

    /** Removes this slot's record and marker. Other accounts and the other slot are not touched. True only when both are gone (PY.8 (3)). */
    @Synchronized
    fun forget(): Boolean {
        if (slot == Slot.ACTIVE) PublicIdentitySnapshot.invalidate(account)
        val markGone = eraseChecked(files, mark)
        val recGone = eraseChecked(files, rec)
        if (slot == Slot.ACTIVE) PublicIdentitySnapshot.invalidate(account)
        return markGone && recGone
    }

    /** True when this slot holds a record or marker (or cannot be read: unknown counts as present). */
    @Synchronized
    fun hasRecord(): Boolean = try {
        files.read(rec) != null || files.read(mark) != null
    } catch (_: Exception) {
        true
    }

    /** The identity of the record in this slot: uppercase master fingerprint and first subkey key ID. Null if none. */
    @Synchronized
    internal fun identity(): PgpIdentity? {
        val unlocked = unlock() ?: return null
        return try {
            val secret = NativePgp.parseSecret(unlocked.armorText()) ?: return null
            val sub = NativePgpBackup.subkeyKeyId(secret) ?: return null
            PgpIdentity(secret.fingerprint.uppercase(), sub)
        } finally {
            unlocked.close()
        }
    }

    /**
     * G1 (review): the three-state identity read of this slot. Absent only when the slot is confirmed empty (no record, no marker); a record
     * whose key cannot be read or parsed is Unknown (25.52Y.84), never Absent.
     */
    @Synchronized
    internal fun identityRead(): IdentityRead {
        if (state() is State.NoKey) return IdentityRead.Absent
        val id = identity() ?: return IdentityRead.Unknown
        return IdentityRead.Present(id)
    }

    /**
     * A copy of the armor of the record in this slot, for native-only moves between slots. The caller owns the copy and zeroes it. Never leaves
     * the native layer.
     */
    @Synchronized
    internal fun armorForMove(): ByteArray? {
        val unlocked = unlock() ?: return null
        return try {
            unlocked.privateArmor.copyOf()
        } finally {
            unlocked.close()
        }
    }

    /** True for the pending slot. Used to refuse a call that mixes the two slots. */
    fun isPendingSlot(): Boolean = slot == Slot.PENDING

    /**
     * Native-only hand-over of a pending key to the active slot (activation after a confirmed registration). Returns the armor
     * for the caller to store in the active slot, and never leaves the native layer. `null` when no ready pending key exists.
     */
    @Synchronized
    internal fun pendingArmorForActivation(): ByteArray? {
        check(slot == Slot.PENDING) { "only the pending slot hands over a key" }
        return armorForMove()
    }

    /** Test seam: the verifier for a signature made by [sign], with the vault key only. */
    @Synchronized
    internal fun verifySignature(purposeId: String, message: ByteArray, armoredSignature: String): Boolean {
        val unlocked = unlock() ?: return false
        return try {
            val secret = NativePgp.parseSecret(unlocked.armorText()) ?: return false
            NativePgp.verifyDocument(secret, domainLabel(purposeId), message, armoredSignature)
        } finally {
            unlocked.close()
        }
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
        val r = files.read(rec) ?: return null
        val m = files.read(mark) ?: return null
        if (!m.contentEquals(digestHex(r).toByteArray(Charsets.US_ASCII))) return null
        val parsed = parseRecord(r) ?: return null
        if (parsed.eoa != account) return null
        return open(parsed)
    }

    private class Parsed(val eoa: String, val sealed: ByteArray)

    private fun parseRecord(bytes: ByteArray): Parsed? {
        return try {
            val o = JSONObject(String(bytes, Charsets.UTF_8))
            if (o.optInt("record", 0) != RECORD_VERSION) return null
            val eoa = o.optString("eoa", "")
            if (!EOA_RE.matches(eoa)) return null
            val sealed = ConetChatCryptoUtil.hexToBytes(o.optString("sealed", "")) ?: return null
            Parsed(eoa, sealed)
        } catch (_: Exception) {
            null
        }
    }

    private fun open(p: Parsed): Unlocked? {
        val plain = wrap.open(aad(p.eoa, slot), p.sealed) ?: return null
        return try {
            // The JSON parse makes transient Strings; the record keeps only the byte forms (the stored format is unchanged).
            val o = JSONObject(String(plain, Charsets.UTF_8))
            val fp = o.optString("fp", "")
            val priv = o.optString("priv", "")
            if (fp.isEmpty() || priv.isEmpty()) return null
            Unlocked(fp, priv.toByteArray(Charsets.UTF_8), o.optString("pass", "").toByteArray(Charsets.UTF_8))
        } catch (_: Exception) {
            null
        } finally {
            plain.fill(0)
        }
    }

    private fun restore(prevRec: ByteArray?, prevMark: ByteArray?) {
        runCatching {
            if (prevRec != null && prevMark != null) {
                files.write(rec, prevRec)
                files.write(mark, prevMark)
            } else {
                files.delete(mark)
                files.delete(rec)
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

    companion object {
        const val RECORD_VERSION = 1

        /** The account of a device with no wallet key. Its vault never holds a record. */
        const val NO_ACCOUNT = "0x0000000000000000000000000000000000000000"

        /** C4 purposes. The interface owner has not yet listed them (spec 25.22.2 refers to the enumeration only). */
        val REGISTERED_PURPOSES: Set<String> = emptySet()

        private val EOA_RE = Regex("^0x[0-9a-f]{40}$")

        /** spec 25.27.6: ASCII, first character a letter, then letters or digits; 1 to 32 bytes. Used with `matches`. */
        private val PURPOSE_RE = Regex("[A-Za-z][A-Za-z0-9]{0,31}")

        /** The native domain tag (spec 25.27.2 / 25.27.7 A): the caller never supplies or omits it. */
        internal fun domainLabel(purposeId: String): String = "beamio.pgp.$purposeId.v1\n"

        private fun bare(account: String): String = account.lowercase().removePrefix("0x")

        /** File name of the record of [account] in [slot]. */
        fun recName(account: String, slot: Slot = Slot.ACTIVE): String = "pgp.v1.${slot.fileTag}${bare(account)}.rec"

        /** File name of the pending key's metadata (idempotency key, observed chain version and kind; no key material). */
        fun pendingMetaName(account: String): String = "pgp.v1.pending.${bare(account)}.meta"

        /** File name of the idempotency key of the last completed replacement or first identity (no key material). */
        fun completedName(account: String): String = "pgp.v1.done.${bare(account)}.idem"

        /** File name of the marker of [account] in [slot]. */
        fun markName(account: String, slot: Slot = Slot.ACTIVE): String = "pgp.v1.${slot.fileTag}${bare(account)}.ok"

        /**
         * AAD for the PGP record. It binds the account and the slot, so a record cannot be moved to another account or into
         * the other slot. The active AAD is the one used since the native PGP record was introduced.
         */
        fun aad(eoa: String, slot: Slot = Slot.ACTIVE): ByteArray =
            "beamio-native-pgp-v1|h|${eoa.lowercase()}${slot.aadTag}".toByteArray(Charsets.UTF_8)
    }
}
