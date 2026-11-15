package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Hardware layer of the native wallet key (spec r3b 25.17.5, device-key mode only). The key is
 * sealed with a non-exportable AES-GCM key: AndroidKeyStore on the device, an in-memory key in tests.
 */
interface KeyWrap {
    /** Returns `iv || ciphertext || tag`. Throws when the wrapping key is unavailable. */
    fun seal(aad: ByteArray, plain: ByteArray): ByteArray

    /** Returns the plaintext, or `null` when authentication fails or the wrapping key is gone. */
    fun open(aad: ByteArray, sealed: ByteArray): ByteArray?

    /** Removes the wrapping key. Records sealed under it can no longer be opened. True only when the key is gone. */
    fun deleteKey(): Boolean
}

/** Record and marker storage. [write] must be all-or-nothing (temp file and rename on the device). */
interface VaultFiles {
    fun read(name: String): ByteArray?
    fun write(name: String, bytes: ByteArray)
    fun delete(name: String)
}

/**
 * Native store for the account's EOA private key. Only native code writes it: a native import or a
 * legacy migration. The bridge never reaches it.
 *
 * Write order: record file, then read back from storage (unwrap, derive address, compare), then the
 * completion marker (SHA-256 of the record). A record without a matching marker was never confirmed
 * and is removed on the next [state] call. A record whose marker does not match is kept and locks the
 * vault, because deleting it could destroy the only copy.
 *
 * Nothing is overwritten: a second wallet is refused until [forget] runs. Plaintext keys are never
 * stored, logged or returned from [state]; [unlock] returns a fresh copy that the caller must zero.
 */
class NativeWalletVault(
    private val wrap: KeyWrap,
    private val files: VaultFiles,
) {
    sealed class State {
        /** No record: nothing to sign with. The user imports or creates natively. */
        object NoKey : State()

        /** A record exists, can be opened, and belongs to [eoa]. */
        class Ready(val eoa: String) : State()

        /**
         * A record exists but cannot be used. [reason] is a code, never key material. `rollback_pending` (spec §25.25.5) means an import
         * could not be rolled back: the account is unavailable and no import is offered.
         */
        class Locked(val reason: String) : State()
    }

    enum class Import(val code: String) {
        OK("ok"),
        ALREADY_PRESENT("already_present"),
        BAD_EOA("bad_eoa"),
        BAD_KEY("bad_key"),
        ADDRESS_MISMATCH("address_mismatch"),
        RECORD_EXISTS("record_exists"),
        STORE_FAILED("store_failed"),
        READBACK_FAILED("readback_failed"),
        /** A rollback removal failed: the intent stays and the account is unavailable (spec 25.25.5, 25.52Y.42 第 4 项 (e)). */
        ROLLBACK_PENDING("rollback_pending"),
    }

    private class Opened(val eoa: String, val key: ByteArray)

    /** What is stored for the account's recovery phrase (spec §25.52Y.42 第 5 项, §25.52Y.38 第 3 项). */
    sealed class MnemonicRead {
        class Stored(val eoa: String, val phrase: String) : MnemonicRead()
        object Missing : MnemonicRead()
        object Unavailable : MnemonicRead()
    }

    /**
     * Startup reconciliation (spec §25.52Y.42 第 4 项, r3nw): run before any read, and it only acts on the intent record.
     * - No intent: nothing to do. A key or phrase with no intent is existing data and is never removed.
     * - An intent that cannot be read or opened: nothing is removed; returns false (rollback_pending).
     * - A commit record present: the import completed; only the intent is removed.
     * - No commit record: the import did not complete; remove what the intent registered (the marker, the key record, the phrase record
     *   if planned, and the intent). A failed removal returns false and the intent stays for the next start.
     */
    private fun reconcile(): Boolean {
        val raw = files.read(INTENT) ?: return true
        val intent = readIntent(raw) ?: return false
        val commit = files.read(COMMIT)
        if (commit != null) {
            if (readCommit(commit, intent.eoa) == null) return false
            // A leftover intent of a completed import is harmless; a failed removal does not lock the account.
            runCatching { files.delete(INTENT) }
            return true
        }
        return try {
            files.delete(MARK)
            files.delete(REC)
            if (intent.mnemonicPlanned) files.delete(MNEM)
            files.delete(INTENT)
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * The marker rule (spec §25.52Y.42 第 4 项 (g)). With a marker it must equal the digest of the stored records. Without one, a record
     * that has no phrase record is a key-only record from before the marker rule, and it is accepted as it is: its AEAD tag and address
     * check still bind it, and nothing is written. A phrase record without a marker is damage.
     */
    private fun markerOk(rec: ByteArray, mark: ByteArray?, mnem: ByteArray?): Boolean =
        if (mark == null) mnem == null else mark.contentEquals(markerOf(rec, mnem))

    /** Reports the state. Never removes a key or phrase record that has no intent (spec §25.52Y.42 第 4 項 (d)). */
    @Synchronized
    fun state(): State {
        if (!reconcile()) return State.Locked("rollback_pending")
        val rec = files.read(REC)
        val mark = files.read(MARK)
        val mnem = files.read(MNEM)
        if (rec == null) {
            // A marker or phrase without a key record cannot be used. A bare marker is removed (it is not key material).
            if (mark != null) runCatching { files.delete(MARK) }
            return if (mnem != null) State.Locked("record_missing") else State.NoKey
        }
        if (!markerOk(rec, mark, mnem)) return State.Locked(if (mark == null) "marker_missing" else "marker_mismatch")
        val opened = openRecord(rec) ?: return State.Locked("unreadable")
        opened.key.fill(0)
        return State.Ready(opened.eoa)
    }

    /** A fresh copy of the key for a usable record. The caller must zero it after use. */
    @Synchronized
    fun unlock(): ByteArray? {
        if (!reconcile()) return null
        val rec = files.read(REC) ?: return null
        val mark = files.read(MARK)
        val mnem = files.read(MNEM)
        if (!markerOk(rec, mark, mnem)) return null
        return openRecord(rec)?.key
    }

    /**
     * Stores [key] for [eoa] after checks: canonical EOA, 32-byte valid scalar, derived address equal to
     * [eoa], nothing stored yet, readback, marker. [key] is only read; the caller zeroes it.
     */
    @Synchronized
    fun importKey(eoa: String, key: ByteArray, source: String = SOURCE_NATIVE_IMPORT): Import =
        store(eoa, key, source, phrase = null)

    /**
     * Stores [key] for [eoa] and the recovery phrase sealed under the same wrapping key (spec §25.52Y.42). [phrase] must be the canonical
     * form ([MnemonicDerivation.canonicalPhrase]) and must derive [key]; otherwise nothing is stored. The phrase is never logged or
     * returned from here.
     */
    @Synchronized
    fun importMnemonicKey(eoa: String, key: ByteArray, phrase: String, source: String = SOURCE_NATIVE_IMPORT): Import {
        val bytes = phrase.toByteArray(Charsets.UTF_8)
        try {
            val derived = MnemonicDerivation.deriveKey(phrase) ?: return Import.BAD_KEY
            try {
                if (!derived.contentEquals(key)) return Import.BAD_KEY
            } finally {
                derived.fill(0)
            }
            return store(eoa, key, source, phrase = bytes)
        } finally {
            bytes.fill(0)
        }
    }

    /**
     * The shell's blob of a recovery phrase (spec 25.52Y.38 第 6 项 (b), (c)): the phrase sealed under the hardware wrap, with the blob AAD of
     * the account. Android has no passcode layer, so this is the device-key form only. The blob is opaque to the page and is usable only on
     * this device and for this account.
     */
    @Synchronized
    fun sealBlob(eoa: String, phrase: ByteArray): String? = try {
        if (!isCanonicalEoa(eoa)) null else ConetChatCryptoUtil.toHex(wrap.seal(blobAad(eoa), phrase))
    } catch (e: Exception) {
        null
    }

    /** The phrase of a blob for [eoa], or null when it does not open under that account's AAD. The caller must not log it. */
    @Synchronized
    fun openBlob(eoa: String, blobHex: String): String? {
        if (!isCanonicalEoa(eoa)) return null
        val sealed = ConetChatCryptoUtil.hexToBytes(blobHex) ?: return null
        val plain = wrap.open(blobAad(eoa), sealed) ?: return null
        return try {
            String(plain, Charsets.UTF_8)
        } finally {
            plain.fill(0)
        }
    }

    /**
     * The recovery phrase of the usable record (spec §25.52Y.42 第 5 项, §25.52Y.38 第 3 项 (e)). [MnemonicRead.Missing] when no phrase was
     * stored (a key-only account, or one from before §25.52Y.42); [MnemonicRead.Unavailable] when the phrase cannot be read or does not
     * derive the record's key and address. The caller must not log the phrase.
     */
    @Synchronized
    fun mnemonicOf(): MnemonicRead {
        if (!reconcile()) return MnemonicRead.Unavailable
        val rec = files.read(REC) ?: return MnemonicRead.Unavailable
        val mark = files.read(MARK)
        val mnem = files.read(MNEM)
        if (!markerOk(rec, mark, mnem)) return MnemonicRead.Unavailable
        val opened = openRecord(rec) ?: return MnemonicRead.Unavailable
        try {
            if (mnem == null) return MnemonicRead.Missing
            val phrase = openMnemonic(mnem, opened.eoa) ?: return MnemonicRead.Unavailable
            val derived = MnemonicDerivation.deriveKey(phrase) ?: return MnemonicRead.Unavailable
            try {
                if (!derived.contentEquals(opened.key)) return MnemonicRead.Unavailable
            } finally {
                derived.fill(0)
            }
            return MnemonicRead.Stored(opened.eoa, phrase)
        } finally {
            opened.key.fill(0)
        }
    }

    /**
     * Import (spec §25.52Y.42 第 4 项, r3nw). The four records (key, phrase, marker, commit) and the intent must all be absent first; any
     * that is present or cannot be read refuses the import and writes nothing. Then the intent, the key record, the phrase record if
     * planned, the readback, the marker, and the commit record last; the intent is removed after the commit. A failure removes what this
     * call registered; a failed removal keeps the intent, so the next start reports rollback_pending.
     */
    private fun store(eoa: String, key: ByteArray, source: String, phrase: ByteArray?): Import {
        if (!isCanonicalEoa(eoa)) return Import.BAD_EOA
        if (source != SOURCE_NATIVE_IMPORT && source != SOURCE_NATIVE_CREATE && source != SOURCE_LEGACY) return Import.BAD_KEY
        if (key.size != 32) return Import.BAD_KEY
        val derived = WalletAddress.fromPrivateKey(key) ?: return Import.BAD_KEY
        if (derived != eoa) return Import.ADDRESS_MISMATCH
        when (val st = state()) {
            is State.Ready -> return if (st.eoa == eoa) Import.ALREADY_PRESENT else Import.RECORD_EXISTS
            is State.Locked -> return Import.RECORD_EXISTS
            State.NoKey -> Unit
        }
        // Precheck (r3nw 第 4 项 (i)): none of the four files may exist or be unreadable.
        for (name in listOf(REC, MNEM, MARK, COMMIT, INTENT)) {
            val present = try {
                files.read(name) != null
            } catch (e: Exception) {
                true
            }
            if (present) return Import.RECORD_EXISTS
        }
        try {
            files.write(INTENT, encodeIntent(eoa, mnemonicPlanned = phrase != null))
        } catch (e: Exception) {
            return rollbackAndReport(Import.STORE_FAILED, mnemonicPlanned = phrase != null)
        }
        val rec = try {
            encodeRecord(eoa, source, wrap.seal(aad(eoa), key))
        } catch (e: Exception) {
            return rollbackAndReport(Import.STORE_FAILED, mnemonicPlanned = phrase != null)
        }
        val mnem: ByteArray? = if (phrase == null) null else try {
            encodeMnemonic(eoa, wrap.seal(mnemAad(eoa), phrase))
        } catch (e: Exception) {
            return rollbackAndReport(Import.STORE_FAILED, mnemonicPlanned = true)
        }
        try {
            files.write(REC, rec)
            if (mnem != null) files.write(MNEM, mnem)
        } catch (e: Exception) {
            return rollbackAndReport(Import.STORE_FAILED, mnemonicPlanned = phrase != null)
        }
        val back = try {
            files.read(REC)?.let { openRecord(it) }
        } catch (e: Exception) {
            null
        }
        val confirmed = back != null && back.eoa == eoa && back.key.contentEquals(key)
        back?.key?.fill(0)
        val phraseConfirmed = mnem == null || try {
            files.read(MNEM)?.let { openMnemonic(it, eoa) }?.let { p -> phrase!!.contentEquals(p.toByteArray(Charsets.UTF_8)) } == true
        } catch (e: Exception) {
            false
        }
        if (!confirmed || !phraseConfirmed) return rollbackAndReport(Import.READBACK_FAILED, mnemonicPlanned = phrase != null)
        try {
            files.write(MARK, markerOf(rec, mnem))
            files.write(COMMIT, encodeCommit(eoa))
        } catch (e: Exception) {
            return rollbackAndReport(Import.STORE_FAILED, mnemonicPlanned = phrase != null)
        }
        // Committed. A failed removal of the intent is left for the next start.
        runCatching { files.delete(INTENT) }
        return Import.OK
    }

    /** Removes what this import registered, then the intent. Any removal that fails keeps the intent: the next start retries and reports rollback_pending. */
    private fun rollbackAndReport(code: Import, mnemonicPlanned: Boolean): Import {
        try {
            files.delete(COMMIT)
            files.delete(MARK)
            files.delete(REC)
            if (mnemonicPlanned) files.delete(MNEM)
            files.delete(INTENT)
        } catch (e: Exception) {
            // The intent stays; the next start retries and the account is rollback_pending (spec 25.52Y.42 第 4 项 (e)).
            return Import.ROLLBACK_PENDING
        }
        return code
    }

    /**
     * Removes the records, the markers, the intent and the wrapping key. Returns true only when every file is gone and the key is
     * removed (spec 25.52PY.8 (3)). A false result means the caller must not report the clear as finished.
     */
    @Synchronized
    fun forget(): Boolean {
        val filesGone = listOf(COMMIT, MARK, REC, MNEM, INTENT).map { eraseChecked(files, it) }.all { it }
        return filesGone && wrap.deleteKey()
    }

    private class Intent(val eoa: String, val mnemonicPlanned: Boolean)

    /**
     * The intent (r3ny, spec §25.52Y.42 第 4 项 (g)): UTF-8 JSON `{"v":1,"kind":"intent","eoa","sealed"}`. The sealed payload is
     * `{"v":1,"eoa","mnemonicPlanned","startedAt","phase":"begun"}` (startedAt is UTC to the second) under the intent AAD.
     */
    private fun encodeIntent(eoa: String, mnemonicPlanned: Boolean): ByteArray {
        val body = JSONObject()
            .put("v", RECORD_VERSION)
            .put("eoa", eoa)
            .put("mnemonicPlanned", mnemonicPlanned)
            .put("startedAt", java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
            .put("phase", "begun")
            .toString()
            .toByteArray(Charsets.UTF_8)
        return envelope("intent", eoa, wrap.seal(intentAad(eoa), body))
    }

    private fun readIntent(raw: ByteArray): Intent? {
        return try {
            val env = openEnvelope(raw, "intent") ?: return null
            val body = wrap.open(intentAad(env.eoa), env.sealed) ?: return null
            val b = JSONObject(String(body, Charsets.UTF_8))
            if (b.optInt("v", 0) != RECORD_VERSION || b.optString("eoa", "") != env.eoa) return null
            if (b.optString("phase", "") != "begun") return null
            Intent(env.eoa, b.getBoolean("mnemonicPlanned"))
        } catch (e: Exception) {
            null
        }
    }

    /** The commit record (r3ny): `{"v":1,"kind":"commit","eoa","sealed"}`; the payload is `{"v":1,"eoa","committedAt"}`. */
    private fun encodeCommit(eoa: String): ByteArray {
        val body = JSONObject()
            .put("v", RECORD_VERSION)
            .put("eoa", eoa)
            .put("committedAt", java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
            .toString()
            .toByteArray(Charsets.UTF_8)
        return envelope("commit", eoa, wrap.seal(commitAad(eoa), body))
    }

    private fun readCommit(raw: ByteArray, eoa: String): String? {
        return try {
            val env = openEnvelope(raw, "commit") ?: return null
            if (env.eoa != eoa) return null
            val body = wrap.open(commitAad(eoa), env.sealed) ?: return null
            val b = JSONObject(String(body, Charsets.UTF_8))
            if (b.optInt("v", 0) != RECORD_VERSION || b.optString("eoa", "") != eoa) null else eoa
        } catch (e: Exception) {
            null
        }
    }

    private class Envelope(val eoa: String, val sealed: ByteArray)

    private fun envelope(kind: String, eoa: String, sealed: ByteArray): ByteArray =
        JSONObject()
            .put("v", RECORD_VERSION)
            .put("kind", kind)
            .put("eoa", eoa)
            .put("sealed", ConetChatCryptoUtil.toHex(sealed))
            .toString()
            .toByteArray(Charsets.UTF_8)

    /** Parses an envelope of the given kind. Returns null for any other version, kind, or a malformed EOA or sealed field. */
    private fun openEnvelope(raw: ByteArray, kind: String): Envelope? {
        val o = JSONObject(String(raw, Charsets.UTF_8))
        if (o.optInt("v", 0) != RECORD_VERSION || o.optString("kind", "") != kind) return null
        val eoa = o.optString("eoa", "")
        if (!isCanonicalEoa(eoa)) return null
        val sealed = ConetChatCryptoUtil.hexToBytes(o.optString("sealed", "")) ?: return null
        return Envelope(eoa, sealed)
    }

    /** The phrase from a sealed phrase record for [eoa], or null. The caller must not log it. */
    private fun openMnemonic(mnem: ByteArray, eoa: String): String? {
        return try {
            val o = JSONObject(String(mnem, Charsets.UTF_8))
            if (o.optInt("record", 0) != RECORD_VERSION) return null
            if (o.optString("eoa", "") != eoa) return null
            val sealed = ConetChatCryptoUtil.hexToBytes(o.optString("sealed", "")) ?: return null
            val plain = wrap.open(mnemAad(eoa), sealed) ?: return null
            try {
                String(plain, Charsets.UTF_8)
            } finally {
                plain.fill(0)
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun encodeMnemonic(eoa: String, sealed: ByteArray): ByteArray =
        JSONObject()
            .put("record", RECORD_VERSION)
            .put("eoa", eoa)
            .put("sealed", ConetChatCryptoUtil.toHex(sealed))
            .toString()
            .toByteArray(Charsets.UTF_8)

    private fun openRecord(rec: ByteArray): Opened? {
        return try {
            val o = JSONObject(String(rec, Charsets.UTF_8))
            if (o.optInt("record", 0) != RECORD_VERSION) return null
            val eoa = o.optString("eoa", "")
            if (!isCanonicalEoa(eoa)) return null
            val sealed = ConetChatCryptoUtil.hexToBytes(o.optString("sealed", "")) ?: return null
            val key = wrap.open(aad(eoa), sealed) ?: return null
            if (key.size != 32 || WalletAddress.fromPrivateKey(key) != eoa) {
                key.fill(0)
                return null
            }
            Opened(eoa, key)
        } catch (e: Exception) {
            null
        }
    }

    private fun encodeRecord(eoa: String, source: String, sealed: ByteArray): ByteArray =
        JSONObject()
            .put("record", RECORD_VERSION)
            .put("eoa", eoa)
            .put("source", source)
            .put("sealed", ConetChatCryptoUtil.toHex(sealed))
            .toString()
            .toByteArray(Charsets.UTF_8)

    companion object {
        const val REC = "wallet.v1.rec"
        const val MARK = "wallet.v1.ok"
        /** The sealed recovery phrase (spec §25.52Y.42), written only by a phrase import. */
        const val MNEM = "wallet.v1.mnem"
        /** The import intent (spec §25.52Y.42 第 4 项, r3nw). It is not part of the marker digest. */
        const val INTENT = "wallet.v1.intent"
        /** The commit record, written last (spec §25.52Y.42 第 4 项, r3nw). */
        const val COMMIT = "wallet.v1.commit"
        const val RECORD_VERSION = 1
        const val SOURCE_NATIVE_IMPORT = "native_import"
        const val SOURCE_NATIVE_CREATE = "native_create"
        const val SOURCE_LEGACY = "legacy_migration"

        /** Hardware-layer AAD (spec 25.17.5): binds the record to its EOA. */
        fun aad(eoa: String): ByteArray = "beamio-native-wallet-v1|h|$eoa".toByteArray(Charsets.UTF_8)

        fun intentAad(eoa: String): ByteArray = "beamio-native-wallet-v1|i|$eoa".toByteArray(Charsets.UTF_8)
        fun commitAad(eoa: String): ByteArray = "beamio-native-wallet-v1|c|$eoa".toByteArray(Charsets.UTF_8)

        /** AAD of the shell's blob (spec 25.52Y.38 第 6 项 (b)). */
        fun blobAad(eoa: String): ByteArray = "beamio-native-wallet-v1|b|$eoa".toByteArray(Charsets.UTF_8)

        /** AAD of the sealed recovery phrase (spec §25.52Y.42 第 3 项 (b)). */
        fun mnemAad(eoa: String): ByteArray = "beamio-native-wallet-v1|m|$eoa".toByteArray(Charsets.UTF_8)

        /**
         * The completion marker. Without a phrase record it is the SHA-256 of the record, as before, so existing devices keep their
         * marker. With one it covers both records (spec §25.52Y.42 第 3 项 (b)).
         */
        fun markerOf(rec: ByteArray, mnem: ByteArray?): ByteArray {
            val r = digestHex(rec)
            return (if (mnem == null) r else r + "+" + digestHex(mnem)).toByteArray(Charsets.US_ASCII)
        }

        fun isCanonicalEoa(s: String): Boolean = Regex("^0x[0-9a-f]{40}$").matches(s)

        private fun digestHex(bytes: ByteArray): String =
            ConetChatCryptoUtil.toHex(MessageDigest.getInstance("SHA-256").digest(bytes))
    }
}
