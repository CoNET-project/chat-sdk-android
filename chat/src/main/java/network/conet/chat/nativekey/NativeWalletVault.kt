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

/**
 * Record and marker storage. [write] must be all-or-nothing (temp file and rename on the device). [delete] throws when the removal does not
 * take effect; a caller that must know the file is gone checks [exists] (see [eraseChecked]), it never trusts a silent return.
 */
interface VaultFiles {
    fun read(name: String): ByteArray?
    fun write(name: String, bytes: ByteArray)
    fun delete(name: String)

    /** True when anything is present under [name], a file or not. The default reads the file back. */
    fun exists(name: String): Boolean = read(name) != null
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
        // Plan 1: only the names the manifest lists, and never a name that predates the import. An old-format intent (no manifest) deletes nothing.
        val manifest = intent.created ?: return false
        val allowed = setOf(MARK, REC, MNEM, COMMIT)
        // Each removal is confirmed (eraseChecked): a manifest file still present keeps the intent, so the state stays Locked and the next start retries.
        for (name in manifest) if (name in allowed && name != COMMIT) {
            if (!eraseChecked(files, name)) return false
        }
        return eraseChecked(files, INTENT)
    }

    /**
     * The marker rule (spec §25.52Y.42 第 4 项 (g), §25.52Y.92). With a marker it must equal the digest of the stored records. Without one, only
     * the legacy pure-key record is accepted as it is ([legacy], see [legacyPureKey]): its AEAD tag and address check still bind it, and nothing
     * is written. Any other record without a marker is damage (unreadable, never accepted or repaired here).
     */
    private fun markerOk(rec: ByteArray, mark: ByteArray?, mnem: ByteArray?, legacy: Boolean): Boolean =
        if (mark == null) legacy && mnem == null else mark.contentEquals(markerOf(rec, mnem))

    /**
     * The legacy pure-key exception (25.52Y.92 第 2 項): no phrase record, no intent record, no commit marker and no digest. Used by the reads
     * that run after the reconcile. [computeState] reads the intent before the reconcile, because the reconcile removes it.
     */
    private fun legacyPureKey(mark: ByteArray?, mnem: ByteArray?): Boolean =
        mark == null && mnem == null && files.read(COMMIT) == null && files.read(INTENT) == null

    /**
     * The last state computed under the lock, read without it (25.52Y.75, the snapshot of the command gate). `null` until the first computation
     * and while a write is in progress: the gate then answers not_ready once and does not touch the keystore on the caller's thread.
     */
    @Volatile
    private var snapshot: State? = null

    /** The snapshot, without the monitor. `null` when it is not known yet. Never blocks. */
    fun snapshotState(): State? = snapshot

    /**
     * The public, lower-case EOA of the key on this device, when the record reads and its address check passes (25.52X.4). That is the
     * derivation and the stored record, both successful. Null otherwise: an unreadable key gives no EOA. The key itself is never returned.
     */
    fun publicEoaIfReadable(): String? = (state() as? State.Ready)?.eoa?.lowercase()?.takeIf { PUBLIC_EOA.matches(it) }

    private val PUBLIC_EOA = Regex("^0x[0-9a-f]{40}$")

    /** Drops the snapshot. Used by the clear path in a finally block, so an interrupted clear never leaves a stale Ready. */
    fun invalidateSnapshot() {
        snapshot = null
    }

    /** Reports the state. Never removes a key or phrase record that has no intent (spec §25.52Y.42 第 4 項 (d)). Updates the snapshot. */
    @Synchronized
    fun state(): State {
        // 25.52Y.75 (project ruling 2026-11-16): between two invalidation events the snapshot is authoritative. Invalidated by store, forget,
        // lock and the clear path (invalidateSnapshot). External changes (a cleared app, a file changed outside the vault) are a stated risk,
        // caught at the next start and at the key check before signing.
        snapshot?.let { return it }
        val s = computeState()
        snapshot = s
        return s
    }

    private fun computeState(): State {
        // 25.52Y.92 第 2 項 (c): an intent present before the reconcile is a write in progress. The reconcile removes it, so it is read first.
        val intentBefore = files.read(INTENT) != null
        if (!reconcile()) return State.Locked("rollback_pending")
        val rec = files.read(REC)
        val mark = files.read(MARK)
        val mnem = files.read(MNEM)
        val commit = files.read(COMMIT)
        if (rec == null) {
            // A marker or phrase without a key record cannot be used. A read never removes it (project ruling 2026-11-16): an unknown state.
            if (mark != null || mnem != null) return State.Locked("record_missing")
            return State.NoKey
        }
        // 25.52Y.92 第 2 項: the legacy pure-key record is accepted only with a readable key record and no phrase, intent, commit marker or
        // digest. An intent or a digest without the commit marker is a write that did not finish: unreadable, never accepted or repaired here.
        if (commit == null && (intentBefore || mark != null)) {
            return State.Locked(if (mark == null) "marker_missing" else "marker_mismatch")
        }
        val legacy = !intentBefore && commit == null && mark == null && mnem == null
        if (!markerOk(rec, mark, mnem, legacy)) return State.Locked(if (mark == null) "marker_missing" else "marker_mismatch")
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
        if (!markerOk(rec, mark, mnem, legacyPureKey(mark, mnem))) return null
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
        if (!markerOk(rec, mark, mnem, legacyPureKey(mark, mnem))) return MnemonicRead.Unavailable
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
        // The snapshot is invalidated and recomputed on the next gate read (io). No reconcile runs here: a crash-recovery path must stay as it was.
        // Invalidated before and after the write: a read inside the write (readback) must not leave its own state behind.
        snapshot = null
        try {
            return storeWrite(eoa, key, source, phrase)
        } finally {
            snapshot = null
        }
    }

    private fun storeWrite(eoa: String, key: ByteArray, source: String, phrase: ByteArray?): Import {
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
            files.write(INTENT, encodeIntent(eoa, mnemonicPlanned = phrase != null, created = listOfNotNull(MARK, REC, if (phrase != null) MNEM else null, COMMIT)))
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
        val names = listOfNotNull(COMMIT, MARK, REC, if (mnemonicPlanned) MNEM else null, INTENT)
        // Every removal is confirmed. The intent is removed last and only after the others are gone; a failure keeps it, so the next start
        // retries and the account is rollback_pending (spec 25.52Y.42 第 4 项 (e)).
        val gone = names.all { eraseChecked(files, it) }
        return if (gone) code else Import.ROLLBACK_PENDING
    }

    /**
     * Removes the records, the markers, the intent and the wrapping key. Returns true only when every file is gone and the key is
     * removed (spec 25.52PY.8 (3)). A false result means the caller must not report the clear as finished.
     */
    @Synchronized
    fun forget(): Boolean {
        snapshot = null
        try {
            return forgetWrite()
        } finally {
            snapshot = null
        }
    }

    private fun forgetWrite(): Boolean {
        val filesGone = listOf(COMMIT, MARK, REC, MNEM, INTENT).map { eraseChecked(files, it) }.all { it }
        return filesGone && wrap.deleteKey()
    }

    /**
     * [created] is the manifest (project ruling 2026-11-16, plan 1): the file names this import creates. Every name in it was absent before the
     * import (the precheck). `null` for an old-format intent (no manifest): such an intent deletes nothing (rollback_pending).
     */
    private class Intent(val eoa: String, val mnemonicPlanned: Boolean, val created: List<String>?)

    /**
     * The intent (r3ny, spec §25.52Y.42 第 4 项 (g)): UTF-8 JSON `{"v":1,"kind":"intent","eoa","sealed"}`. The sealed payload is
     * `{"v":1,"eoa","mnemonicPlanned","startedAt","phase":"begun"}` (startedAt is UTC to the second) under the intent AAD.
     */
    internal fun encodeIntent(eoa: String, mnemonicPlanned: Boolean, created: List<String>?): ByteArray {
        val body = JSONObject()
            .put("v", RECORD_VERSION)
            .put("eoa", eoa)
            .put("mnemonicPlanned", mnemonicPlanned)
            // A null manifest is the old format (no `created`): reconcile deletes nothing for it (plan 1).
            .apply { if (created != null) put("created", org.json.JSONArray(created)) }
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
            val manifest = if (b.has("created")) b.getJSONArray("created").let { a -> (0 until a.length()).map { a.getString(it) } } else null
            Intent(env.eoa, b.getBoolean("mnemonicPlanned"), manifest)
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
