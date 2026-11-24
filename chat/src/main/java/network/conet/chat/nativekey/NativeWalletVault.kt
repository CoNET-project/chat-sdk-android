package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
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

    /**
     * The presence of the wrapping key (25.52Y.122 第 1 項). [WrapKeyPresence.CONFIRMED_ABSENT] only when the keystore enumeration succeeded and
     * the alias is not in it. The default is unknown, so a wrap that cannot tell never reads as absent.
     */
    fun presence(): WrapKeyPresence = WrapKeyPresence.UNKNOWN
}

/** The presence of a wrapping key (25.52Y.122 第 1 項). An absent key is confirmed only when the enumeration itself succeeded. */
enum class WrapKeyPresence { PRESENT, CONFIRMED_ABSENT, UNKNOWN }

/**
 * Thrown by [KeyWrap.seal] when the alias is confirmed absent while sealed records exist (25.52Y.124 第 2 項 (a)). The seal creates no key and
 * writes nothing; the vault reports `wrap_key_missing`.
 */
class WrapKeyMissingException : IllegalStateException("wrap_key_missing")

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

    /**
     * Moves [from] to [to], which must not exist (25.52Y.128 第 3 項 (a)). The write path only. The default is a copy and a delete, for test
     * doubles; the device implementation is one move, and never replaces.
     */
    fun rename(from: String, to: String) {
        if (exists(to)) throw IOException("rename target exists")
        val bytes = read(from) ?: throw IOException("rename source absent")
        write(to, bytes)
        delete(from)
    }

    /** The names in the vault directory. The write path uses it to isolate every sealed record under a confirmed loss (25.52Y.136 第 8 項). */
    fun names(): List<String> = emptyList()
}

/**
 * Native store for the account's EOA private key. Only native code writes it: a native import or a
 * legacy migration. The bridge never reaches it.
 *
 * Write order: record file, then read back from storage (unwrap, derive address, compare), then the
 * completion marker (SHA-256 of the record). A record without a matching marker was never confirmed
 * and is removed only by the next write operation (settleForWrite, 25.52Y.125); a read never removes it. A record whose marker does not match is kept and locks the
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
        /** Internal cause: the wrap cannot seal (absent with sealed records, or unknown). Nothing was written; on the wire it is not_ready, unreadable (25.52Y.136 第 7 項). */
        WRAP_KEY_MISSING("wrap_key_missing"),
        /** An overwrite whose old copy cannot be verified (a present file that does not open, a different address, or the account_address.v1 flag
         *  names another account or cannot be read): nothing moved. On the pwaWalletSync wire: write_failed with reason old_copy_unverified. */
        OLD_COPY_UNVERIFIED("old_copy_unverified"),
        /** Written and read back, but the pending marker could not be removed: the record is good, the marker stays (25.52Y.136 第 9 項). */
        OK_CLEANUP_PENDING("ok_cleanup_pending"),
        /** The seal did not verify (v2 §三): the old names are restored, nothing is written, retryable. */
        SEALING_FAILED("sealing_failed"),
    }

    private class Opened(val eoa: String, val key: ByteArray)

    /** What is stored for the account's recovery phrase (spec §25.52Y.42 第 5 项, §25.52Y.38 第 3 项). */
    sealed class MnemonicRead {
        class Stored(val eoa: String, val phrase: String) : MnemonicRead()
        object Missing : MnemonicRead()
        object Unavailable : MnemonicRead()
    }

    /**
     * Read-only judgement of the intent record (spec §25.52Y.42 第 4 项, §25.52Y.125 第 2 項). Nothing is removed and nothing is written.
     * - No intent: settled. A key or phrase with no intent is existing data and is never removed.
     * - An intent that cannot be read, or a commit record that cannot be read or does not match: not settled (rollback_pending, unknown).
     * - A commit record that matches: the import completed; the leftover intent is harmless and is removed by the next write.
     * - An intent without a commit record: the import did not finish; not settled until a write operation rolls it back ([settleForWrite]).
     */
    /**
     * The pending marker carries the additive field `overwrite=true` (written only by the overwrite path). A marker without the field is read as not
     * an overwrite. Reads only. Used by the pre-read for a listed sealed copy that does not read (2026-11-18, on the unsettled overwrite).
     */
    internal fun overwriteMarkerNew(): Boolean = pendingMarkOrNull()?.overwrite == true

    /**
     * An unsettled overwrite ( iii, implemented with the additive field `overwrite`): the pending marker has overwrite=true and
     * lists an isolated copy of the fixed REC or MNEM. Not the list alone: a residual MARK of an import makes the list non-empty, a first write
     * has no overwrite marker, and a keep entry (a settled move) has no overwrite flag. A marker without the field is not an overwrite. Reads only.
     */
    internal fun overwriteIntentUnsettled(): Boolean =
        pendingMarkOrNull()?.let { m -> m.overwrite && m.items.any { it.name == REC || it.name == MNEM } } == true

    /**
     * E1 (global rule: a read failure is unknown and retryable): a pending marker that is present but cannot be read or parsed
     * is an unsettled state the pre-read must not answer valid for. It is not an overwrite proof either way (the marker cannot be read), so the
     * pre-read answer is unknown. An absent marker is not this case. Reads only.
     */
    /** A read of the pending marker itself throws (an I/O fault): unknown for any pre-read answer (global rule). Reads only. */
    internal fun pendingMarkerReadFault(): Boolean = try {
        files.read(PENDING)
        false
    } catch (_: Exception) {
        true
    }

    internal fun pendingMarkerUnreadable(): Boolean = try {
        files.read(PENDING)?.let { pendingMarkOrNull() == null } == true
    } catch (_: Exception) {
        true
    }

    /** The EOA of a verified current account (validCurrentAccount), or null. Reads only ( c). */
    internal fun liveValidAccount(): String? = validCurrentAccount()

    /** Whether the phrase-only record verifies (its own phrase derives its own account). Reads only. */
    internal fun phraseOnlyVerifies(): Boolean = phraseOnly() != null

    /**
     * key_only ( c, N2′): every position that may hold a phrase (the fixed phrase file and each isolated copy of it) is read
     * successfully and none holds a valid phrase. A read that fails, or a copy that does not read, is not confirmed: false. Reads only.
     */
    internal fun noValidPhraseConfirmed(): Boolean = try {
        files.names().filter { it == MNEM || it.startsWith("$MNEM.isolated.") }.all { name ->
            val bytes = files.read(name)
            bytes == null || phraseItemOf(bytes) == PhraseItem.Invalid
        }
    } catch (_: Exception) {
        false
    }

    private fun pendingSettled(): Boolean {
        // An unfinished isolation (25.52Y.128 第 3 項): the marker stays until the new record is confirmed, so the state is unknown.
        if (pendingBlocks()) return false
        val raw = files.read(INTENT) ?: return true
        val intent = readIntent(raw) ?: return false
        val commit = files.read(COMMIT) ?: return false
        return readCommit(commit, intent.eoa) != null
    }

    /** Files the write path kept because they could not be attributed to a pending import (25.52Y.125 第 3 项). */
    internal var retainedUnattributed: Int = 0
        private set

    /**
     * Write-path settlement of a pending import (25.52Y.125 第 3 项). Runs only in a write operation, before its state check. A completed
     * import's leftover intent is removed. An unfinished import is rolled back: a manifest file is removed only when it belongs to the
     * intent's account and its audit line was written first. A file that cannot be attributed is kept and counted; the intent then stays,
     * so the state stays unknown. Returns true when nothing is pending afterwards.
     */
    /**
     * Settles a pending write on the write path. A read fault while settling is a refusal: nothing is removed, the marker and the intent stay, and
     * the next write path settles again (hotfix review, P2/P3: no exception reaches the page).
     */
    internal fun settleForWrite(): Boolean = try {
        settleReadFault = false
        settleForWriteOrThrow()
    } catch (_: IOException) {
        settleReadFault = true
        false
    }

    /** Set by [settleForWrite] when its last settle stopped on a read fault. */
    private var settleReadFault = false

    private fun settleForWriteOrThrow(): Boolean {
        if (!reconcileOrphanAudits()) return false
        if (!settlePending()) return false
        val raw = files.read(INTENT) ?: return true
        val intent = readIntent(raw) ?: return false
        val commit = files.read(COMMIT)
        if (commit != null) {
            if (readCommit(commit, intent.eoa) == null) return false
            runCatching { files.delete(INTENT) }
            return true
        }
        // E9.11.16 RF-1 (intent without a marker, e.g. after a rollback whose read failed): a valid current account rolls forward.
        if (rollForwardTarget(intent.eoa)) return rollForwardFinish(intent.eoa, emptyList())
        val manifest = intent.created ?: return false
        val recBytes = files.read(REC)
        val mnemBytes = files.read(MNEM)
        var allGone = true
        for (name in manifest) if (name == MARK || name == REC || name == MNEM) {
            val bytes = files.read(name) ?: continue
            val belongs = when (name) {
                MARK -> recBytes != null && recordOwnedBy(recBytes, intent.eoa) && bytes.contentEquals(markerOf(recBytes, mnemBytes))
                else -> recordOwnedBy(bytes, intent.eoa)
            }
            if (!belongs) {
                retainedUnattributed++
                allGone = false
                continue
            }
            if (!keepAsIsolated(name, bytes, "pending_import_rollback")) return false
        }
        if (!allGone) return false
        // The intent of the aborted import is moved to an isolated name, audited (no erase).
        val abortedIntent = files.read(INTENT) ?: return true
        return keepIntentAsIsolated(abortedIntent, "pending_import_rollback")
    }

    /**
     * A roll-forward needs the intent's `mnemonicPlanned` to match the phrase record on disk (reviewer note on 25.52Y.137). Without an intent nothing is
     * compared; an intent that cannot be read does not allow a roll-forward.
     */
    private fun plannedMatches(): Boolean {
        val raw = files.read(INTENT) ?: return true
        val planned = readIntent(raw)?.mnemonicPlanned ?: return false
        return planned == (files.read(MNEM) != null)
    }

    /** True when [bytes] is a versioned record whose clear `eoa` is [eoa]. Only the content is read; nothing is opened. */
    private fun recordOwnedBy(bytes: ByteArray, eoa: String): Boolean = try {
        val o = JSONObject(String(bytes, Charsets.UTF_8))
        o.optInt("record", 0) == RECORD_VERSION && o.optString("eoa", "") == eoa
    } catch (_: Exception) {
        false
    }

    /**
     * Appends one audit line (25.52Y.128 第 5 项): names, UTC time, reason and the SHA-256 of the old bytes, never the content. False when
     * the line cannot be written; the caller then does not remove or move the file.
     */
    private fun appendAudit(
        name: String,
        reason: String,
        bytes: ByteArray,
        isolated: String? = null,
        confirmedLost: Boolean = false,
        state: String? = null,
    ): Boolean = try {
        val row = JSONObject()
            .put("v", RECORD_VERSION)
            .put("name", name)
            // A pending row names its copy as "isolating", never "isolated": a reader that looks for the done key does not take it for a done row
            // (the downgrade mitigation). Only done rows and state-less rows use "isolated".
            .apply { if (isolated != null) put(if (state == "pending") "isolating" else "isolated", isolated) }
            .apply { if (confirmedLost) put("confirmedLost", true) }
            // r2.5 audit order (spec 3(e)3): "pending" is written before the rename, "done" after the copy is read back. A row without
            // a state is a done row (every row written before this order).
            .apply { if (state != null) put("state", state) }
            .put("reason", reason)
            .put("utc", java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
            .put("sha256", digestHex(bytes))
        // v3.2 §六: the row identifier (auditRef points at it). It is the digest of the row without the identifier.
        val rowId = digestHex(row.toString().toByteArray(Charsets.UTF_8))
        val line = row.put("id", rowId).toString() + "\n"
        val old = files.read(AUDIT) ?: ByteArray(0)
        files.write(AUDIT, old + line.toByteArray(Charsets.UTF_8))
        lastAuditRowId = rowId
        true
    } catch (_: Exception) {
        false
    }

    /**
     * Whether the audit holds a done row for [iso] (a row with no state counts as done). A pending row is only an intent: the rename it
     * announces may not have happened, so recovery never trusts it (r2.5 audit order).
     */
    private fun auditHasDone(audit: String, iso: String): Boolean = audit.lines().any { line ->
        line.contains("\"isolated\":\"$iso\"") && try {
            val o = JSONObject(line)
            o.optString("isolated") == iso && o.optString("state", "done") == "done"
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Before a backfill writes a done row from the current bytes, the bytes must still hold the digest that the pending row recorded before the
     * rename. No pending row: nothing to check against, the backfill proceeds as before. A mismatch refuses the backfill.
     */
    private fun mayBackfill(audit: String, iso: String, bytes: ByteArray): Boolean {
        val recorded = audit.lines().firstNotNullOfOrNull { line ->
            try {
                val o = JSONObject(line)
                if (o.optString("state") == "pending" && o.optString("isolating") == iso) o.optString("sha256") else null
            } catch (_: Exception) {
                null
            }
        } ?: return true
        return recorded == digestHex(bytes)
    }

    /** The identifier of the last audit row this instance wrote (auditRef of isolation.retained). */
    private var lastAuditRowId: String? = null

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
    private var snapshot: Snap? = null

    /** Set by computeState from its own phrase read (under the monitor, in state()). Not a separate read. */
    private var observedNoPhrase: Boolean = false

    /**
     * The state and the key-only flag, published as one object (review: one read, no window between two reads). The flag is decided from the
     * same reads that decided the state, on the reader's thread; nothing here reads the keystore on the caller's thread.
     */
    class Snap internal constructor(val state: State, val keyOnly: Boolean, internal val signature: String? = null)

    /** The snapshot, without the monitor. `null` when it is not known yet. Never blocks. */
    fun snapshotState(): State? = snapshot?.state

    /** The snapshot with its key-only flag, read in one step (31(3)): a caller that needs both reads this once. Never blocks. */
    fun snapshotWithKeyOnly(): Snap? = snapshot

    /**
     * The state for a command that must not wait: the snapshot, after the same discard-intent check [state] makes first (a
     * plain file read), and never the monitor, never the keystore. `null` when the snapshot is not known yet: the caller treats it as unknown
     * (`not_ready`), asks for a refresh and answers at once. [state] would wait for a cold compute holding the monitor for seconds.
     */
    fun stateIfKnown(): State? {
        if (discardIntentPresent()) return State.Locked(DISCARD_PENDING)
        return snapshot?.state
    }

    /**
     * A digest of the records that decide the state and the key-only flag (REC, MARK, MNEM, COMMIT, INTENT: a hash of each file's bytes, `-` when
     * absent): plain file reads and hashing, no Keystore. Null when a file cannot be read. It is an in-memory validity key only: it is never stored,
     * logged or sent, and it contains no ciphertext, only digests.
     */
    internal fun recordSignature(): String? = try {
        listOf(REC, MARK, MNEM, COMMIT, INTENT).joinToString("|") { name -> files.read(name)?.let { digestHex(it) } ?: "-" }
    } catch (_: Exception) {
        null
    }

    /**
     * The snapshot's key-only flag, vouched for: the records still have the signature they had when the snapshot was computed, so the flag is the
     * one a live read would give (barring a change in the keystore itself, the stated blind spot). Null when it cannot be vouched for
     * (no snapshot, no signature, a read failure, or the files changed outside the vault): the snapshot is then dropped and the caller decides
     * ([keyOnlyChecked] reads live). Never blocks, never reads the keystore.
     */
    fun keyOnlyIfVerified(): Boolean? {
        val snap = snapshot ?: return null
        val recorded = snap.signature ?: return null
        val now = recordSignature()
        if (now == null || now != recorded) {
            if (snapshot === snap) snapshot = null
            return null
        }
        return snap.keyOnly
    }

    /** [keyOnlyIfVerified], else the live read ([keyOnlyLive]): the answer is the same as a live read in every case, and costs one only when the files changed. */
    fun keyOnlyChecked(): Boolean = keyOnlyIfVerified() ?: keyOnlyLive()

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
    fun state(): State {
        // The wait for the monitor is measured (log only); the monitor is the same one the @Synchronized methods use.
        val waitStart = System.nanoTime()
        return synchronized(this) { stateLocked((System.nanoTime() - waitStart) / 1_000_000L) }
    }

    private fun stateLocked(lockWaitMs: Long): State {
        // A recorded discard is unknown until the startup hook finishes or drops it (review: reads have no side effect, 25.52Y.125).
        if (discardIntentPresent()) return State.Locked(DISCARD_PENDING)
        // 25.52Y.75: between two invalidation events the snapshot is authoritative. Invalidated by store, forget,
        // lock and the clear path (invalidateSnapshot). External changes (a cleared app, a file changed outside the vault) are a stated risk,
        // caught at the next start and at the key check before signing.
        snapshot?.let { return it.state }
        // The records' signature is taken first, under the monitor, so a later check against it can only fail on a change after this point.
        val signature = recordSignature()
        // 25.52Y.144: no session latch. Each read is decided by the probes of that read (25.52Y.143 第 1 項), never by an earlier read.
        observedNoPhrase = false
        val t0 = DiagTiming.now()
        val perf = VaultPerf.mark()
        val s = computeState()
        VaultPerf.log("vault.computeState", t0, perf, lockWaitMs)
        // 31(3) (r2.5.17): a readable key record with no phrase is not an account. The flag comes from the phrase read of computeState (one MNEM
        // read for both), and the state and the flag are published in one object.
        val keyOnly = s is State.Ready && observedNoPhrase
        snapshot = Snap(s, keyOnly, signature)
        return s
    }

    /**
     * True when the account is a readable key record with no phrase (the startup classification: a private key is not an account). Reads the
     * vault; the snapshot flag and the phrase verdict are both checked.
     */
    fun isKeyOnlyAccount(): Boolean = keyOnlyLive()

    /**
     * The key-only flag read live from the records, not from the snapshot (the snapshot can be stale when the store changes outside the vault).
     * Used where the keystore may be read on that thread; the snapshot flag stays for the answers that must not read the keystore (25.52Y.75).
     */
    @Synchronized
    fun keyOnlyLive(): Boolean {
        // Synchronized with state(): both write the shared observedNoPhrase flag and the snapshot, so one call cannot see another call's flag.
        observedNoPhrase = false
        val s = computeState()
        return s is State.Ready && observedNoPhrase
    }

    /** True when the snapshot is a readable key record with no phrase entry (31(3)): walletStatus answers no_key for it. Reads no keystore. */
    fun snapshotKeyOnly(): Boolean = snapshot?.keyOnly ?: false

    /**
     * Per-account key-only criterion for the identity clear and the unregister (2026-11-22). A device with a key record
     * (REC, MARK, COMMIT or INTENT) is key-only for the account [eoa] unless that account has a valid phrase: the vault phrase at the fixed
     * position names it, or the mnemonic set store's current set names it. No account (null) with a key present is key-only (fail closed).
     * Every read failure returns true (refuse), never a permission. Reads only; writes nothing.
     */
    internal fun keyWithoutPhraseFor(eoa: String?, store: MnemonicSetStore, legacy: PublishedWalletCopy = PublishedWalletCopy.Absent): Boolean {
        // Every key file is read (no short circuit), so a read failure of any of them refuses.
        val vaultKeyPresent = try {
            listOf(REC, MARK, COMMIT, INTENT).map { files.read(it) != null }.any { it }
        } catch (_: Exception) {
            return true
        }
        // published copy (beamio_chat_wallet_v1): a copy that is present counts as a key record; a copy that cannot be read is
        // unknown and refuses (retryable). Absent adds nothing. The copy is only observed here, never written or removed.
        if (legacy == PublishedWalletCopy.Unknown) return true
        val keyPresent = vaultKeyPresent || legacy == PublishedWalletCopy.Present
        if (!keyPresent) return false
        val who = eoa?.lowercase() ?: return true
        val vaultOwner = try {
            files.read(MNEM)?.let { (phraseItemOf(it) as? PhraseItem.Valid)?.eoa?.lowercase() }
        } catch (_: Exception) {
            return true
        }
        if (vaultOwner == who) return false
        return try {
            when (val c = store.current()) {
                is MnemonicSetStore.Current.Found -> c.eoa.lowercase() != who
                MnemonicSetStore.Current.Absent -> true
                is MnemonicSetStore.Current.Unknown -> true
            }
        } catch (_: Exception) {
            true
        }
    }


    /** True only when REC, MARK, COMMIT and INTENT are all read and absent. Any read failure is false (never an absence). Reads only. */
    internal fun keyRecordsAbsent(): Boolean = try {
        listOf(REC, MARK, COMMIT, INTENT).map { files.read(it) == null }.all { it }
    } catch (_: Exception) {
        false
    }

    /** Observation of the published wallet copy (beamio_chat_wallet_v1) for the key-only criterion. Unknown is a read failure: it refuses and can be retried. */
    internal enum class PublishedWalletCopy { Absent, Present, Unknown }

    private fun computeState(): State {
        // 25.52Y.92 第 2 項 (c): an intent present is a write in progress. Reads never remove it (25.52Y.125), so it is read here and judged.
        val intentBefore = files.read(INTENT) != null
        if (!pendingSettled()) {
            // H3: a leftover marker does not hide a valid current account. With no intent, a valid current phrase
            // for the fixed record's own account is Ready; the marker only blocks writes (E9.11-1, single decision: the current phrase).
            return validCurrentAccount()?.let { State.Ready(it) } ?: State.Locked("rollback_pending")
        }
        //  (E9.1-3, E71-06-b): a read failure of REC or MARK does not decide the account. The phrase at the fixed position does.
        val (rec, recFault) = readSafe(REC)
        val (mark, markFault) = readSafe(MARK)
        val mnem = files.read(MNEM)
        if (recFault || markFault) {
            val item = mnem?.let { phraseItemQuiet(it) }
            observedNoPhrase = mnem == null || item == PhraseItem.Invalid
            if (item is PhraseItem.Valid && !intentBefore) return State.Ready(item.eoa)
            // the phrase position read cleanly and is empty, so the record is no account (the key record alone is not one).
            // The pre-read answers the same (absent, then the copies). The REC and MARK bytes are kept.
            if (mnem == null && !intentBefore) return State.NoKey
            // Not decided by the phrase: the read failure surfaces as before (the snapshot stays unknown, nothing is taken as absent).
            throw IOException("REC or MARK unreadable and no valid phrase at the fixed position")
        }
        // One compute opens and derives the phrase record once: the same record, read in the same call, gives the same answer to both
        // questions below. Each open is a Keystore operation and a BIP-39 derivation, the slow part of a cold read on a device with a hardware keystore.
        var phraseItem: PhraseItem? = null
        fun phraseItemOnce(m: ByteArray): PhraseItem = phraseItem ?: phraseItemQuiet(m).also { phraseItem = it }
        // a phrase record with a clear EOA that cannot be decrypted is a read failure: unknown, bytes kept, retryable.
        // A confirmed loss of the wrap key (SO-22A, WK vectors) is not a read failure and keeps its existing answer.
        if (mnem != null && !intentBefore && wrap.presence() != WrapKeyPresence.CONFIRMED_ABSENT &&
            phraseItemOnce(mnem) == PhraseItem.Unreadable && hasCanonicalEoaField(mnem)
        ) return State.Locked("unreadable")
        // The same read that decides the state records whether a phrase record is present (31(3)); state() takes the flag from here.
        // A deterministically invalid phrase at the fixed position is no phrase (2026-11-17: a key without a valid phrase is not an account).
        observedNoPhrase = mnem == null || phraseItemOnce(mnem) == PhraseItem.Invalid
        val commit = files.read(COMMIT)
        if (rec == null) {
            //  (2026-11-16, urgent): no key record and a readable phrase is has (the original account continues by recovery).
            if (mnem != null) {
                // A phrase that cannot be read or opened is unknown (unreadable, retryable), never confirmed none.
                return if (phraseReadable(mnem)) State.Locked(PHRASE_ONLY) else State.Locked("record_missing")
            }
            // 25.52Y.127 第 1 項 (WK-31) and 25.52Y.136 第 4、5 項: a missing record with a marker is unknown. A commit record alone is confirmed none (no_key).
            // WK-31a (E9.10.3): the phrase position read cleanly and is empty, with no intent: no account, the marker bytes are kept.
            if (mark != null) return if (mnem == null && !intentBefore) State.NoKey else State.Locked("record_missing")
            // Every read completed and no phrase or residue is held: confirmed absent (no_key). A read that failed throws before this point
            // and is never taken for absence.
            return State.NoKey
        }
        // 25.52Y.92 第 2 項: the legacy pure-key record is accepted only with a readable key record and no phrase, intent, commit marker or
        // digest. An intent or a digest without the commit marker is a write that did not finish: unreadable, never accepted or repaired here.
        // E9.1-4: a COMMIT moved away by a settled rollback does not decide the account when the phrase at the fixed
        // position is valid and no intent is pending. The account is then the same one the pre-read answers (source order), and the marker check
        // below still applies to REC and MARK.
        val commitMovedButPhraseValid = commit == null && !intentBefore && mnem != null && phraseReadable(mnem)
        if (commit == null && (intentBefore || mark != null) && !commitMovedButPhraseValid) {
            // 25.52Y.127: REC and MARK present; COMMIT, INTENT and MNEM absent; reads and keystore normal: confirmed absent (no_key).
            val residueShape = mark != null && mnem == null && !intentBefore
            if (residueShape && wrap.presence() != WrapKeyPresence.UNKNOWN) {
                return State.NoKey
            }
            return State.Locked(if (mark == null) "marker_missing" else "marker_mismatch")
        }
        val legacy = !intentBefore && commit == null && mark == null && mnem == null
        if (!markerOk(rec, mark, mnem, legacy)) return State.Locked(if (mark == null) "marker_missing" else "marker_mismatch")
        val opened = openRecord(rec)
        if (opened == null) {
            // 25.52Y.122 第 1、2 項: the wrap alias is confirmed absent and no phrase is readable: confirmed absent (no_key). Any other failure is unknown.
            // 25.52Y.138 第 7 項 with 25.52Y.143 第 3 項: an audit flag (the alias was absent before a rolled-back write) confirms the loss, even when the
            // alias now holds the key of the failed write. Only a phrase that opens keeps the account (phrase_only is decided above, not here).
            val lostByFlagNow = flagConfirmsLoss(rec)
            if ((wrap.presence() == WrapKeyPresence.CONFIRMED_ABSENT || lostByFlagNow) && (mnem == null || !phraseReadable(mnem))) {
                return State.NoKey
            }
            return State.Locked("unreadable")
        }
        opened.key.fill(0)
        return State.Ready(opened.eoa)
    }

    /**
     * H3: with no intent and a readable valid current phrase, the account of the fixed record when the record opens to the same EOA; otherwise null.
     * A read fault is null (not decided). Writes nothing.
     */
    private fun validCurrentAccount(): String? {
        return try {
            if (files.read(INTENT) != null) return null
            val mnem = files.read(MNEM) ?: return null
            val eoa = (phraseItemOf(mnem) as? PhraseItem.Valid)?.eoa ?: return null
            val rec = files.read(REC) ?: return null
            if (opensAs(rec) == eoa) eoa else null
        } catch (_: IOException) {
            null
        }
    }

    /** The EOA the fixed record opens to (its key record), or null when it does not open. Opens and wipes its key at once. */
    private fun opensAs(rec: ByteArray): String? = try {
        openRecord(rec)?.let { o -> o.key.fill(0); o.eoa }
    } catch (_: Exception) {
        null
    }

    /** True when the phrase record opens under its own EOA (the envelope's clear `eoa`): a readable phrase, 25.52Y.106 第 1 条. */
    private fun phraseReadable(mnem: ByteArray): Boolean = try {
        val eoa = JSONObject(String(mnem, Charsets.UTF_8)).optString("eoa", "")
        isCanonicalEoa(eoa) && openMnemonic(mnem, eoa) != null
    } catch (_: Exception) {
        false
    }

    /** A read that reports a storage fault as a flag instead of throwing (the fault is then decided by the phrase position, E9.1-3). */
    private fun readSafe(name: String): Pair<ByteArray?, Boolean> = try {
        files.read(name) to false
    } catch (_: IOException) {
        null to true
    }

    /** A fresh copy of the key for a usable record. The caller must zero it after use. */
    @Synchronized
    fun unlock(): ByteArray? {
        if (!pendingSettled()) return null
        val (rec, recFault) = readSafe(REC)
        val (mark, markFault) = readSafe(MARK)
        val mnem = files.read(MNEM)
        if (recFault || markFault) {
            // The same rule as the state: the valid phrase at the fixed position is the key (the derived EOA is checked by phraseItemOf).
            val item = mnem?.let { phraseItemQuiet(it) } as? PhraseItem.Valid ?: return null
            return MnemonicDerivation.deriveKey(item.phrase)
        }
        if (rec == null) return null
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
                // E7-1 / E7-3 N4: the derived EOA must be the account the caller names (the keyID). A mismatch writes nothing.
                val derivedEoa = WalletAddress.fromPrivateKey(derived) ?: return Import.BAD_KEY
                if (!derivedEoa.equals(eoa, ignoreCase = true)) return Import.BAD_KEY
            } finally {
                derived.fill(0)
            }
            return store(eoa, key, source, phrase = bytes)
        } finally {
            bytes.fill(0)
        }
    }

    /** Outcome of [syncPhrase] (r2.4.2 42(1), 43(3)). Only [UPDATED] is a success. Nothing here carries the phrase. */
    enum class SyncOutcome { UPDATED, IDEMPOTENT, BAD_INPUT, NOT_READY, WRITE_FAILED, READBACK_FAILED, ROLLBACK_PENDING, SEALING_FAILED, OLD_COPY_UNVERIFIED }

    /**
     * Native side of the PWA sync (r2.4.2 42(1)): the phrase the PWA sent is the account now. [phrase] must be canonical and derive [key] and [eoa].
     * Same phrase already held: idempotent, nothing written. Otherwise the existing fixed names are isolated (25.52Y.128) and the new record is
     * written, read back and checked (writeNewSlot); a failure restores the old names and reports it. An unknown state (unreadable, locked) is
     * NOT_READY and writes nothing (42(3)). The phrase is never logged or returned.
     */
    fun syncPhrase(eoa: String, key: ByteArray, phrase: String, expectedAccount: () -> String? = { null }): SyncOutcome {
        // Outside the monitor: the check of the input alone. It reads no vault data and writes nothing, so it needs no lock; the comparison with
        // the current record and every write stay inside the lock below.
        if (!isCanonicalEoa(eoa) || key.size != 32) return SyncOutcome.BAD_INPUT
        val derived = MnemonicDerivation.deriveKey(phrase) ?: return SyncOutcome.BAD_INPUT
        try {
            if (!derived.contentEquals(key) || WalletAddress.fromPrivateKey(key) != eoa) return SyncOutcome.BAD_INPUT
        } finally {
            derived.fill(0)
        }
        return syncPhraseLocked(eoa, key, phrase, expectedAccount, System.nanoTime())
    }

    /** The control files whose change means the vault's records changed: a cheap, Keystore-free signature (name, length, content hash). */
    private fun controlSignature(): List<Pair<String, String>> =
        listOf(REC, MNEM, MARK, COMMIT, INTENT, PENDING, RETAINED, AUDIT, DISCARD_INTENT).map { name ->
            name to (try { files.read(name)?.let { "${it.size}:${digestHex(it)}" } ?: "-" } catch (_: Exception) { "?" })
        }

    /**
     * The locked part of [syncPhrase]. The snapshot is dropped only when something may have changed: before and after a write (so the gate answers
     * not_ready while it runs and never reads a stale value after it), or when settling a pending write changed a control file. IDEMPOTENT, BAD_INPUT
     * and NOT_READY answers that wrote nothing leave the snapshot as it is (it stays authoritative), so a repeated pwaWalletSync does not
     * force a cold recompute.
     */
    @Synchronized
    private fun syncPhraseLocked(eoa: String, key: ByteArray, phrase: String, expectedAccount: () -> String?, waitStartNs: Long): SyncOutcome {
        // Log only: how long this call waited for the monitor, and what it spent inside it (counts and milliseconds).
        val lockWaitMs = (System.nanoTime() - waitStartNs) / 1_000_000L
        val t0 = DiagTiming.now()
        val perf = VaultPerf.mark()
        val before = controlSignature()
        var wrote = false
        try {
            if (!settleForWrite()) return SyncOutcome.NOT_READY
            // Settling a pending write may have changed a control file: then the decision below is made on a fresh read, not on the snapshot.
            if (controlSignature() != before) snapshot = null
            val bytes = phrase.toByteArray(Charsets.UTF_8)
            try {
                return when (val st = state()) {
                    is State.NoKey -> {
                        wrote = true
                        mapImport(importMnemonicKey(eoa, key, phrase))
                    }
                    is State.Ready -> {
                        if (st.eoa == eoa && samePhrase(bytes)) return SyncOutcome.IDEMPOTENT
                        if (st.eoa == eoa && mnemonicOf() == MnemonicRead.Unavailable) return SyncOutcome.NOT_READY
                        // account_address.v1 (project rule 2026-11-18): when present it must name the old account. Unknown (a read that fails)
                        // or different: refused before anything moves. Missing is not a reason to refuse.
                        val named = try {
                            expectedAccount()
                        } catch (_: Exception) {
                            return SyncOutcome.OLD_COPY_UNVERIFIED
                        }
                        if (named != null && named != st.eoa) return SyncOutcome.OLD_COPY_UNVERIFIED
                        // The write: the snapshot is dropped before it and again after it (a read inside the write must not leave its own state behind).
                        snapshot = null
                        wrote = true
                        replaceWithIsolation(eoa, key, bytes, st.eoa)
                    }
                    // E5 (2026-11-17): pwaWalletSync with PHRASE_ONLY is write_failed / internal_state: no seal, no rename, no cleanup,
                    // the residue is unchanged. Any other Locked state is unknown too.
                    // An unreadable record (its key record or phrase does not open): the old copy is not verified. Other locks: not_ready.
                    is State.Locked -> if (st.reason == "unreadable" && oldCopyUnverifiable()) SyncOutcome.OLD_COPY_UNVERIFIED else SyncOutcome.NOT_READY
                }
            } finally {
                bytes.fill(0)
            }
        } catch (_: Exception) {
            // An exception after a write began may have changed the records: the snapshot goes (below). Before one, nothing changed.
            return SyncOutcome.NOT_READY
        } finally {
            if (wrote || controlSignature() != before) snapshot = null
            VaultPerf.log("vault.syncPhrase", t0, perf, lockWaitMs)
        }
    }

    /**
     * B1 (review): a readable phrase with no key record (PHRASE_ONLY) is a valid account. The phrase record is opened under its own EOA
     * (the clear `eoa` of its envelope), and the phrase must derive that EOA. Null when it cannot be read or does not derive that EOA.
     */
    @Synchronized
    fun phraseOnly(): Pair<String, String>? {
        val mnem = files.read(MNEM) ?: return null
        val eoa = try {
            JSONObject(String(mnem, Charsets.UTF_8)).optString("eoa", "")
        } catch (_: Exception) {
            return null
        }
        if (!isCanonicalEoa(eoa)) return null
        val phrase = openMnemonic(mnem, eoa) ?: return null
        val key = MnemonicDerivation.deriveKey(phrase) ?: return null
        try {
            if (WalletAddress.fromPrivateKey(key) != eoa) return null
        } finally {
            key.fill(0)
        }
        return eoa to phrase
    }

    /**
     * The native side of the narrow discard (r2.4.9 46(1), 53(7)): `explicit_empty` when the store is read and holds no phrase entry (a
     * key-only record, or no record at all), `valid` when a phrase is held, `unknown` otherwise. Read only.
     */
    @Synchronized
    fun nativeStateLabel(): String = try {
        when (state()) {
            is State.NoKey -> NATIVE_EXPLICIT_EMPTY
            is State.Ready -> if (mnemonicOf() is MnemonicRead.Stored) "valid" else if (mnemonicOf() is MnemonicRead.Missing) NATIVE_EXPLICIT_EMPTY else "unknown"
            // A readable, valid phrase with no key record is valid (PHRASE_ONLY, 25.52Y.106 第 1 条); any other lock is unknown.
            is State.Locked -> when {
                (state() as State.Locked).reason == PHRASE_ONLY && phraseOnly() != null -> "valid"
                mnemonicOf() is MnemonicRead.Missing -> NATIVE_EXPLICIT_EMPTY
                else -> "unknown"
            }
        }
    } catch (_: Exception) {
        "unknown"
    }

    /** The result of a narrow discard (r2.4.9 46, review): dropped, not dropped, or decided and pending (the startup hook finishes it). */
    enum class DiscardOutcome { DROPPED, NOT_DROPPED, PENDING }

    /**
     * Narrow discard (r2.4.9 46(1)-(3)): drops the key-only entry, the one private-key record of this account, and only when the shell's
     * `nativeState` is `explicit_empty` and the PWA side is explicitly empty too. Order (review): the intent is written as `prepared` and read
     * back, then as `pending` and read back; only then the audit line is appended; then the records are removed; then the intent is removed.
     * Any failure before the removal aborts the intent and reports NOT_DROPPED. If the abort itself cannot be written or removed, the answer is
     * PENDING: the decision stays on disk and the startup hook completes it, so nothing is reported as kept when it will be dropped.
     */
    @Synchronized
    fun discardPrivateOnly(pwaExplicitEmpty: Boolean, nativeState: String): DiscardOutcome {
        if (!pwaExplicitEmpty || nativeState != NATIVE_EXPLICIT_EMPTY) return DiscardOutcome.NOT_DROPPED
        // (2026-11-17, from the project's standing constraint: no data cleared, no keystore or wallet store deleted, and E7: the
        // onboarding path deletes no old record): a private-only record is kept. Nothing is removed on this path. The decision of 33(5) is not
        // carried out; the call answers NOT_DROPPED and changes no bytes.
        return DiscardOutcome.NOT_DROPPED
    }

        /**
     * Startup hook (review: no read has a side effect). Called once per process by the vault factory. A `pending` intent is finished: the
     * records are removed and the intent is removed. Any other intent (prepared, aborted, unreadable) is removed without dropping anything.
     */
    @Synchronized
    fun completeDiscardAtStartup() {
        // E9 补正 1 (startup scan): the orphan audit backfill runs at every start. A failed row keeps its entry for the next start (not blocking here).
        reconcileOrphanAudits()
        val raw = try {
            files.read(DISCARD_INTENT)
        } catch (_: Exception) {
            return
        } ?: return
        if (String(raw, Charsets.UTF_8) == INTENT_PENDING) {
            // Review (b): the record is checked again before anything is removed. Only a key-only record (or a record already removed) is
            // dropped. A phrase found now means the decision is abandoned: the intent goes, and an aborted audit line (count 0) is written.
            // A phrase record without the key record (PHRASE_ONLY) is a phrase: the decision is abandoned, not run (mnemonicOf needs REC).
            val check = try {
                val rec = files.read(REC)
                val mnem = files.read(MNEM)
                when {
                    rec == null && mnem == null -> MnemonicRead.Missing
                    rec == null -> MnemonicRead.Stored("", "") // a phrase record with no key record: a phrase is held
                    else -> mnemonicOf()
                }
            } catch (_: Exception) {
                return // unknown: the intent stays, the state stays unknown
            }
            when (check) {
                //  (2026-11-17): a private-only record is never removed; the intent is only cleared below.
                is MnemonicRead.Missing -> Unit
                is MnemonicRead.Stored -> {
                    // The aborted line must be written before the intent goes. If it cannot be, the intent stays and the state stays unknown
                    // (the next start decides again); nothing is removed here.
                    if (!appendAbortedDiscardAudit()) return
                }
                is MnemonicRead.Unavailable -> return
            }
        }
        snapshot = null
        eraseChecked(files, DISCARD_INTENT)
    }

    /**
     * Review (a): a live decision is one that is prepared or pending. An aborted mark is not a decision, and it does not lock the state. A read
     * that throws propagates, as every other state read does: an unreadable intent is unknown to the caller.
     */
    private fun discardIntentPresent(): Boolean {
        val raw = files.read(DISCARD_INTENT) ?: return false
        return String(raw, Charsets.UTF_8) != INTENT_ABORTED
    }

    /** The aborted audit line of a discard that was decided and then not carried out: the same three keys, with count 0 (AU format). */
    private fun appendAbortedDiscardAudit(): Boolean {
        val line = JSONObject()
            .put("entryType", "privatekey")
            .put("count", 0)
            .put("utc", java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
            .toString() + "\n"
        val prior = files.read(DISCARD_AUDIT)?.let { String(it, Charsets.UTF_8) } ?: ""
        return try {
            files.write(DISCARD_AUDIT, (prior + line).toByteArray(Charsets.UTF_8))
            files.read(DISCARD_AUDIT)?.let { String(it, Charsets.UTF_8) }?.endsWith(line) == true
        } catch (_: Exception) {
            false
        }
    }

        /** True when the stored phrase of the usable record equals [bytes]. An unreadable phrase is not equal (the caller decides the state). */
    private fun samePhrase(bytes: ByteArray): Boolean = when (val r = mnemonicOf()) {
        is MnemonicRead.Stored -> r.phrase.toByteArray(Charsets.UTF_8).contentEquals(bytes)
        else -> false
    }

    private fun replaceWithIsolation(eoa: String, key: ByteArray, bytes: ByteArray, oldEoa: String): SyncOutcome {
        val names = listOf(REC, MNEM, MARK, COMMIT).filter { files.read(it) != null }
        return mapImport(writeNewSlot(eoa, key, SOURCE_NATIVE_IMPORT, bytes, names, keepUsable = true, requireOpenable = oldEoa, overwrite = true))
    }

    private fun mapImport(r: Import): SyncOutcome = when (r) {
        Import.OK, Import.OK_CLEANUP_PENDING -> SyncOutcome.UPDATED
        Import.ALREADY_PRESENT -> SyncOutcome.IDEMPOTENT
        Import.READBACK_FAILED -> SyncOutcome.READBACK_FAILED
        Import.SEALING_FAILED -> SyncOutcome.SEALING_FAILED
        Import.ROLLBACK_PENDING -> SyncOutcome.ROLLBACK_PENDING
        Import.WRAP_KEY_MISSING, Import.RECORD_EXISTS -> SyncOutcome.NOT_READY
        Import.OLD_COPY_UNVERIFIED -> SyncOutcome.OLD_COPY_UNVERIFIED
        Import.BAD_KEY, Import.BAD_EOA, Import.ADDRESS_MISMATCH -> SyncOutcome.BAD_INPUT
        Import.STORE_FAILED -> SyncOutcome.WRITE_FAILED
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
        if (!pendingSettled()) return MnemonicRead.Unavailable
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
     * The verdict on the phrase item for the pre-read (E7-3 N1–N4, E7-7 N5). Reads only. [PhraseVerdict.INVALID] is a phrase item that was read
     * and decrypted but is not a valid BIP-39 phrase for this account (checksum, word list, length, or the derived key does not match). A read
     * that fails, a marker that does not verify, or a record that does not open is [PhraseVerdict.UNKNOWN]. A missing phrase item is
     * [PhraseVerdict.MISSING] (only when the key record was read). Nothing is removed.
     */
    /**
     * Key-only for the empty-store pre-read (2026-11-22): true only when the phrase verdict
     * is MISSING AND the key record and the marker were both read without a fault, and the key record exists. A read fault of REC or MARK is never
     * key-only (it is unknown, read_error). Reads only; nothing is written or removed.
     */
    fun keyOnlyPreread(): Boolean {
        if (phraseVerdict() != PhraseVerdict.MISSING) return false
        val (rec, recFault) = readSafe(REC)
        val (mark, markFault) = readSafe(MARK)
        return !recFault && !markFault && rec != null && mark != null
    }

    fun phraseVerdict(): PhraseVerdict {
        if (!pendingSettled()) return if (validCurrentAccount() != null) PhraseVerdict.VALID else PhraseVerdict.UNKNOWN
        val (rec0, recFault) = readSafe(REC)
        val (mark, markFault) = readSafe(MARK)
        val mnem = files.read(MNEM)
        // E9.1-3: a REC or MARK read fault does not decide; a valid phrase at the fixed position is the verdict.
        if (recFault || markFault) {
            if (mnem == null && files.read(INTENT) == null) return PhraseVerdict.MISSING
            return if (mnem?.let { phraseItemQuiet(it) } is PhraseItem.Valid) PhraseVerdict.VALID else PhraseVerdict.UNKNOWN
        }
        // WK-31a: no REC, the phrase position read cleanly and is empty, no intent: no phrase (MISSING), the same as the state (NoKey).
        val rec = rec0 ?: return if (mnem == null && files.read(INTENT) == null && mark != null) PhraseVerdict.MISSING else PhraseVerdict.UNKNOWN
        // WK-04a (E9.10.3): the residue shape of computeState (REC and MARK present, COMMIT, INTENT and MNEM absent, normal keystore) is no phrase,
        // whatever the marker says (a half write and an old marker do not block). The same answer as the state (NoKey).
        if (mnem == null && mark != null && files.read(COMMIT) == null && files.read(INTENT) == null && wrap.presence() != WrapKeyPresence.UNKNOWN) {
            return PhraseVerdict.MISSING
        }
        // H3: a current phrase that is valid for the record's own account is VALID before the marker is compared (the marker does not decide).
        if (mnem != null) {
            val item = phraseItemQuiet(mnem)
            if (item is PhraseItem.Valid && opensAs(rec) == item.eoa) return PhraseVerdict.VALID
        }
        if (!markerOk(rec, mark, mnem, legacyPureKey(mark, mnem))) return PhraseVerdict.UNKNOWN
        val opened = openRecord(rec) ?: return PhraseVerdict.UNKNOWN
        try {
            if (mnem == null) return PhraseVerdict.MISSING
            val phrase = openMnemonic(mnem, opened.eoa) ?: return PhraseVerdict.UNKNOWN
            val derived = MnemonicDerivation.deriveKey(phrase) ?: return PhraseVerdict.INVALID
            try {
                return if (derived.contentEquals(opened.key)) PhraseVerdict.VALID else PhraseVerdict.INVALID
            } finally {
                derived.fill(0)
            }
        } finally {
            opened.key.fill(0)
        }
    }

    enum class PhraseVerdict { VALID, MISSING, INVALID, UNKNOWN }

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
        } catch (_: IOException) {
            // A read fault on the write path is a refusal (write_failed / internal_state): nothing new is written, nothing is removed.
            return Import.STORE_FAILED
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
        // 25.52Y.125: the write path settles a pending import before the state check; reads never do.
        settleForWrite()
        if (settleReadFault) return Import.STORE_FAILED // the pending write could not be settled (read fault): refused, nothing removed
        when (val st = state()) {
            is State.Ready -> return if (st.eoa == eoa) Import.ALREADY_PRESENT else Import.RECORD_EXISTS
            is State.Locked -> return Import.RECORD_EXISTS
            State.NoKey -> Unit
        }
        // 25.52Y.127 第 3 項, 25.52Y.136 第 6 項 and 第 8 項: a no_key state with residues writes the new account into a new slot, whether or not
        // the existing record opens. The isolation (25.52Y.128) is the step that lets the write go on.
        val isolate = try {
            isolationSet()
        } catch (_: Exception) {
            return Import.WRAP_KEY_MISSING // an unreadable listing is unknown, never a write failure (25.52Y.136 第 7 項)
        }
        if (isolate.isNotEmpty()) return writeNewSlot(eoa, key, source, phrase, isolate, confirmedNoKey = true)
        return writeFresh(eoa, key, source, phrase)
    }

    /** The ordinary write: precheck, intent, record, readback, marker, commit. Nothing here touches an isolated name. */
    private fun writeFresh(eoa: String, key: ByteArray, source: String, phrase: ByteArray?, onRecordSealed: ((ByteArray) -> Boolean)? = null): Import {
        // Precheck (r3nw 第 4 项 (i)): none of the four files may exist or be unreadable.
        for (name in listOf(REC, MNEM, MARK, COMMIT, INTENT)) {
            val present = try {
                files.read(name) != null
            } catch (e: Exception) {
                true
            }
            if (present) return Import.RECORD_EXISTS
        }
        // The seal of the intent runs before any write. A seal that cannot run is not_ready (25.52Y.136 第 7 項), never a write failure.
        val intentBytes = try {
            encodeIntent(eoa, mnemonicPlanned = phrase != null, created = listOfNotNull(MARK, REC, if (phrase != null) MNEM else null, COMMIT))
        } catch (e: Exception) {
            return Import.WRAP_KEY_MISSING
        }
        try {
            files.write(INTENT, intentBytes)
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
        // 25.52Y.137 第 1 項 (iv): the new record's hash is filled into the pending marker after the record is written, before the readback.
        if (onRecordSealed != null && !onRecordSealed(rec)) return rollbackAndReport(Import.STORE_FAILED, mnemonicPlanned = phrase != null)
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

    /** One file of a pending write-back: its original name, the isolated name, and the SHA-256 of the old bytes (25.52Y.136 第 1 項). */
    private class PendingItem(val name: String, val isolated: String, val oldSha: String)

    /**
     * The pending marker (25.52Y.136 第 1 項): written before the first isolation; [newRecordSha] is set once the new record is sealed.
     * [preWriteAliasAbsent] (25.52Y.138 第 7 項) records that the wrap alias was confirmed absent before the write: the alias was then the
     * precondition for a new key, so an old record that does not open under it is a confirmed loss (25.52Y.122), not unknown.
     */
    private class PendingMark(
        val eoa: String,
        val items: List<PendingItem>,
        val newRecordSha: String?,
        val preWriteAliasAbsent: Boolean = false,
        /**
         *  (i), additive field `overwrite` (written only when true; absent means false). A marker written by an overwrite
         * (writeNewSlot) carries it; a first write, an import residue and a keep entry do not. Only an overwrite marker that lists an isolated
         * REC or MNEM copy is an unsettled overwrite for the pre-read (overwriteIntentUnsettled).
         */
        val overwrite: Boolean = false,
    )

    /**
     * The names a new account isolates (25.52Y.128, 25.52Y.136 第 8 項): the fixed-name residues of the wallet; under a confirmed loss (the wrap alias
     * is confirmed absent) also every other sealed record of the vault, such as the PGP and K records.
     */
    private fun isolationSet(): List<String> {
        val fixed = listOf(REC, MNEM, MARK, COMMIT).filter { files.read(it) != null }
        if (wrap.presence() != WrapKeyPresence.CONFIRMED_ABSENT) return fixed
        return fixed + files.names().filter { isSealedRecordName(it) && it !in fixed && it != INTENT }.sorted()
    }

    private fun parsePending(raw: ByteArray): PendingMark {
        val o = JSONObject(String(raw, Charsets.UTF_8))
        if (o.optInt("v", 0) != RECORD_VERSION) throw IllegalStateException("pending marker version")
        val arr = o.getJSONArray("items")
        val items = (0 until arr.length()).map { i ->
            val e = arr.getJSONObject(i)
            PendingItem(e.getString("name"), e.getString("isolated"), e.getString("oldSha"))
        }
        val newSha = if (o.isNull("newRecordSha")) null else o.getString("newRecordSha")
        return PendingMark(o.getString("eoa"), items, newSha, o.optBoolean("preWriteAliasAbsent", false), o.optBoolean("overwrite", false))
    }

    /** The parsed marker, or null when there is none or it cannot be parsed. Reads only. */
    private fun pendingMarkOrNull(): PendingMark? = try {
        files.read(PENDING)?.let { parsePending(it) }
    } catch (_: Exception) {
        null
    }

    /** Writes the marker: names, isolated names, old hashes, the new record hash when known, the account and the time. No key material. */
    private fun writePendingMark(m: PendingMark): Boolean = try {
        val items = org.json.JSONArray()
        for (item in m.items) items.put(JSONObject().put("name", item.name).put("isolated", item.isolated).put("oldSha", item.oldSha))
        val body = JSONObject()
            .put("v", RECORD_VERSION)
            .put("utc", java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
            .put("eoa", m.eoa)
            .put("items", items)
            .put("newRecordSha", m.newRecordSha ?: JSONObject.NULL)
            .put("preWriteAliasAbsent", m.preWriteAliasAbsent)
            .apply { if (m.overwrite) put("overwrite", true) }
        files.write(PENDING, body.toString().toByteArray(Charsets.UTF_8))
        true
    } catch (_: Exception) {
        false
    }

    /** True when the new record is confirmed on disk: its hash is the marker's, and MARK and COMMIT are present (25.52Y.136 第 9 項). A read that fails is not confirmed. */
    private fun confirmedNew(m: PendingMark): Boolean = try {
        val rec = files.read(REC)
        val sha = m.newRecordSha
        val mark = files.read(MARK)
        rec != null && sha != null && mark != null && digestHex(rec) == sha && mark.contentEquals(markerOf(rec, files.read(MNEM))) && files.read(COMMIT) != null
    } catch (_: Exception) {
        false
    }

    /** The flag entries of the audit (25.52Y.143 第 3 項): (name, oldSha) pairs. A malformed line is not a flag. Reads only; a failed read throws. */
    private fun auditFlags(): List<Pair<String, String>> {
        val raw = files.read(AUDIT) ?: return emptyList()
        return String(raw, Charsets.UTF_8).lines().filter { it.isNotBlank() }.mapNotNull { line ->
            try {
                val o = JSONObject(line)
                if (o.optString("kind", "") == "flag") o.getString("name") to o.getString("oldSha") else null
            } catch (_: Exception) {
                null
            }
        }
    }

    /**
     * 25.52Y.143 第 3 項 (with 25.52Y.138 第 7 項): the loss is confirmed when the audit holds a flag for the fixed record, the flag's old SHA-256 is the
     * SHA-256 of the record now there (a later record does not inherit it), the record does not open, and the wrap is not unknown. A failed read never
     * confirms a loss. Reads only.
     */
    private fun flagConfirmsLoss(rec: ByteArray): Boolean = try {
        if (wrap.presence() == WrapKeyPresence.UNKNOWN) {
            false
        } else {
            val sha = digestHex(rec)
            if (auditFlags().none { it.first == REC && it.second == sha }) {
                false
            } else {
                val opened = openRecord(rec)
                opened?.key?.fill(0)
                opened == null
            }
        }
    } catch (_: Exception) {
        false
    }

    /**
     * Appends the flag for the fixed record before its marker is removed (25.52Y.143 第 3 項): name, old SHA-256 and time, never key material. Written once
     * per old hash. False when the line cannot be written; the caller then keeps the marker.
     */
    private fun appendFlag(oldSha: String): Boolean = try {
        if (auditFlags().none { it.first == REC && it.second == oldSha }) {
            val line = JSONObject()
                .put("v", RECORD_VERSION)
                .put("kind", "flag")
                .put("name", REC)
                .put("oldSha", oldSha)
                .put("utc", java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
                .toString() + "\n"
            val old = files.read(AUDIT) ?: ByteArray(0)
            files.write(AUDIT, old + line.toByteArray(Charsets.UTF_8))
        }
        true
    } catch (_: Exception) {
        false
    }

    /**
     * Whether a pending marker blocks every read (25.52Y.143 第 1 項). A marker that does not confirm a completed write blocks in every instance and process
     * until the next write operation settles it (the state is unknown). A read never removes it. An absent marker does not block; an unreadable marker
     * blocks; a marker whose new record is confirmed (the write returned ok, only its cleanup failed) does not block.
     */
    private fun pendingBlocks(): Boolean {
        val raw = files.read(PENDING) ?: return false
        // E9 启动钩子: a marker that holds only "keep" entries (moves whose audit row is still owed) does not block the state. The write path refuses
        // until the row is backfilled, because settleForWrite runs reconcileOrphanAudits first.
        if (keepOnly(raw)) return false
        val m = try {
            parsePending(raw)
        } catch (_: Exception) {
            return true
        }
        return !confirmedNew(m)
    }

    /**
     * 25.52Y.137 第 2 項 with 25.52Y.138 第 3 項: an isolated file belongs to the account when one of these holds: (a) the K item name carries the
     * account; (b) a PGP record names the account as recipient, carries a key identifier, and the account's K item (`K.v1|<eoa>|default`) carries the
     * same identifier, exactly (an absent, unreadable or identifier-less K item does not establish it; nothing is derived from the record key);
     * (c) its hash is the marker's old hash. A file that meets none is not attributable, and the caller keeps it and counts it.
     */
    internal fun attributable(name: String, bytes: ByteArray, eoa: String, oldSha: String): Boolean {
        if (digestHex(bytes) == oldSha) return true
        if (Regex("^K\\.v1\\|(0x[0-9a-f]{40})\\|[^|]+$").matchEntire(name)?.groupValues?.get(1) == eoa) return true
        val pgp = try {
            JSONObject(String(bytes, Charsets.UTF_8))
        } catch (_: Exception) {
            return false
        }
        if (pgp.isNull("recipientEoa") || pgp.optString("recipientEoa", "").lowercase() != eoa) return false
        if (pgp.isNull("userPgpKeyId")) return false
        val keyId = pgp.optString("userPgpKeyId", "")
        if (keyId.isEmpty()) return false
        val kKeyId = try {
            val k = files.read("K.v1|$eoa|default") ?: return false
            val ko = JSONObject(String(k, Charsets.UTF_8))
            if (ko.isNull("keyId")) "" else ko.optString("keyId", "")
        } catch (_: Exception) {
            return false
        }
        return kKeyId.isNotEmpty() && kKeyId == keyId
    }

    /**
     * Resolves a pending marker in a write operation (25.52Y.136 第 1、2、9 項). A confirmed new record needs only the marker removed. A restored set
     * (every name holds its old bytes, nothing isolated) also needs only the marker removed. Otherwise the new records are rolled back and the isolated
     * files restored, when every isolated file still holds its old bytes and belongs to the account, and MARK equals the digest of REC and MNEM. When
     * MARK was never written, the record alone must be the recorded new record. Any other case is kept and counted. True when nothing blocks afterwards.
     */
    /**
     * A restored group (25.52Y.128 第 3 項, 25.52Y.143 第 2 項): no isolated file is left and every fixed name holds its old bytes, by SHA-256. The
     * record need not open. Reads only; a failed read throws.
     */
    private fun restoredGroup(m: PendingMark): Boolean =
        m.items.all { item -> files.read(item.isolated) == null && files.read(item.name)?.let { digestHex(it) == item.oldSha } == true }

    /**
     * Completes a restored group (25.52Y.143 第 2、3 項): the flag comes first when the alias was absent before the write, then the marker is removed. A
     * group that is not restored, or a flag that cannot be written, keeps the marker (unknown).
     */
    private fun finishRestored(m: PendingMark): Boolean {
        val restored = try {
            restoredGroup(m)
        } catch (_: Exception) {
            false
        }
        if (!restored) return false
        if (m.preWriteAliasAbsent) {
            val rec = try {
                files.read(REC)
            } catch (_: Exception) {
                return false
            }
            if (rec != null && !appendFlag(digestHex(rec))) return false
        }
        return keepMarkerAsIsolated("rollback_marker")
    }

    /**
     * 25.52Y.138 第 6 項: the marker has no new-record hash (the process stopped after the record was written and before the hash, or before the
     * record). (a) The fixed record reads under the wrap and its EOA is the marker's: roll forward (hash filled, audited, then the hashed path completes
     * the marker). (b) Every fixed name is empty and every isolated file holds its old bytes: roll back (restored, audited), then [finishRestored].
     * Otherwise both kinds of file are kept and the state is unknown.
     */
    private fun settleUnhashed(m: PendingMark): Boolean {
        // E9.11.16 RF-1 / RF-2: a valid current account (two identical reads) rolls forward; nothing of it moves, the other entries stay isolated.
        if (rollForwardTarget(m.eoa)) return rollForwardFinish(m.eoa, m.items)
        if (windowShape(m)) return settleWindow(m)
        val restored = try {
            restoredGroup(m)
        } catch (_: Exception) {
            return keepUnhashed(m)
        }
        // A restore that was completed by an earlier launch (its audit row or its intent removal did not happen) still retires the intent.
        if (restored) return retireIntent() && finishRestored(m)
        val rec = try {
            files.read(REC)
        } catch (_: Exception) {
            return keepUnhashed(m)
        }
        if (rec != null) {
            val opened = try {
                openRecord(rec)
            } catch (_: Exception) {
                null
            }
            val sameAccount = opened != null && opened.eoa == m.eoa
            opened?.key?.fill(0)
            if (!sameAccount) return keepUnhashed(m)
            // (a) roll forward: the hash is filled first (25.52Y.137 第 1 項 (iv)), then the audit line, then the hashed path.
            // The phrase is not written yet. When the sealed old copy verifies (opens to the EOA it named), the partial new record is not the
            // account (v3.2 §四之二, SO-25). Otherwise the WK-39 roll-forward rule applies unchanged.
            // D2: the roll-forward rewrite keeps the marker's overwrite flag; a default would drop it.
            if (!writePendingMark(PendingMark(m.eoa, m.items, digestHex(rec), m.preWriteAliasAbsent, overwrite = m.overwrite))) return false
            if (!appendAudit(REC, "roll_forward", rec)) return false
            return settlePending()
        }
        // (b) the fixed names are empty and every isolated file holds its old bytes.
        val rolledBack = try {
            m.items.all { item -> files.read(item.name) == null && files.read(item.isolated)?.let { digestHex(it) == item.oldSha } == true }
        } catch (_: Exception) {
            return keepUnhashed(m)
        }
        if (!rolledBack) return keepUnhashed(m)
        if (!restoreAll(m.items.map { it.name to it.isolated }, reason = "rollback")) return false
        // The intent of the aborted write (written before its record) is audited and removed, as in the window resume.
        if (!retireIntent()) return false
        return finishRestored(m)
    }

    /**
     * The intent of an aborted write is audited (rollback_new_record) and then removed. Nothing is removed when the row cannot be written:
     * the intent stays and the resume returns false (the next launch retries). No intent: nothing to do.
     */
    private fun retireIntent(): Boolean {
        val intent = files.read(INTENT) ?: return true
        return keepIntentAsIsolated(intent, "rollback_new_record")
    }

    /**
     * v3.2 §四之二 (SO-25): REC was written, MNEM was not, and no digest was recorded. The partial new record is renamed to an isolated name
     * (kept, audited); the old record is restored from its sealed copy, read back, and its EOA checked against the one it named before the
     * move. The state returns to "old account in place, retryable". Anything that does not verify is kept and unknown.
     */
    /** The sealed copy of the record opens, and to the EOA it named before the move (the old account is recoverable). Reads only. */
    private fun sealedOldVerifies(m: PendingMark): Boolean {
        val oldCopy = m.items.firstOrNull { it.name == REC }?.let { files.read(it.isolated) } ?: return false
        val oldEoa = recordEoaOf(oldCopy) ?: return false
        return openRecord(oldCopy)?.let { o -> o.key.fill(0); o.eoa == oldEoa } == true
    }

    /**
     * v3.3 window shape (REC written, phrase not written or already restored, no digest recorded): every sealed copy is intact, the old
     * record's copy opens to the EOA it named, some fixed name is partly restored (or holds the partial new record), and no fixed name holds
     * anything else. Reads only; a shape that does not match is not the window (the WK rules apply).
     */
    private fun windowShape(m: PendingMark): Boolean = try {
        windowShapeChecked(m)
    } catch (_: Exception) {
        false
    }

    private fun windowShapeChecked(m: PendingMark): Boolean {
        if (m.newRecordSha != null || m.items.isEmpty() || !sealedOldVerifies(m)) return false
        // Every entry is either still in its fixed name with the old bytes, or has its sealed copy intact (E2 附加 A1).
        val intact = m.items.all { item ->
            files.read(item.name)?.let { digestHex(it) == item.oldSha } == true ||
                files.read(item.isolated)?.let { digestHex(it) == item.oldSha } == true
        }
        if (!intact) return false
        var anyOld = false
        var partialNew = false
        for (item in m.items) {
            val cur = files.read(item.name)
            when {
                cur == null -> Unit
                digestHex(cur) == item.oldSha -> anyOld = true
                item.name == REC && (openRecord(cur)?.let { o -> o.key.fill(0); o.eoa == m.eoa } == true) -> partialNew = true
                // The new phrase is on disk: the write got that far, so this is the roll-forward shape (SO-09), not the window.
                item.name == MNEM && (openMnemonic(cur, m.eoa) != null) -> return false
                // Any other content under a fixed name is kept (isolated) by the resume before the sealed copy is restored (E2 附加 A1, A2).
                else -> Unit
            }
        }
        return anyOld || partialNew
    }

    /**
     * v3.3 window (SO-25, SO-25b, SO-25c): the partial new record is renamed to an isolated name (kept, audited after the rename); then every
     * sealed entry (REC, MNEM, MARK, COMMIT) is restored by its digest from its sealed copy, copied back under its fixed name and read back
     * entry by entry. All ok → the intent marker is cleared and the old account is in place (no isolation.retained: nothing was overwritten).
     * Any failure → every file is kept, nothing is deleted, the marker stays (rollback_pending). The automatic resume runs at most once per
     * launch and records only the failure code; a user retry through [retryPendingByUser] runs it again. Re-entrant: an interruption leaves
     * a shape that the next launch resumes from the start with the same result.
     */
    private fun settleWindow(m: PendingMark): Boolean {
        if (!windowUserRetry && !windowAutoUsed.compareAndSet(false, true)) return false
        val oldRecCopy = m.items.firstOrNull { it.name == REC }?.let { files.read(it.isolated) } ?: return false
        val oldEoa = recordEoaOf(oldRecCopy) ?: return false
        for (item in m.items) {
            val cur = files.read(item.name)
            if (cur != null && digestHex(cur) == item.oldSha) continue // already the old bytes: nothing to restore
            val iso = files.read(item.isolated) ?: return windowFailed(item.name)
            // Whatever sits under the fixed name is kept first (renamed, audited). A failed rename overwrites nothing (E2 附加 A2); a rename that
            // succeeds whose audit row cannot be written stays isolated without its row and is backfilled by the next launch (E2 附加 A3).
            // A failed rename writes no row (E2 附加 A2, SO-25e): the caller stops with nothing written.
            if (cur != null && !preserveFixedContent(item)) return false
            files.write(item.name, iso)
            if (files.read(item.name)?.let { digestHex(it) } != item.oldSha) return windowFailed(item.name)
            if (!appendAudit(item.name, "restored_from_sealed_copy", iso, isolated = item.isolated)) return windowFailed(item.name)
        }
        val back = files.read(REC) ?: return windowFailed(REC)
        if (openRecord(back)?.let { o -> o.key.fill(0); o.eoa == oldEoa } != true) return windowFailed(REC)
        // The aborted write's intent belongs to the partial new record: audited, then removed (the same as the rollback path).
        if (!retireIntent()) return false
        if (m.preWriteAliasAbsent && !appendFlag(digestHex(back))) return false
        return keepMarkerAsIsolated("window_restored_marker")
    }

    /**
     * E9.11.16 RF-1 / RF-3: the roll-forward target. The current phrase at the fixed position is valid for [eoa] on two identical reads, and the
     * fixed record opens to [eoa]. A read fault throws (the settle is refused, nothing moves).
     */
    private fun rollForwardTarget(eoa: String): Boolean {
        val first = files.read(MNEM) ?: return false
        val second = files.read(MNEM) ?: return false
        if (!first.contentEquals(second)) return false
        val a = phraseItemOf(first)
        val b = phraseItemOf(second)
        if (a !is PhraseItem.Valid || b !is PhraseItem.Valid) return false
        if (a.eoa != eoa || b.eoa != eoa) return false
        val rec = files.read(REC) ?: return false
        return openRecord(rec)?.let { o -> o.key.fill(0); o.eoa == eoa } == true
    }

    /**
     * E9.11.16 RF-1 / RF-2 completion: the account's record, phrase and commit are not moved or renamed. The marker is completed (MARK written
     * from them) if absent, the commit is written if absent; the pending marker and the intent are isolated after their audit rows (nothing erased).
     * The other entries of the marker stay isolated and are not restored (counted by their existing rows).
     */
    private fun rollForwardFinish(eoa: String, items: List<PendingItem>): Boolean {
        val rec = files.read(REC) ?: return false
        val mnem = files.read(MNEM)
        val mark = markerOf(rec, mnem)
        val current = files.read(MARK)
        if (current == null) files.write(MARK, mark) else if (!current.contentEquals(mark)) return false
        if (files.read(COMMIT) == null) files.write(COMMIT, encodeCommit(eoa))
        if (files.read(PENDING) != null && !keepMarkerAsIsolated("roll_forward_marker")) return false
        files.read(INTENT)?.let { if (!keepIntentAsIsolated(it, "roll_forward_intent")) return false }
        // v2 §二 step 8 (SO-09): a rolled-forward write keeps the isolated copies and records isolation.retained, as the hashed roll-forward does.
        if (items.isNotEmpty()) {
            val oldEoa = items.firstOrNull { it.name == REC }?.let { files.read(it.isolated) }?.let { recordEoaOf(it) }
            if (!writeRetainedMark(eoa, oldEoa, items)) return false
        }
        return true
    }

    /** Moves the pending marker to an isolated name and audits the move (rollback paths; nothing is erased). Absent marker: nothing to do. */
    private fun keepMarkerAsIsolated(reason: String): Boolean {
        val marker = files.read(PENDING) ?: return true
        val kept = isolatedName(PENDING)
        if (!appendAudit(PENDING, reason, marker, isolated = kept)) return false
        return renameOrFalse(PENDING, kept)
    }

    /** Keeps what is under a fixed name before the sealed copy is restored there: renamed to an isolated name, then audited. */
    private fun preserveFixedContent(item: PendingItem): Boolean {
        val cur = files.read(item.name) ?: return true
        val kept = isolatedName(item.name)
        if (!renameOrFalse(item.name, kept)) return false
        // The rename is not rolled back if the row cannot be written (E2 附加 A3): the caller stops here and the next launch backfills it.
        return appendAudit(item.name, if (item.name == REC) "partial_new_isolated" else "preserved_before_restore", cur, isolated = kept)
    }

    /**
     * E2 附加 A3 (SO-25f): every isolated copy must have an audit row. A copy that has none (its rename succeeded and the row could not be
     * written) gets one now, matched by its digest (idempotent). Returns false when a row cannot be written: the state stays rollback_pending.
     */
    private fun reconcileIsolationAudit(m: PendingMark): Boolean {
        val audit = files.read(AUDIT)?.let { String(it, Charsets.UTF_8) } ?: ""
        // Only the copies the marker does not name (the partial new record and what the resume kept): those are the renames that can lack a row.
        val named = m.items.map { it.isolated }.toSet()
        for (name in files.names()) {
            if (!name.contains(".isolated.") || name in named) continue
            if (auditHasDone(audit, name)) continue
            val bytes = files.read(name) ?: continue
            if (!mayBackfill(audit, name, bytes)) return false
            if (!appendAudit(name.substringBefore(".isolated."), "audit_backfilled", bytes, isolated = name)) return false
        }
        return true
    }

    /** A failed window restore: the failure code is recorded (no content) and everything stays; the next launch resumes from the start. */
    private fun windowFailed(name: String): Boolean {
        appendAudit(name, "window_restore_failed", ByteArray(0))
        return false
    }

    /** User retry through the existing retry entry: the window resume runs again (the once-per-launch limit does not apply). */
    fun retryPendingByUser(): Boolean {
        windowUserRetry = true
        try {
            return settleForWrite()
        } finally {
            windowUserRetry = false
        }
    }

    /**
     * 25.52Y.138 第 6 項 (c): both kinds of file are kept and counted; the state stays unknown. The internal tag is rollback_pending
     * (independent review, 2026-11-17); on the wire it is internal_state (no new word).
     */
    private fun keepUnhashed(m: PendingMark): Boolean {
        retainedUnattributed += m.items.size
        return false
    }

    private fun settlePending(): Boolean {
        val raw = files.read(PENDING) ?: return true
        val m = try {
            parsePending(raw)
        } catch (_: Exception) {
            return false
        }
        if (!reconcileIsolationAudit(m)) return false
        if (confirmedNew(m)) return eraseChecked(files, PENDING)
        if (m.newRecordSha == null) return settleUnhashed(m)
        // Roll forward (25.52Y.136 第 1 項, 前滚): the new record is on disk and reads under the wrap; MARK and COMMIT are completed, then the marker goes.
        val recNow = files.read(REC)
        if (recNow != null && m.newRecordSha != null && digestHex(recNow) == m.newRecordSha && plannedMatches()) {
            val readable = openRecord(recNow)?.let { o -> o.key.fill(0); true } == true
            if (readable) {
                return try {
                    files.write(MARK, markerOf(recNow, files.read(MNEM)))
                    files.write(COMMIT, encodeCommit(m.eoa))
                    runCatching { files.delete(INTENT) }
                    // v2 §二 step 8 (SO-09): a rolled-forward sync keeps the isolated copies and writes isolation.retained, then clears the marker.
                    if (m.items.isNotEmpty()) {
                        val oldEoa = m.items.firstOrNull { it.name == REC }?.let { files.read(it.isolated) }?.let { recordEoaOf(it) }
                        if (!writeRetainedMark(m.eoa, oldEoa, m.items)) return false
                    }
                    eraseChecked(files, PENDING)
                } catch (_: Exception) {
                    false
                }
            }
        }
        // 25.52Y.143 第 2、3 項: a restored group (by hash) is completed with its flag, then its marker is removed.
        if (restoredGroup(m)) return finishRestored(m)
        val isolatedOk = m.items.all { item ->
            val iso = files.read(item.isolated) ?: return@all false
            digestHex(iso) == item.oldSha && attributable(item.name, iso, m.eoa, item.oldSha)
        }
        // 25.52Y.137 B2: interrupted after the isolation and before the record was written: every fixed name is empty and every isolated file holds
        // its old bytes. The isolated files go back under their names, and the marker is removed.
        if (isolatedOk && m.items.all { item -> files.read(item.name) == null }) {
            if (!restoreAll(m.items.map { it.name to it.isolated })) return false
            return finishRestored(m)
        }
        val rec = files.read(REC)
        val mnem = files.read(MNEM)
        val mark = files.read(MARK)
        val markOk = rec != null && if (mark != null) {
            mark.contentEquals(markerOf(rec, mnem))
        } else {
            m.newRecordSha != null && digestHex(rec) == m.newRecordSha
        }
        if (!isolatedOk || !markOk) {
            retainedUnattributed += m.items.size
            return false
        }
        // The partial new record under each fixed name is kept (renamed, audited), never erased (no data is removed by the window logic).
        for (name in m.items.map { it.name }) {
            val bytes = files.read(name) ?: continue
            val kept = isolatedName(name)
            if (!renameOrFalse(name, kept)) return false
            if (!appendAudit(name, "rollback_new_record", bytes, isolated = kept)) return false
        }
        files.read(INTENT)?.let { intent -> if (!keepIntentAsIsolated(intent, "rollback_new_record")) return false }
        if (!restoreAll(m.items.map { it.name to it.isolated })) return false
        return finishRestored(m)
    }

    /**
     * 25.52Y.128 with 25.52Y.136: each name is isolated by rename (bytes checked against the old hash, each line audited) after the pending marker is
     * written. The new account is then written into the same fixed names by [writeFresh], and the marker receives the new record's hash once the record
     * is sealed. A failure restores the isolated files when the fixed names are empty; if that fails, the files are kept and the state is unknown.
     */
    private fun writeNewSlot(
        eoa: String,
        key: ByteArray,
        source: String,
        phrase: ByteArray?,
        names: List<String>,
        keepUsable: Boolean = false,
        confirmedNoKey: Boolean = false,
        requireOpenable: String? = null,
        // D1: true only from the overwrite path (replaceWithIsolation). The store path isolates the same names but is not an overwrite.
        overwrite: Boolean = false,
    ): Import {
        // R1 (review): with [keepUsable], a failed write whose old names are restored is confirmed against the bytes read before the write;
        // the marker is then cleared and the account stays as it was. Only an unconfirmed rollback keeps the marker (unknown).
        val before = if (keepUsable) names.associateWith { files.read(it) } else emptyMap()
        val items = names.mapNotNull { name ->
            files.read(name)?.let { bytes -> PendingItem(name, isolatedName(name), digestHex(bytes)) }
        }
        // Before anything moves: which items open under their key now, and the EOA each one names (v3.1 step 5: the old account).
        val pre = items.associateWith { item -> files.read(item.name)?.let { sealedPre(item.name, it) } ?: SealPre(false, null) }
        val openableBefore = pre.mapValues { it.value.openable }
        // The EOA of the old record, read before it moves (kept on the retained marker as oldEoa).
        val oldEoa = items.firstOrNull { it.name == REC }?.let { pre[it]?.eoa }
        // 25.52Y.138 第 7 項: the alias was absent before this write, or a kept marker already carried that fact (the old record stays lost).
        val aliasAbsentBefore = (try { wrap.presence() == WrapKeyPresence.CONFIRMED_ABSENT } catch (_: Exception) { false }) ||
            (try { pendingMarkOrNull()?.preWriteAliasAbsent == true } catch (_: Exception) { false })
        // v3.1 §一 (3): an old record that does not open is either confirmed lost (WK rules: the write goes on, the bytes are kept)
        // or unknown (cannot tell whether it is lost: nothing is written, the old data stays, retryable). Nothing has moved yet.
        val unopenable = items.filter { openableBefore[it] != true }
        // The store path reaches here only in State.NoKey (the state machine's confirmed no-key verdict, WK-21/22/32/34/39/45): that verdict
        // is the confirmed loss for the store path. The sync path needs the three conditions of v3.2 §四.
        // r2.5 (verified copies only, fix 1): an overwrite of a native record names the old EOA and needs
        // both the key record and the phrase to open under that EOA. Otherwise nothing moves (NOT_READY, the caller's write_failed).
        val lossConfirmed = if (requireOpenable != null) {
            overwriteVerified(pre, items, requireOpenable) && unopenable.isEmpty()
        } else {
            unopenable.isEmpty() || confirmedNoKey || confirmedLoss(pre, items)
        }
        if (!lossConfirmed) return if (requireOpenable != null) Import.OLD_COPY_UNVERIFIED else Import.WRAP_KEY_MISSING
        val lostNames = if (unopenable.isEmpty()) emptySet() else unopenable.map { it.name }.toSet()
        // v2 step 3: the intent marker (prepared) is written before anything moves. It is not wallet data.
        if (!writePendingMark(PendingMark(eoa, items, null, aliasAbsentBefore, overwrite = overwrite))) return Import.STORE_FAILED
        val moved = ArrayList<Pair<String, String>>()
        val sealCode = if (keepUsable) Import.SEALING_FAILED else Import.STORE_FAILED
        // A seal that does not verify restores what moved (the old bytes at their names, audited) and clears the marker when confirmed.
        fun sealFailed(): Import = failedRestored(moved, before, keepUsable, sealCode)
        // v2 step 4: each file is checked against its old digest, renamed, read back (digest), then audited (the audit row follows a rename that happened).
        for (item in items) {
            val bytes = files.read(item.name) ?: continue
            if (digestHex(bytes) != item.oldSha) return sealFailed()
            // r2.5 audit order (spec 3(e)3): the pending row is written before the rename; a row that cannot be written moves nothing.
            if (!appendAudit(item.name, "isolated_for_new_slot", bytes, isolated = item.isolated, confirmedLost = item.name in lostNames, state = "pending")) return sealFailed()
            if (!renameOrFalse(item.name, item.isolated)) return sealFailed()
            moved += item.name to item.isolated
            val back = try {
                files.read(item.isolated)
            } catch (_: Exception) {
                null
            }
            if (back == null || digestHex(back) != item.oldSha) return sealFailed()
            // The done row follows the read-back: its own row, the pending row is not rewritten. v3.1 SO-22A: a confirmed loss keeps its bytes.
            if (!appendAudit(item.name, "isolated_for_new_slot", bytes, isolated = item.isolated, confirmedLost = item.name in lostNames, state = "done")) return sealFailed()
        }
        // v2 step 5: the old account must still open from each copy that opened before (its own EOA, its own key).
        if (!sealedCopiesStillOpen(pre, items)) return sealFailed()
        val result = writeFresh(eoa, key, source, phrase) { rec ->
            writePendingMark(PendingMark(eoa, items, digestHex(rec), aliasAbsentBefore, overwrite = overwrite))
        }
        if (result == Import.OK) {
            // v2 step 8: the copies and the audit are kept; the retained state is written; only the intent marker is cleared.
            if (items.isNotEmpty() && !writeRetainedMark(eoa, oldEoa, items)) return Import.OK_CLEANUP_PENDING
            return if (eraseChecked(files, PENDING)) Import.OK else Import.OK_CLEANUP_PENDING
        }
        if (!restoreAll(moved)) return Import.ROLLBACK_PENDING
        if (!keepUsable) return result
        if (result != Import.STORE_FAILED && result != Import.READBACK_FAILED) return result
        if (!(confirmedOldState(before) && keepMarkerAsIsolated("rollback_marker"))) return Import.ROLLBACK_PENDING
        return result
    }

    /**
     * Project rule (2026-11-18, Q7 answered: an unverifiable old wallet is not overwritten): every sealed copy that is present must open and name
     * [expectedEoa]. The key record must be present. The phrase may be absent (a key-only account, the key is the wallet) but, when present,
     * it must open and derive the same account. "Absent" means the file does not exist (`items` holds only existing names); a present file that
     * does not open is never treated as absent. Reads nothing new.
     */
    private fun overwriteVerified(pre: Map<PendingItem, SealPre>, items: List<PendingItem>, expectedEoa: String): Boolean {
        val rec = items.firstOrNull { it.name == REC }?.let { pre[it] } ?: return false
        if (!(rec.openable && rec.eoa == expectedEoa)) return false
        val mnemItem = items.firstOrNull { it.name == MNEM } ?: return true
        val mnem = pre[mnemItem] ?: return false
        return mnem.openable && mnem.eoa == expectedEoa
    }

    /** Restores the moved names; with [keepUsable], the old state is confirmed and the marker cleared, else the outcome is unknown. */
    private fun failedRestored(moved: List<Pair<String, String>>, before: Map<String, ByteArray?>, keepUsable: Boolean, code: Import): Import {
        if (!restoreAll(moved)) return Import.ROLLBACK_PENDING
        if (!keepUsable) return code
        return if (confirmedOldState(before) && keepMarkerAsIsolated("rollback_marker")) code else Import.ROLLBACK_PENDING
    }

    /** The EOA a stored record names in its clear envelope (null when it is not a record). */
    private fun recordEoaOf(bytes: ByteArray): String? = try {
        JSONObject(String(bytes, Charsets.UTF_8)).optString("eoa", "").takeIf { isCanonicalEoa(it) }
    } catch (_: Exception) {
        null
    }

    /** Whether a sealed fixed name opens under the wrap key: the record to its key and address, the phrase under its envelope's EOA. */
    private fun sealedOpens(name: String, bytes: ByteArray): Boolean = try {
        when (name) {
            REC -> openRecord(bytes)?.let { it.key.fill(0); true } ?: false
            MNEM -> {
                val eoa = JSONObject(String(bytes, Charsets.UTF_8)).optString("eoa", "")
                isCanonicalEoa(eoa) && openMnemonic(bytes, eoa) != null
            }
            else -> true
        }
    } catch (_: Exception) {
        false
    }

    /**
     * Sealing check: every item that opened before the isolation must still open from its isolated copy. An item that
     * did not open before is a loss the write path already handles (unchanged). Nothing is removed here.
     */
    private fun sealedCopiesStillOpen(pre: Map<PendingItem, SealPre>, items: List<PendingItem>): Boolean = try {
        items.all { item ->
            val p = pre[item]
            if (p == null || !p.openable) return@all true
            val bytes = files.read(item.isolated) ?: return@all false
            // The copy must open, and to the EOA the old record named before the move (step 5: the old account is recoverable).
            sealedOpensAs(item.name, bytes) == p.eoa
        }
    } catch (_: Exception) {
        false
    }

    /**
     * v3.2 §四: a loss is confirmed only when all three hold: the keystore enumeration succeeded and the alias is absent (CONFIRMED_ABSENT),
     * and the native side holds no readable phrase and no readable key. Anything else is unknown (not a loss).
     */
    private fun confirmedLoss(pre: Map<PendingItem, SealPre>, items: List<PendingItem>): Boolean {
        val enumerated = try { wrap.presence() == WrapKeyPresence.CONFIRMED_ABSENT } catch (_: Exception) { false }
        if (!enumerated) return false
        val keyReadable = items.firstOrNull { it.name == REC }?.let { pre[it]?.openable } == true
        val phraseReadable = items.firstOrNull { it.name == MNEM }?.let { pre[it]?.openable } == true
        return !keyReadable && !phraseReadable
    }

    /** What a fixed name held before the move: whether it opened under the wrap key, and the EOA it names. */
    private class SealPre(val openable: Boolean, val eoa: String?)

    /** Opens a fixed name and returns the EOA it names, or null when it does not open. Nothing is written. */
    private fun sealedOpensAs(name: String, bytes: ByteArray): String? = try {
        when (name) {
            REC -> openRecord(bytes)?.let { o -> o.key.fill(0); o.eoa }
            MNEM -> {
                val eoa = JSONObject(String(bytes, Charsets.UTF_8)).optString("eoa", "")
                // r2.5 (fix A): the phrase must derive the envelope's address; an opened phrase of another account is not a copy.
                val phrase = if (isCanonicalEoa(eoa)) openMnemonic(bytes, eoa) else null
                if (phrase != null && phraseDerivesTo(phrase, eoa)) eoa else null
            }
            else -> null
        }
    } catch (_: Exception) {
        null
    }

    /**
     * An old copy that is present and does not open, with the wrap known: the key record or the phrase exists and fails to open.
     * An unknown wrap (an undecided loss, a failed listing) is not an unverifiable copy: that stays not_ready.
     */
    private fun oldCopyUnverifiable(): Boolean = try {
        wrap.presence() != WrapKeyPresence.UNKNOWN && listOf(REC, MNEM).any { name ->
            val bytes = files.read(name)
            bytes != null && sealedOpensAs(name, bytes) == null
        }
    } catch (_: Exception) {
        false
    }

    /** Whether [phrase] derives [eoa] (m/44'/60'/0'/0/0). The derived key is zeroed; the phrase is held only by the caller, in memory. */
    private fun phraseDerivesTo(phrase: String, eoa: String): Boolean {
        val key = MnemonicDerivation.deriveKey(phrase) ?: return false
        return try {
            WalletAddress.fromPrivateKey(key) == eoa
        } finally {
            key.fill(0)
        }
    }

    private fun sealedPre(name: String, bytes: ByteArray): SealPre {
        // Only the record and the phrase are sealed under the wrap key; the marker and the commit are checked by digest alone.
        if (name != REC && name != MNEM) return SealPre(openable = true, eoa = null)
        val eoa = sealedOpensAs(name, bytes)
        return SealPre(openable = eoa != null, eoa = eoa)
    }

    /**
     * Lists the isolated copies kept after a successful write (existing entries are kept too). Written and read back; the copies
     * themselves are never removed by this step.
     */
    private fun writeRetainedMark(newEoa: String, oldEoa: String?, items: List<PendingItem>): Boolean = try {
        // v3.1 §七 (SO-23): only these fields. No mnemonic, key, password or ciphertext is written here.
        val isolatedNames = JSONArray()
        val oldSha = JSONArray()
        files.read(RETAINED)?.let { raw ->
            val prior = JSONObject(String(raw, Charsets.UTF_8))
            prior.optJSONArray("isolatedNames")?.let { a -> for (i in 0 until a.length()) isolatedNames.put(a.getString(i)) }
            prior.optJSONArray("oldSha")?.let { a -> for (i in 0 until a.length()) oldSha.put(a.getString(i)) }
        }
        for (item in items) {
            isolatedNames.put(item.isolated)
            oldSha.put(item.oldSha)
        }
        val auditRef = lastAuditRowId ?: ""
        val bytes = JSONObject()
            .put("oldEoa", oldEoa ?: JSONObject.NULL)
            .put("time", java.time.Instant.now().toString())
            .put("auditRef", auditRef)
            .put("isolatedNames", isolatedNames)
            .put("oldSha", oldSha)
            .toString()
            .toByteArray(Charsets.UTF_8)
        files.write(RETAINED, bytes)
        files.read(RETAINED)?.contentEquals(bytes) == true
    } catch (_: Exception) {
        false
    }

    /** The isolated copies kept after successful writes, as (name, isolated name) pairs. Empty when none is kept. Read only. */
    @Synchronized
    fun isolationRetained(): List<Pair<String, String>> = try {
        val raw = files.read(RETAINED) ?: return emptyList()
        val arr = JSONObject(String(raw, Charsets.UTF_8)).optJSONArray("isolatedNames") ?: return emptyList()
        (0 until arr.length()).map { i ->
            val iso = arr.getString(i)
            iso.substringBefore(".isolated.") to iso
        }
    } catch (_: Exception) {
        emptyList()
    }

    /**
     * The read state for the retained case (v3.1 §二 step 8): "unknown" while the intent (pending) marker stands; "retained" when the
     * retained marker is present and no pending marker is (the completed sync with its old copies kept); else "ok". Read only.
     */
    @Synchronized
    fun readStateLabel(): String = when {
        files.read(PENDING) != null -> "unknown"
        files.read(RETAINED) != null -> "retained"
        else -> "ok"
    }

    /** Independent check after a restored failure: every name holds its pre-write bytes and no new intent is left . */
    private fun confirmedOldState(before: Map<String, ByteArray?>): Boolean = try {
        before.all { (name, bytes) ->
            val now = files.read(name)
            if (bytes == null) now == null else now != null && now.contentEquals(bytes)
        } && files.read(INTENT) == null
    } catch (_: Exception) {
        false
    }

    private fun renameOrFalse(from: String, to: String): Boolean = try {
        files.rename(from, to)
        true
    } catch (_: Exception) {
        false
    }

    /** Restores the moved files in reverse order (25.52Y.128 第 3 項 (d)). Each restore needs an empty fixed name, and is audited. */
    private fun restoreAll(moved: List<Pair<String, String>>, reason: String = "restored_after_failed_write"): Boolean {
        // 25.52Y.137 第 4 項: all or nothing. Every fixed name must be empty and every isolated file present before the first rename. If one restore
        // fails, the ones already restored are isolated again, so the marker describes the state and nothing is reported as complete.
        val ready = moved.all { (name, iso) ->
            try {
                files.read(name) == null && files.read(iso) != null
            } catch (_: Exception) {
                false
            }
        }
        if (!ready) return false
        val done = ArrayList<Pair<String, String>>()
        for ((name, iso) in moved.asReversed()) {
            if (!restoreIsolated(name, iso, reason)) {
                for ((n, i) in done.asReversed()) renameOrFalse(n, i)
                return false
            }
            done += name to iso
        }
        return true
    }

    private fun restoreIsolated(name: String, iso: String, reason: String): Boolean {
        val current = try {
            files.read(name)
        } catch (_: Exception) {
            return false
        }
        if (current != null) return false
        if (!renameOrFalse(iso, name)) return false
        val restored = try {
            files.read(name)
        } catch (_: Exception) {
            null
        }
        if (restored != null) appendAudit(name, reason, restored, isolated = iso)
        return true
    }

    /** A name for an isolated file: the original name, `.isolated.`, the UTC time (ISO 8601 basic) and eight random hex digits (25.52Y.128 第 3 項 (a)). */
    internal fun isolatedName(name: String): String {
        val stamp = java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
            .withZone(java.time.ZoneOffset.UTC)
            .format(java.time.Instant.now())
        val rnd = ByteArray(4).also { java.security.SecureRandom().nextBytes(it) }
        return name + ".isolated." + stamp + "." + ConetChatCryptoUtil.toHex(rnd)
    }

    /**
     * Keeps the bytes under [name] by moving them to an isolated name and writing the audit row for that move (decision: no stored bytes are deleted by
     * the window or rollback paths; standing constraint). A failed move changes nothing; a failed audit row leaves the moved bytes isolated (the row is backfilled).
     */
    private fun keepAsIsolated(name: String, bytes: ByteArray, reason: String): Boolean {
        val kept = isolatedName(name)
        // Marker first (E9 补正 1): the pending marker lists the move before anything moves; it is cleared only after the audit row is written.
        // A record without an EOA in its bytes (MARK) gets no marker entry here; the orphan scan backfills its row (see reconcileOrphanAudits).
        val eoa = eoaHintOf(bytes)
        if (eoa != null && !addPendingEntry(eoa, name, kept, bytes)) return false
        if (!renameOrFalse(name, kept)) return false
        if (!appendAudit(name, reason, bytes, isolated = kept)) return false
        return if (eoa != null) removePendingEntry(kept) else true
    }

    /** The account a stored record names in its own clear fields (REC, the phrase item, the commit), or null (the marker bytes name none). */
    private fun eoaHintOf(bytes: ByteArray): String? = try {
        JSONObject(String(bytes, Charsets.UTF_8)).optString("eoa", "").takeIf { isCanonicalEoa(it) }
    } catch (_: Exception) {
        null
    }

    /** Adds one entry to the pending marker (the others are kept; a marker is created when there is none). False when the marker cannot be written. */
    private fun addPendingEntry(eoa: String, name: String, kept: String, bytes: ByteArray): Boolean = try {
        val o = files.read(PENDING)?.let { JSONObject(String(it, Charsets.UTF_8)) } ?: JSONObject()
            .put("v", RECORD_VERSION)
            .put("utc", nowUtc())
            .put("eoa", eoa)
            .put("newRecordSha", JSONObject.NULL)
            .put("preWriteAliasAbsent", false)
            .put("items", org.json.JSONArray())
        val items = o.optJSONArray("items") ?: org.json.JSONArray().also { o.put("items", it) }
        // kind "keep": a move of a rollback or failure path, not an unfinished write; only the audit backfill of the move is pending.
        items.put(JSONObject().put("name", name).put("isolated", kept).put("oldSha", digestHex(bytes)).put("kind", "keep"))
        files.write(PENDING, o.toString().toByteArray(Charsets.UTF_8))
        true
    } catch (_: Exception) {
        false
    }

    /**
     * True when the marker holds entries, every one is a "keep" entry (a record move whose audit row is owed), and the marker shows no write in progress:
     * no confirmed new-record digest ([newRecordSha] null) and no wrap-alias flag ([preWriteAliasAbsent] false). A fresh-account write that failed after
     * its REC was sealed carries a newRecordSha and a keep entry; it must keep blocking. Reads only.
     */
    private fun keepOnly(raw: ByteArray): Boolean = try {
        val o = JSONObject(String(raw, Charsets.UTF_8))
        val arr = o.optJSONArray("items")
        val writeInProgress = !o.isNull("newRecordSha") || o.optBoolean("preWriteAliasAbsent", false)
        arr != null && arr.length() > 0 && !writeInProgress &&
            (0 until arr.length()).all { arr.getJSONObject(it).optString("kind") == "keep" }
    } catch (_: Exception) {
        false
    }

    /** Removes every "keep" entry (its audit row is written or its copy is gone); the marker goes when no entry is left. */
    private fun removeKeepEntries(): Boolean = try {
        val raw = files.read(PENDING) ?: null
        if (raw == null) true else removeKeepEntriesIn(raw)
    } catch (_: Exception) {
        false
    }

    private fun removeKeepEntriesIn(raw: ByteArray): Boolean {
        val o = JSONObject(String(raw, Charsets.UTF_8))
        val items = o.optJSONArray("items") ?: return true
        val rest = org.json.JSONArray()
        for (i in 0 until items.length()) {
            val e = items.getJSONObject(i)
            if (e.optString("kind") != "keep") rest.put(e)
        }
        // A marker without keep entries (an unfinished write, a confirmed-loss flag) is left as it is.
        if (rest.length() == items.length()) return true
        return if (rest.length() == 0) eraseChecked(files, PENDING) else {
            o.put("items", rest)
            files.write(PENDING, o.toString().toByteArray(Charsets.UTF_8))
            true
        }
    }

    private fun nowUtc(): String = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString()

    /** Removes the marker entry of [kept] after its audit row is written; the marker goes when no entry is left. */
    private fun removePendingEntry(kept: String): Boolean = try {
        val raw = files.read(PENDING) ?: return true
        val o = JSONObject(String(raw, Charsets.UTF_8))
        val items = o.optJSONArray("items") ?: return true
        val kept2 = org.json.JSONArray()
        for (i in 0 until items.length()) {
            val e = items.getJSONObject(i)
            if (e.optString("isolated") != kept) kept2.put(e)
        }
        if (kept2.length() == 0) eraseChecked(files, PENDING) else {
            o.put("items", kept2)
            files.write(PENDING, o.toString().toByteArray(Charsets.UTF_8))
            true
        }
    } catch (_: Exception) {
        false
    }

    /**
     * Orphan audit scan (E9 补正 1): an isolated copy that no pending entry names and that has no audit row gets one (reason audit_backfilled). A
     * failed row leaves the copy and the marker in place; the next settle retries. Runs before every settle.
     */
    internal fun reconcileOrphanAudits(): Boolean = try {
        // The moves that wrote their marker entry first (kind keep): a missing audit row is written, then the entry goes. A failed row keeps
        // the entry (and the marker), so the next settle retries; nothing is moved back and nothing is erased.
        files.read(PENDING)?.let { raw ->
            val o = JSONObject(String(raw, Charsets.UTF_8))
            val arr = o.optJSONArray("items")
            if (arr != null) {
                val audit0 = files.read(AUDIT)?.let { String(it, Charsets.UTF_8) } ?: ""
                for (i in 0 until arr.length()) {
                    val e = arr.getJSONObject(i)
                    if (e.optString("kind") != "keep") continue
                    val iso = e.optString("isolated")
                    val bytes = files.read(iso)
                    if (bytes != null && !auditHasDone(audit0, iso) && !mayBackfill(audit0, iso, bytes)) return false
                    if (bytes != null && !auditHasDone(audit0, iso) &&
                        !appendAudit(e.optString("name").ifEmpty { iso.substringBefore(".isolated.") }, "audit_backfilled", bytes, isolated = iso)) return false
                }
                if (!removeKeepEntries()) return false
            }
        }
        val marked = files.read(PENDING)?.let { raw ->
            val arr = JSONObject(String(raw, Charsets.UTF_8)).optJSONArray("items")
            if (arr == null) emptySet() else (0 until arr.length()).map { arr.getJSONObject(it).optString("isolated") }.toSet()
        } ?: emptySet()
        val audit = files.read(AUDIT)?.let { String(it, Charsets.UTF_8) } ?: ""
        var ok = true
        for (name in files.names()) {
            if (!name.contains(".isolated.") || name in marked || auditHasDone(audit, name)) continue
            val bytes = files.read(name) ?: continue
            if (!mayBackfill(audit, name, bytes) || !appendAudit(name.substringBefore(".isolated."), "audit_backfilled", bytes, isolated = name)) {
                ok = false
                break
            }
        }
        ok
    } catch (_: Exception) {
        false
    }

    /**
     * The rollback of this vault's own new writes (the store path, a failed write): each record it wrote is moved to an isolated name, audited, and the
     * intent goes last. Nothing is erased. Returns false when a move or an audit row cannot be done (the intent stays, the state is unknown).
     */
    internal fun isolateWrittenRecords(mnemonicPlanned: Boolean): Boolean = try {
        val fixed = listOfNotNull(COMMIT, MARK, REC, if (mnemonicPlanned) MNEM else null)
        val allKept = fixed.all { name -> files.read(name)?.let { keepAsIsolated(name, it, "rollback_new_record") } ?: true }
        // The intent of the aborted write is moved to an isolated name and audited too (no erase).
        allKept && (files.read(INTENT)?.let { intent -> keepIntentAsIsolated(intent, "rollback_new_record") } ?: true)
    } catch (_: Exception) {
        false
    }

    /**
     * The intent of an aborted write is moved to an isolated name. The audit row is written first, so a failed audit leaves the intent in place
     * (the next start retries); a failed move after the row leaves the row for the move that did not happen (the next start writes it again).
     */
    private fun keepIntentAsIsolated(intent: ByteArray, reason: String): Boolean {
        val kept = isolatedName(INTENT)
        if (!appendAudit(INTENT, reason, intent, isolated = kept)) return false
        return renameOrFalse(INTENT, kept)
    }

    /**
     * The names the pending marker lists (its items: the fixed name and the isolated name of each entry), for the pre-read (read only). A marker that
     * cannot be parsed names nothing. A failed read of the marker throws.
     */
    internal fun prereadMarkerNames(): Set<String> {
        val raw = files.read(PENDING) ?: return emptySet()
        return try {
            val arr = JSONObject(String(raw, Charsets.UTF_8)).optJSONArray("items") ?: return emptySet()
            (0 until arr.length()).flatMap { i ->
                val e = arr.getJSONObject(i)
                listOf(e.optString("name", ""), e.optString("isolated", "")).filter { it.isNotEmpty() }
            }.toSet()
        } catch (_: Exception) {
            emptySet()
        }
    }

    /** The names of the files the vault holds, for the pre-read (read only). A failed enumeration throws. */
    internal fun storedNames(): List<String> = files.names()

    /** The bytes of one stored file, for the pre-read (read only). A failed read throws. */
    internal fun storedBytes(name: String): ByteArray? = files.read(name)

    /** One phrase item, read for the pre-read: a valid phrase for its own EOA, a phrase that does not verify, or unreadable. Reads only. */
    internal sealed class PhraseItem {
        class Valid(val eoa: String, val phrase: String) : PhraseItem()
        object Invalid : PhraseItem()
        object Unreadable : PhraseItem()
    }

    /** True when the phrase record holds a canonical clear EOA (the envelope names an account). Reads only. */
    private fun hasCanonicalEoaField(mnem: ByteArray): Boolean = try {
        isCanonicalEoa(JSONObject(String(mnem, Charsets.UTF_8)).optString("eoa", ""))
    } catch (_: Exception) {
        false
    }

    /**
     * The phrase item [bytes] (a fixed or isolated mnemonic file): decrypted under its own envelope EOA, the phrase must derive that EOA. Reads only;
     * nothing is written and no key leaves the call.
     */
    /** [phraseItemOf] for the state and verdict readers: a transient failure is Unreadable there, so the state's own rule decides (unknown or the key rule). */
    internal fun phraseItemQuiet(bytes: ByteArray): PhraseItem = try {
        phraseItemOf(bytes)
    } catch (_: IOException) {
        PhraseItem.Unreadable
    }

    /** The phrase item, with a transient failure thrown (the pre-read uses this: unknown, never Absent). Reads only. */
    internal fun phraseItemOf(bytes: ByteArray): PhraseItem {
        val eoa = try {
            JSONObject(String(bytes, Charsets.UTF_8)).optString("eoa", "")
        } catch (_: Exception) {
            return PhraseItem.Unreadable
        }
        if (!isCanonicalEoa(eoa)) return PhraseItem.Unreadable
        // Deterministic failures return Unreadable (a corrupt record); a transient failure throws (unknown). See openMnemonicForItem.
        val phrase = openMnemonicForItem(bytes, eoa) ?: return PhraseItem.Unreadable
        val key = MnemonicDerivation.deriveKey(phrase) ?: return PhraseItem.Invalid
        try {
            return if (WalletAddress.fromPrivateKey(key) == eoa) PhraseItem.Valid(eoa, phrase) else PhraseItem.Invalid
        } finally {
            key.fill(0)
        }
    }

    /** Removes what this import registered, then the intent. Any removal that fails keeps the intent: the next start retries and reports rollback_pending. */
    private fun rollbackAndReport(code: Import, mnemonicPlanned: Boolean): Import {
        // The written records are kept (isolated and audited), never erased; the intent goes last (see isolateWrittenRecords).
        val names = listOfNotNull(COMMIT, MARK, REC, if (mnemonicPlanned) MNEM else null, INTENT)
        // Every removal is confirmed. The intent is removed last and only after the others are gone; a failure keeps it, so the next start
        // retries and the account is rollback_pending (spec 25.52Y.42 第 4 项 (e)).
        val gone = isolateWrittenRecords(mnemonicPlanned) && names.none { files.read(it) != null }
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
        val filesGone = listOf(COMMIT, MARK, REC, MNEM, INTENT, PENDING).map { eraseChecked(files, it) }.all { it }
        val done = filesGone && wrap.deleteKey()
        return done
    }

    /**
     * [created] is the manifest (plan 1): the file names this import creates. Every name in it was absent before the
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
    /**
     * The phrase of a phrase item (transient vs deterministic). Returns null for a deterministic failure: the record is
     * malformed, or the wrap key is present and the record does not authenticate (a corrupt record). Throws for a transient failure: the keystore
     * read fails (the exception propagates from the wrap), or the wrap key is not confirmed present (absent or unknown). Both are unknown.
     */
    private fun openMnemonicForItem(mnem: ByteArray, eoa: String): String? {
        val o = try {
            JSONObject(String(mnem, Charsets.UTF_8))
        } catch (_: Exception) {
            return null
        }
        if (o.optInt("record", 0) != RECORD_VERSION) return null
        if (o.optString("eoa", "") != eoa) return null
        val sealed = ConetChatCryptoUtil.hexToBytes(o.optString("sealed", "")) ?: return null
        if (sealed.size < 13) return null   // a malformed input (the AES-GCM layout needs an IV and a tag): deterministic
        // X5 (review): any failure of the wrap is transient (unknown), except the deterministic authentication failure (null from open).
        val plain = try {
            wrap.open(mnemAad(eoa), sealed)
        } catch (e: IOException) {
            throw e
        } catch (e: Exception) {
            throw IOException("wrap failed: ${e.javaClass.simpleName}", e)
        }
        if (plain == null) {
            if (wrap.presence() != WrapKeyPresence.PRESENT) throw IOException("wrap key not confirmed present: transient")
            return null
        }
        try {
            return String(plain, Charsets.UTF_8)
        } finally {
            plain.fill(0)
        }
    }

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
        /** The automatic window resume runs at most once per launch (v3.3.1); a user retry is the only other trigger. */
        private val windowAutoUsed = java.util.concurrent.atomic.AtomicBoolean(false)
        @Volatile private var windowUserRetry = false

        /** Test hook: a new launch. */
        internal fun resetLaunchForTests() {
            windowAutoUsed.set(false)
        }

        const val REC = "wallet.v1.rec"

        /** The locked reason of a vault with a readable phrase and no key record: the account continues by recovery (25.52Y.106 第 1 条). */
        const val PHRASE_ONLY = "phrase_only"

        /** The encrypted mnemonic waits for the UI to hand over the passcode. A Locked reason, not an unreadable one. */
        const val PASSCODE_REQUIRED = "passcode_not_provided"
        const val MARK = "wallet.v1.ok"
        /** The sealed recovery phrase (spec §25.52Y.42), written only by a phrase import. */
        const val MNEM = "wallet.v1.mnem"
        /** The import intent (spec §25.52Y.42 第 4 项, r3nw). It is not part of the marker digest. */
        const val INTENT = "wallet.v1.intent"
        /** The commit record, written last (spec §25.52Y.42 第 4 项, r3nw). */
        const val COMMIT = "wallet.v1.commit"

        /** Append-only audit of the write path (25.52Y.125 第 3 项, 25.52Y.128 第 5 项). Names, times, reasons and hashes only. */
        const val AUDIT = "wallet.isolation.audit"

        /** Marks an isolation that has not finished (25.52Y.128). Its presence is unknown; it holds names and a time, never key material. */
        const val PENDING = "wallet.isolation.pending"
        /** Isolated copies kept after a successful write: listed here, never removed automatically. */
        const val RETAINED = "wallet.isolation.retained"
        const val RECORD_VERSION = 1
        const val SOURCE_NATIVE_IMPORT = "native_import"

        /** The shell's read answer for the narrow discard (r2.4.5, 46(1)). */
        const val NATIVE_EXPLICIT_EMPTY = "explicit_empty"

        /** The intent of a narrow discard (review): `prepared`, then `pending` once confirmed, or `aborted`. Only `pending` is finished at startup. */
        const val DISCARD_INTENT = "wallet.discard.intent"
        const val INTENT_PREPARED = "prepared"
        const val INTENT_PENDING = "pending"
        const val INTENT_ABORTED = "aborted"

        /** The reason of the Locked state while a discard intent is on disk: unknown until the startup hook decides it. */
        const val DISCARD_PENDING = "discard_pending"

        /** Append-only audit of the narrow discard: one JSON line per discard, `{entryType, count, utc}` only (46(3)). */
        const val DISCARD_AUDIT = "wallet.discard.audit"

        /** The shell's `nativeState` value: the three named values, and any other value as unknown (46(1)). */
        fun nativeStateOf(raw: String?): String = when (raw) {
            "valid", NATIVE_EXPLICIT_EMPTY, "unknown" -> raw
            else -> "unknown"
        }
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
