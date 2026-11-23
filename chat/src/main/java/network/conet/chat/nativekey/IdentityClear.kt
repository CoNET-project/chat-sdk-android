package network.conet.chat.nativekey

import android.content.Context
import java.io.File

/**
 * Codes of the identity clear (spec 25.52PY.2, PY.8, PY.9; r3qr). Only the code is returned, never a value.
 */
internal object IdentityClearCode {
    const val OK = "ok"
    const val UNREGISTER_REFUSED = "unregister_refused"
    const val CLEAR_INCOMPLETE = "clear_incomplete"
}

/**
 * Device-level, non-secret flags of the identity clear. They are kept in the no-backup page-record directory next to the account
 * pointer, one byte each, with no key material (PY.8 第 4 项, PY.10).
 *  - `clear_pending.v1`: set before any deletion, cleared as the last step (PY.8 (2) and (7)). Survives a restart.
 *  - `recovery_backup_confirmed.v1`: the user has confirmed the backup of the recovery phrase (PY.10). Only the setting entry
 *    (PY.11, undefined) may set it; until then a wallet that holds W cannot be cleared (fail closed).
 */
internal class ClearFlagFiles(private val files: VaultFiles) {
    /** Unreadable counts as set: an unknown state resumes the clear rather than reporting it finished. */
    fun clearPending(): Boolean = try {
        files.read(CLEAR_PENDING) != null
    } catch (_: Exception) {
        true
    }

    /**
     * Whether the recovery-backup flag of [eoa] is set (PY.10, PY.16, r3rq: per account). Unreadable or damaged counts as not confirmed.
     */
    fun recoveryBackupConfirmed(eoa: String): Boolean = try {
        files.read(backupFlagName(eoa))?.contentEquals(ONE) == true
    } catch (_: Exception) {
        false
    }

    /** Strict read for the orphan sweep (PY.8 第 7 项): set only when readable and present. Unreadable counts as not set, so nothing is swept. */
    fun clearPendingStrict(): Boolean = try {
        files.read(CLEAR_PENDING) != null
    } catch (_: Exception) {
        false
    }

    /**
     * Three-state read of clear_pending (rc2.2-qa): true when the marker is present, false when it is absent, and null when
     * the read fails. A failed read is unknown, never "no pending clear": nothing is written or consumed here, and the next read decides.
     */
    fun clearPendingState(): Boolean? = try {
        files.read(CLEAR_PENDING) != null
    } catch (_: Exception) {
        null
    }

    /**
     * Owner of clear_pending (2026-11-22): the marker records the EOA of the account whose clear started (lower-case), or
     * [NO_ACCOUNT] when the clear started with no account. The marker is written and read back; false when either step fails.
     */
    fun setClearPending(owner: String?): Boolean {
        val value = (owner?.lowercase() ?: NO_ACCOUNT)
        if (value != NO_ACCOUNT && !EOA_RE.matches(value)) return false
        return writeChecked(CLEAR_PENDING, value.toByteArray(Charsets.UTF_8)) && clearPendingOwner() == expectedOwner(value)
    }

    /**
     * The owner of clear_pending, read once. Absent when no marker; Unknown when it cannot be read or holds no owner (a marker written before
     * the owner was recorded, `1`). Unknown never resumes a clear and never deletes anything.
     */
    fun clearPendingOwner(): PendingOwner = try {
        val raw = files.read(CLEAR_PENDING) ?: return PendingOwner.Absent
        val text = String(raw, Charsets.UTF_8).trim()
        when {
            text == NO_ACCOUNT -> PendingOwner.NoAccount
            EOA_RE.matches(text) -> PendingOwner.Owned(text)
            else -> PendingOwner.Unknown
        }
    } catch (_: Exception) {
        PendingOwner.Unknown
    }

    private fun expectedOwner(value: String): PendingOwner =
        if (value == NO_ACCOUNT) PendingOwner.NoAccount else PendingOwner.Owned(value)

    /**
     * The identity_cleared marker (item 3): set when an identity clear completes. It holds no secret. The shipped wallet copy and the
     * other published stores are kept, but after the clear the device never adopts the kept wallet copy automatically (the first-run import refuses).
     * An explicit recovery or import follows the normal rules. Unreadable counts as set (fail closed).
     */
    fun identityCleared(): Boolean = try {
        files.read(IDENTITY_CLEARED) != null
    } catch (_: Exception) {
        true
    }

    /** True only when the identity_cleared marker is read and holds the written content. Unreadable or damaged is false here (never an exemption), unlike [identityCleared]. */
    fun identityClearedStrict(): Boolean = try {
        // A3: the content is checked, not only the file's presence: an empty or damaged file is not "cleared".
        files.read(IDENTITY_CLEARED)?.contentEquals(CLEARED) == true
    } catch (_: Exception) {
        false
    }

    fun setIdentityCleared(): Boolean = writeChecked(IDENTITY_CLEARED, CLEARED)

    /** Native-internal only (PY.11, PY.16): set for [eoa] by the save-recovery-phrase confirmation, or after a successful recovery. */
    fun setRecoveryBackupConfirmed(eoa: String): Boolean = writeChecked(backupFlagName(eoa))

    /** Step (5): the last reported legacy-store value, `absent` (PY.8 (5), Y.19 第 10 项). It is not the unreadable marker. */
    fun writeLegacyReportAbsent(): Boolean = writeLegacyReport("absent")

    /** The last reported legacy-store value (PY.15, r3rn): `found`, `absent` or `unreadable`, as non-secret text. */
    fun writeLegacyReport(value: String): Boolean = writeChecked(LEGACY_REPORT, value.toByteArray(Charsets.UTF_8))

    fun clearClearPending(): Boolean = eraseChecked(files, CLEAR_PENDING)

    fun clearRecoveryBackupConfirmed(eoa: String): Boolean = eraseChecked(files, backupFlagName(eoa))

    private fun writeChecked(name: String, value: ByteArray = ONE): Boolean = try {
        files.write(name, value)
        files.read(name)?.contentEquals(value) == true
    } catch (_: Exception) {
        false
    }

    companion object {
        const val CLEAR_PENDING = "clear_pending.v1"
        const val IDENTITY_CLEARED = "identity_cleared.v1"
        /** The closed `reason` of unregister_refused (interface PROTOCOL-unregister-refused-reason-field): a backup not confirmed. */
        const val REASON_BACKUP_UNCONFIRMED = "backup_unconfirmed"
        /** The closed `reason` of unregister_refused for a key-only account (PY.14 4(c), 2026-11-15 owner). */
        const val REASON_KEY_ONLY = "key_only"
        /** The owner value of a clear_pending that started with no account. */
        const val NO_ACCOUNT = "none"
        private val EOA_RE = Regex("^0x[0-9a-f]{40}$")
        private val CLEARED = "cleared".toByteArray(Charsets.US_ASCII)
        const val LEGACY_REPORT = "legacy_report.v1"
        /** The prefix of the per-account backup flags (r3rq): `recovery_backup_confirmed.<40 hex>.v1`. */
        const val BACKUP_PREFIX = "recovery_backup_confirmed."
        private val ONE = byteArrayOf(1)

        /** The file name of [eoa]'s backup flag. The address is lower-case, without the 0x prefix. */
        fun backupFlagName(eoa: String): String = BACKUP_PREFIX + eoa.lowercase().removePrefix("0x") + ".v1"
    }
}

/** The no-backup directory of page records and the device flags (the same directory as ShellRecord's flagsOf). */
internal fun pageRecordFiles(context: Context): AndroidVaultFiles =
    AndroidVaultFiles(File(context.applicationContext.noBackupFilesDir, "page_record_v1"))

/**
 * The native-internal entry of the recovery-backup flag (PY.11, r3qs). Not a bridge command. The save-recovery-phrase page
 * confirms through [confirm] (a skip never calls it), and a successful recovery calls it too. Until those are wired, a wallet
 * that holds W cannot be cleared (fail closed).
 */
object RecoveryBackupConfirmation {
    private val EOA = Regex("^0x[0-9a-fA-F]{40}$")

    /**
     * Records that the user confirmed the backup of the recovery phrase of [eoa] (PY.11, PY.16, r3rq). Called by the native save-recovery-phrase
     * page on its confirm action (a skip does not call it), and after a successful recovery. True only when the flag is written and read back.
     * A malformed [eoa] is refused. Not a bridge command.
     */
    fun confirmRecoveryBackup(context: Context, eoa: String): Boolean =
        EOA.matches(eoa) && ClearFlagFiles(pageRecordFiles(context)).setRecoveryBackupConfirmed(eoa.lowercase())

    /** True only when the flag of [eoa] is set. Unreadable or damaged counts as not confirmed (PY.10). For the native UI only. */
    fun isRecoveryBackupConfirmed(context: Context, eoa: String): Boolean =
        EOA.matches(eoa) && ClearFlagFiles(pageRecordFiles(context)).recoveryBackupConfirmed(eoa.lowercase())
}

/**
 * The recovery phrase handed to the native save-recovery-phrase view only (PY.14 (d), PY.16, r3rt). It is not serialisable, has no bridge
 * route, and is cleared on [close]. The view must call [close] when it is dismissed or the backup is confirmed. The phrase is never logged.
 */
class BackupPhrase internal constructor(private var chars: CharArray?) : AutoCloseable {
    /** The characters for the view. Null after [close]. Do not copy them out. */
    fun chars(): CharArray? = chars

    override fun close() {
        chars?.fill('\u0000')
        chars = null
    }

    override fun toString(): String = "BackupPhrase(redacted)"
}

/** The native read for the save-recovery-phrase view (PY.16, r3rq, r3rt). Public for the shell's native module; not a bridge command. */
object RecoveryPhraseForBackup {
    /** The only purpose this read answers. Any other value is unavailable. */
    const val PURPOSE = "backup_display"

    /**
     * The recovery phrase of [eoa] for the backup view, or null (unavailable): a key-only account, a record that cannot be read or verified, a
     * different account, or a purpose other than [PURPOSE]. A null result never sets the backup flag.
     */
    fun readMnemonicForBackupDisplay(context: Context, eoa: String, purpose: String): BackupPhrase? =
        readBackupPhrase(eoa, purpose) { NativeWallet.vault(context).mnemonicOf() }
}

/** The purpose check comes first: another purpose never reads the vault. [read] is the vault's read, injected for the tests. */
internal fun readBackupPhrase(eoa: String, purpose: String, read: () -> NativeWalletVault.MnemonicRead): BackupPhrase? {
    if (purpose != RecoveryPhraseForBackup.PURPOSE) return null
    return backupPhraseFrom(read(), eoa)
}

/** Maps the vault's read to the view handle. A phrase is returned only for the account asked for. */
internal fun backupPhraseFrom(read: NativeWalletVault.MnemonicRead, eoa: String): BackupPhrase? {
    val stored = read as? NativeWalletVault.MnemonicRead.Stored ?: return null
    if (!stored.eoa.equals(eoa, ignoreCase = true)) return null
    return BackupPhrase(stored.phrase.toCharArray())
}

/**
 * The start-up report of the legacy store (PY.15, r3rn): found, absent or unreadable. Stored as the last report (legacy_report.v1, non-secret
 * text, no-backup directory). Called by the shell at every start, before the WebView, synchronously. It only writes; it imports nothing.
 */
object LegacyStoreReport {
    const val FOUND = "found"
    const val ABSENT = "absent"
    const val UNREADABLE = "unreadable"

    /** Returns `ok`; `bad_request` for any other value (nothing is saved); `write_failed` when the local write cannot be read back. */
    fun reportLegacyStore(context: Context, value: String): String = reportLegacyValue(ClearFlagFiles(pageRecordFiles(context)), value)

    /**
     * The only reader of the legacy report (E9.11.33 r2-amend6, G-LR-3). Returns one of five states; any other stored value is READ_FAILED. Read
     * only: no write, no delete, no change. Used by the shellRecordRead legacy answers, the native pre-read's absent decision, and the create guard.
     */
    internal fun readReport(context: Context): LegacyReportState = readReportIn(pageRecordFiles(context))

    /** The same reader over an explicit file set (tests count the reads at this layer). Never throws. */
    internal fun readReportIn(files: VaultFiles): LegacyReportState = try {
        mapLegacyReport(files.read(ClearFlagFiles.LEGACY_REPORT)?.toString(Charsets.UTF_8))
    } catch (_: Exception) {
        LegacyReportState.READ_FAILED
    }
}

/** The five states of the legacy report (E9.11.33 r2-amend6): the value the shell reported, or what the read found. */
internal enum class LegacyReportState { ABSENT, FOUND, UNREADABLE, NOT_REPORTED, READ_FAILED }

/** Whitelist mapping of a stored report: absent and the three reported values; nothing else is a usable report (READ_FAILED). */
internal fun mapLegacyReport(raw: String?): LegacyReportState = when (raw) {
    null -> LegacyReportState.NOT_REPORTED
    LegacyStoreReport.ABSENT -> LegacyReportState.ABSENT
    LegacyStoreReport.FOUND -> LegacyReportState.FOUND
    LegacyStoreReport.UNREADABLE -> LegacyReportState.UNREADABLE
    else -> LegacyReportState.READ_FAILED
}

/**
 * With no account known, every account's backup flag is removed once the wallet is erased: a later restore of the same
 * account must not find a stale "backed up" flag. Returns false when a removal failed.
 */
internal fun eraseBackupFlagsOfUnknownAccount(names: List<String>, erase: (String) -> Boolean): Boolean =
    names.filter { it.removeSuffix(".tmp").startsWith(ClearFlagFiles.BACKUP_PREFIX) }.map(erase).all { it }

/** The report's rule, testable without a Context: only the three values are saved. */
internal fun reportLegacyValue(flags: ClearFlagFiles, value: String): String {
    if (value != LegacyStoreReport.FOUND && value != LegacyStoreReport.ABSENT && value != LegacyStoreReport.UNREADABLE) return "bad_request"
    return if (flags.writeLegacyReport(value)) "ok" else "write_failed"
}

/**
 * Whether the orphan sweep may be started (PY.8 第 7 项, r3rh): only when an interrupted clear is marked (clear_pending set, strictly read).
 * It must be read before the start-up redo, which clears the marker on success.
 */
internal fun orphanSweepMayRun(flags: ClearFlagFiles): Boolean = flags.clearPendingStrict()

/**
 * The key-only precheck of clearIdentity (PY.14 4(c), with the continuation of an interrupted clear, 2026-11-22; aligned). A key-only
 * account is refused only while clear_pending is not strictly set to present. A present marker lets the command reach the redo path, which runs
 * the full [IdentityClear.clear] again; an unreadable marker (null) refuses, as before. The marker is written only after the refusals of (1a) to
 * (1c) passed for the account whose clear started, so a key-only account with a marker is the account of that interrupted clear.
 */
internal fun keyOnlyClearRefused(keyOnly: Boolean, owner: PendingOwner, currentEoa: String?): Boolean =
    keyOnly && !(owner is PendingOwner.Owned && currentEoa != null && owner.eoa == currentEoa.lowercase())

/**
 * P3 (G0 plan B spec section 4; vectors GB-P3a to GB-P3d item 1): the key-only refusal, except in the one state where the gate already answers
 * no_key and nothing could be deleted. Every condition must hold: no current account; no clear_pending marker; the identity_cleared marker read as
 * set with its content ([identityClearedStrict]); the vault actually has no wallet entity ([vaultNoKey]: the snapshot is NoKey and there is no REC, MARK,
 * COMMIT or INTENT file); and the published copy is readable (not Unknown). A Locked vault, any key record, or an unreadable copy keeps the refusal:
 * a device that was cleared and later restored with a private-key-only account is refused again. With a current account (GB-P3a) the refusal stands.
 */
internal fun keyOnlyClearRefusedAt(
    keyOnly: Boolean,
    owner: PendingOwner,
    currentEoa: String?,
    identityClearedStrict: Boolean,
    vaultNoKey: Boolean = false,
    copy: NativeWalletVault.PublishedWalletCopy = NativeWalletVault.PublishedWalletCopy.Absent,
): Boolean {
    if (currentEoa == null && owner == PendingOwner.Absent && identityClearedStrict && vaultNoKey &&
        copy != NativeWalletVault.PublishedWalletCopy.Unknown
    ) return false
    return keyOnlyClearRefused(keyOnly, owner, currentEoa)
}

/** The decision of the clearIdentity precheck, before any handler or gate answer. */
internal enum class ClearPrecheck {
    /** G0 with an account or unknown marker: clear_incomplete, nothing deleted or written (item 2: ahead of the key-only precheck). */
    INCOMPLETE,
    /** unregister_refused with reason key_only. */
    REFUSED_KEY_ONLY,
    /** Go on to the gate and the handler. */
    PROCEED,
}

/**
 * item 2 (audit A2): the G0 marker rule comes first, then the key-only precheck, so a device that kept the published copy still answers
 * clear_incomplete for G0 + Owned X (or Unknown). Both are non-deleting.
 */
internal fun clearPrecheck(
    g2: Boolean,
    g0: Boolean,
    owner: PendingOwner,
    currentEoa: String?,
    keyOnly: Boolean,
    identityClearedStrict: Boolean,
    vaultNoKey: Boolean,
    copy: NativeWalletVault.PublishedWalletCopy,
): ClearPrecheck = when {
    clearGateStep(g2, g0, owner, currentEoa) == ClearGateStep.INCOMPLETE -> ClearPrecheck.INCOMPLETE
    keyOnlyClearRefusedAt(keyOnly, owner, currentEoa, identityClearedStrict, vaultNoKey, copy) -> ClearPrecheck.REFUSED_KEY_ONLY
    else -> ClearPrecheck.PROCEED
}

/**
 * Whether clearIdentity may resume the interrupted clear recorded in clear_pending (the gate step, 25.26.4c G0-CLR-PENDING and G1-CLR-PENDING).
 * Only the current account equal to the recorded EOA resumes it. With no current account (G0) only a no-account marker resumes; an account marker
 * with no current account does not (no account equals it), and an unknown marker never does.
 */
internal fun clearResumable(owner: PendingOwner, currentEoa: String?): Boolean = when (owner) {
    // only when the current account equals the recorded EOA. With no current account (G0) nothing equals it, so no resume.
    is PendingOwner.Owned -> currentEoa != null && owner.eoa == currentEoa.lowercase()
    PendingOwner.NoAccount -> currentEoa == null
    PendingOwner.Absent, PendingOwner.Unknown -> false
}

/** What the account pointer says, for [redoScopeSafe]: not set, naming an account, or not readable. */
internal sealed class PointerRead {
    object None : PointerRead()
    class At(val eoa: String) : PointerRead()
    object Unreadable : PointerRead()
}

/**
 * G0 plan B (owner item 1): the automatic finish of an interrupted clear (cold start, and the retry at a command's gate) runs only when it
 * is safe: the marker names the recorded account X (Owned X) or no account, and nothing of another account is in the scope of the erase.
 * Returns true (safe), false (another account's entry is in scope, or an entry cannot be attributed) or null (a read failed). Anything but true
 * keeps the marker and deletes and writes nothing; the next start decides again.
 *  - the native PGP records (`pgp.v1.*`, all accounts' files are in the erase): every one must be X's; with a no-account marker none may exist;
 *  - the mnemonic set store's current set: absent, or X's (the set store is kept by the clear; another account's set means another account is live);
 *  - the account pointer: not set, or X (the erase clears it).
 * An unknown marker is never safe.
 */
internal fun redoScopeSafe(owner: PendingOwner, pgpNames: List<String>, setCurrent: MnemonicSetStore.Current, pointer: PointerRead): Boolean? {
    val x = when (owner) {
        is PendingOwner.Owned -> owner.eoa.lowercase()
        PendingOwner.NoAccount -> null
        PendingOwner.Absent, PendingOwner.Unknown -> return false
    }
    for (name in pgpNames) {
        when (val o = CleanupOwners.pgpOwner(name)) {
            is OwnerRead.Known -> if (x == null || !o.accountKey.startsWith("$x:")) return false
            OwnerRead.Unowned -> return false
            OwnerRead.Unreadable -> return null
        }
    }
    when (setCurrent) {
        MnemonicSetStore.Current.Absent -> Unit
        is MnemonicSetStore.Current.Found -> if (x == null || setCurrent.eoa.lowercase() != x) return false
        is MnemonicSetStore.Current.Unknown -> return null
    }
    when (pointer) {
        PointerRead.None -> Unit
        is PointerRead.At -> if (x == null || pointer.eoa.lowercase() != x) return false
        PointerRead.Unreadable -> return null
    }
    return true
}

/** The reads behind [redoScopeSafeReading]; each may throw, which is a failed read. */
internal class RedoScopeReads(
    val pgpNames: () -> List<String>,
    val setCurrent: () -> MnemonicSetStore.Current,
    val pointer: () -> PointerRead,
    /** The chat library (inbox) must be readable before an automatic finish (G0-B vectors GB-04b). The clear never deletes it (B6). Throws when it is not. */
    val chatReadable: () -> Unit,
)

/** [redoScopeSafe] over reads: any exception in any read is null (nothing is deleted). */
internal fun redoScopeSafeReading(owner: PendingOwner, reads: RedoScopeReads): Boolean? = try {
    reads.chatReadable()
    redoScopeSafe(owner, reads.pgpNames(), reads.setCurrent(), reads.pointer())
} catch (_: Exception) {
    null
}

/** What the gate does with a `clearIdentity` before its normal answer (25.26.4c 第 3a 項, G0 plan B). */
internal enum class ClearGateStep {
    /** Reach the handler and resume the interrupted clear (the marker names the current account, or no account). */
    RESUME,
    /** G0 with an account marker or an unknown marker: answer clear_incomplete; nothing is deleted or written. */
    INCOMPLETE,
    /** No special handling: the gate answers as before (G0 no_key, G1 not_ready), or G2 reaches the handler. */
    GATE,
}

/**
 * G0 plan B (owner item 2; vectors GB-01, GB-05b): in G0 a manual clear does not resume an account marker and answers clear_incomplete; an
 * unknown marker answers clear_incomplete too. No marker: the gate answers as before (GB-P3b). [g2] is true when the session is ready (the gate lets the
 * command through); the resume applies to G0 and G1 only. A no-account marker keeps its existing rule (resumes in G0).
 */
internal fun clearGateStep(g2: Boolean, g0: Boolean, owner: PendingOwner, currentEoa: String?): ClearGateStep = when {
    g2 -> ClearGateStep.GATE
    clearResumable(owner, currentEoa) -> ClearGateStep.RESUME
    g0 && (owner is PendingOwner.Owned || owner == PendingOwner.Unknown) -> ClearGateStep.INCOMPLETE
    else -> ClearGateStep.GATE
}

/** The owner of clear_pending (see [ClearFlagFiles.clearPendingOwner]). */
internal sealed class PendingOwner {
    object Absent : PendingOwner()
    object Unknown : PendingOwner()
    object NoAccount : PendingOwner()
    class Owned(val eoa: String) : PendingOwner() {
        override fun equals(other: Any?): Boolean = other is Owned && other.eoa == eoa
        override fun hashCode(): Int = eoa.hashCode()
    }
}

/**
 * The accounts the start-up orphan sweep may remove (25.52Y.85 第 6 条, Y.80 第 3 項). Only the continuation of a
 * user-initiated clear counts: [clearPending] is the strict read taken before the redo. The clear involves [involved], the account of the
 * active pointer read before the redo, and only that account is a candidate. [live] is the account of a live record (a new account): it is
 * never a candidate, and when it is the involved account nothing is removed. No clear, or no involved account, removes nothing.
 * No-account alone is never a reason (the removal reading "no W" is not an allowed deletion).
 */
internal object OrphanSweepRule {
    fun accountsToRemove(clearPending: Boolean, involved: String?, live: String?, accounts: Collection<String>): List<String> {
        if (!clearPending) return emptyList()
        val target = involved?.lowercase()?.takeIf { it.isNotEmpty() } ?: return emptyList()
        if (live != null && live.lowercase() == target) return emptyList()
        return accounts.map { it.lowercase() }.distinct().filter { it == target }
    }
}

/**
 * The account of a migration record file (`pgp.v1.mig.<40 hex>.<workspace>.{n,m,last}`), as a lower-case `0x` address, or null for any other
 * name. Used by the start-up redo when no account is known (PY.8 第 7 项).
 */
internal fun migrationAccountOfName(name: String): String? {
    val m = Regex("""^pgp\.v1\.mig\.([0-9a-f]{40})\.[A-Za-z0-9_-]+\.(n|m|last)$""").find(name) ?: return null
    return "0x" + m.groupValues[1]
}

/**
 * Deletes one file and checks that it is gone. The check is [VaultFiles.exists], not a read: a name that holds something a read does not
 * return (a directory) is still present. Any exception or a name still present is a failure.
 */
internal fun eraseChecked(files: VaultFiles, name: String): Boolean {
    runCatching { files.delete(name) }
    return try {
        !files.exists(name)
    } catch (_: Exception) {
        false
    }
}

/**
 * The erasure of the identity (PY.8, PY.12). The steps are injected, so the order and the failure rule can be tested without the platform.
 *
 *  (1a) the C.3 check for N and M, run by [migrationCheck] (true when it passes). No removal.
 *  (1b) W (the mnemonic record, K, the EOA private-key copy, the page copies) may be deleted only when `recovery_backup_confirmed` is
 *       true. Unreadable storage cannot confirm that no W exists, so it is refused (`unregister_refused`).
 *  (1c) when a native PGP record (`pgp.v1.<account>.*`) exists, a recovery source must exist: L, P readable, or a chain backup
 *       ([pgpSourceAvailable]). Without a record, (1c) passes. Refused as `unregister_refused`.
 *  (2)  set `clear_pending` before any deletion.
 *  (3)  erase the wallet keys, the page copies, the migration records and the native PGP records; L is kept. The recovery-backup flag is
 *       cleared once every W item succeeded (r3qv).
 *  (4)  erase the inbox. (5) report the legacy value absent, after (3) and (4), with no W left.
 *  (6)  clear the account pointer and its address, the last deletion.
 *  (7)  clear `clear_pending`. (8) `ok`, reported by the caller only after this.
 *
 * A failed step in (3) to (6) returns `clear_incomplete`; the pointer and `clear_pending` are kept and [redo] resumes from (3).
 * Every step is idempotent. The native PGP record is erased in (3) only after (1c) (PY.12). L is never erased (I.9).
 * The refusals (1a) to (1c) come before any write, so a refused clear changes no state.
 */
internal class IdentityClear(
    private val flags: ClearFlagFiles,
    /** (1b): true when the recovery-backup flag of the account whose W is held is set (PY.10). No account means not confirmed. */
    private val backupConfirmed: () -> Boolean = { false },
    /** (1a): true when the migration check passes (N and M), false when it refuses. */
    private val migrationCheck: () -> Boolean = { true },
    /** True when a native PGP record exists for the account (or anywhere in the vault). */
    private val pgpRecordPresent: () -> Boolean = { false },
    /** (1c): true when a recovery source exists for the PGP record (L, P readable, or a chain backup). */
    private val pgpSourceAvailable: () -> Boolean = { true },
    /** True when W may exist, false when none does, null when the storage cannot be read. */
    private val holdsWallet: () -> Boolean?,
    private val eraseWallet: () -> Boolean,
    private val eraseInbox: () -> Boolean,
    private val reportLegacyAbsent: () -> Boolean,
    private val clearPointer: () -> Boolean,
    /** Writes the identity_cleared markers (page and store). It is the last step before clear_pending is consumed: a failure keeps the clear pending. */
    private val markCleared: () -> Boolean = { true },
    /** The account the clear is for (lower-case EOA), or null with no account. clear_pending records it. */
    private val currentEoa: String? = null,
    /** Whether the automatic finish is safe for the marker's owner (see [redoScopeSafe]): true runs it; false or null (a read failed) keeps everything. */
    private val redoSafe: (PendingOwner) -> Boolean? = { true },
) {
    /** The closed reason of the last unregister_refused answer: `backup_unconfirmed`, or null when the refusal has no reason of this set. */
    var refusalReason: String? = null
        private set

    /** Steps (1a), (1b), (1c) and (2) to (8). Returns the code only. */
    fun clear(): String {
        refusalReason = null
        if (!migrationCheck()) return IdentityClearCode.UNREGISTER_REFUSED
        val holds = holdsWallet() ?: return IdentityClearCode.UNREGISTER_REFUSED
        if (holds && !backupConfirmed()) {
            refusalReason = ClearFlagFiles.REASON_BACKUP_UNCONFIRMED
            return IdentityClearCode.UNREGISTER_REFUSED
        }
        if (pgpRecordPresent() && !pgpSourceAvailable()) return IdentityClearCode.UNREGISTER_REFUSED
        // a clear_pending that names another account is that account's interrupted clear. It is not overwritten, and this clear
        // writes nothing (the refusals above already ran). An unknown marker blocks the same way.
        val mine = currentEoa?.lowercase()
        when (val existing = flags.clearPendingOwner()) {
            PendingOwner.Absent -> Unit
            is PendingOwner.Owned -> if (existing.eoa != mine) return IdentityClearCode.CLEAR_INCOMPLETE
            PendingOwner.NoAccount -> if (mine != null) return IdentityClearCode.CLEAR_INCOMPLETE
            PendingOwner.Unknown -> return IdentityClearCode.CLEAR_INCOMPLETE
        }
        if (!flags.setClearPending(mine)) return IdentityClearCode.CLEAR_INCOMPLETE
        return redo()
    }

    /**
     * Start-up redo (PY.8 第 5 项): when `clear_pending` is set and no wallet key is held, finish steps (3) to (7). The refusals were
     * already decided before `clear_pending` was set, so they are not repeated. Returns null when nothing was interrupted.
     */
    fun redoIfInterrupted(): String? {
        // Three states: present runs the redo; absent is nothing interrupted (null). An unreadable marker is unknown: no redo,
        // no deletion, no marker written, and the pending state is not consumed. It answers clear_incomplete, which keeps the block until a
        // later read decides (the command gate retries the redo).
        // an unknown marker (unreadable, or with no owner) is never redone and nothing is deleted.
        val owner = flags.clearPendingOwner()
        if (owner == PendingOwner.Unknown) return IdentityClearCode.CLEAR_INCOMPLETE
        if (owner == PendingOwner.Absent) return null
        // r3rk: while clear_pending is set and W is held (or unreadable), the redo does not run and the block stays, until clearIdentity
        // completes the clear. A null result is returned only when nothing was interrupted, so it is the only way the block lifts.
        if (holdsWallet() != false) return IdentityClearCode.CLEAR_INCOMPLETE
        // G0 plan B: the automatic finish needs the recorded account only, with every read successful. Otherwise nothing is deleted or written.
        if (runCatching { redoSafe(owner) }.getOrNull() != true) return IdentityClearCode.CLEAR_INCOMPLETE
        return redo()
    }

    /** Steps (3) to (8). Each step is attempted in its own order; a failure stops the pointer steps and keeps the marker. */
    private fun redo(): String {
        val wallet = eraseWallet()
        val inbox = eraseInbox()
        if (!wallet || !inbox) return IdentityClearCode.CLEAR_INCOMPLETE
        if (!reportLegacyAbsent()) return IdentityClearCode.CLEAR_INCOMPLETE
        if (!clearPointer()) return IdentityClearCode.CLEAR_INCOMPLETE
        // The identity_cleared markers are written before the pending state is consumed; a failure keeps the clear pending and the redo writes them.
        if (!markCleared()) return IdentityClearCode.CLEAR_INCOMPLETE
        if (!flags.clearClearPending()) return IdentityClearCode.CLEAR_INCOMPLETE
        return IdentityClearCode.OK
    }
}
