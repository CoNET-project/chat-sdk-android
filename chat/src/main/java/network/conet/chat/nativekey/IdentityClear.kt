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

    fun setClearPending(): Boolean = writeChecked(CLEAR_PENDING)

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
}

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
 * The account of a migration record file (`pgp.v1.mig.<40 hex>.<workspace>.{n,m,last}`), as a lower-case `0x` address, or null for any other
 * name. Used by the start-up redo when no account is known (PY.8 第 7 项).
 */
internal fun migrationAccountOfName(name: String): String? {
    val m = Regex("""^pgp\.v1\.mig\.([0-9a-f]{40})\.[A-Za-z0-9_-]+\.(n|m|last)$""").find(name) ?: return null
    return "0x" + m.groupValues[1]
}

/**
 * Deletes one file and checks that it is gone. A delete that reports nothing is confirmed by reading the file back. Any exception
 * or a file still present is a failure.
 */
internal fun eraseChecked(files: VaultFiles, name: String): Boolean {
    runCatching { files.delete(name) }
    return try {
        files.read(name) == null
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
) {
    /** Steps (1a), (1b), (1c) and (2) to (8). Returns the code only. */
    fun clear(): String {
        if (!migrationCheck()) return IdentityClearCode.UNREGISTER_REFUSED
        val holds = holdsWallet() ?: return IdentityClearCode.UNREGISTER_REFUSED
        if (holds && !backupConfirmed()) return IdentityClearCode.UNREGISTER_REFUSED
        if (pgpRecordPresent() && !pgpSourceAvailable()) return IdentityClearCode.UNREGISTER_REFUSED
        if (!flags.setClearPending()) return IdentityClearCode.CLEAR_INCOMPLETE
        return redo()
    }

    /**
     * Start-up redo (PY.8 第 5 项): when `clear_pending` is set and no wallet key is held, finish steps (3) to (7). The refusals were
     * already decided before `clear_pending` was set, so they are not repeated. Returns null when nothing was interrupted.
     */
    fun redoIfInterrupted(): String? {
        if (!flags.clearPending()) return null
        // r3rk: while clear_pending is set and W is held (or unreadable), the redo does not run and the block stays, until clearIdentity
        // completes the clear. A null result is returned only when nothing was interrupted, so it is the only way the block lifts.
        if (holdsWallet() != false) return IdentityClearCode.CLEAR_INCOMPLETE
        return redo()
    }

    /** Steps (3) to (8). Each step is attempted in its own order; a failure stops the pointer steps and keeps the marker. */
    private fun redo(): String {
        val wallet = eraseWallet()
        val inbox = eraseInbox()
        if (!wallet || !inbox) return IdentityClearCode.CLEAR_INCOMPLETE
        if (!reportLegacyAbsent()) return IdentityClearCode.CLEAR_INCOMPLETE
        if (!clearPointer()) return IdentityClearCode.CLEAR_INCOMPLETE
        if (!flags.clearClearPending()) return IdentityClearCode.CLEAR_INCOMPLETE
        return IdentityClearCode.OK
    }
}
