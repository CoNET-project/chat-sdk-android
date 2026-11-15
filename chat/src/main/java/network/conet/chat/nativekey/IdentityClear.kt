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

    /** Unreadable or damaged counts as not confirmed (PY.10). */
    fun recoveryBackupConfirmed(): Boolean = try {
        files.read(BACKUP_CONFIRMED)?.contentEquals(ONE) == true
    } catch (_: Exception) {
        false
    }

    fun setClearPending(): Boolean = writeChecked(CLEAR_PENDING)

    /** Native-internal only (PY.11): set by the native save-recovery-phrase confirmation or after a successful recovery. */
    fun setRecoveryBackupConfirmed(): Boolean = writeChecked(BACKUP_CONFIRMED)

    /** Step (5): the last reported legacy-store value, `absent` (PY.8 (5), Y.19 第 10 项). It is not the unreadable marker. */
    fun writeLegacyReportAbsent(): Boolean = writeChecked(LEGACY_REPORT, "absent".toByteArray(Charsets.UTF_8))

    fun clearClearPending(): Boolean = eraseChecked(files, CLEAR_PENDING)

    fun clearRecoveryBackupConfirmed(): Boolean = eraseChecked(files, BACKUP_CONFIRMED)

    private fun writeChecked(name: String, value: ByteArray = ONE): Boolean = try {
        files.write(name, value)
        files.read(name)?.contentEquals(value) == true
    } catch (_: Exception) {
        false
    }

    companion object {
        const val CLEAR_PENDING = "clear_pending.v1"
        const val BACKUP_CONFIRMED = "recovery_backup_confirmed.v1"
        const val LEGACY_REPORT = "legacy_report.v1"
        private val ONE = byteArrayOf(1)
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
internal object RecoveryBackupConfirmation {
    fun confirm(context: Context): Boolean = ClearFlagFiles(pageRecordFiles(context)).setRecoveryBackupConfirmed()

    fun isConfirmed(context: Context): Boolean = ClearFlagFiles(pageRecordFiles(context)).recoveryBackupConfirmed()
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
        if (holds && !flags.recoveryBackupConfirmed()) return IdentityClearCode.UNREGISTER_REFUSED
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
        if (holdsWallet() != false) return null
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
