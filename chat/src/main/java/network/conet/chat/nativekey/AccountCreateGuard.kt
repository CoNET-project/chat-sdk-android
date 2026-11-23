package network.conet.chat.nativekey

import android.content.Context
import java.io.File

/** The state of the native key (the vault): none, readable, or present but unreadable. */
internal enum class KeyState { NONE, READABLE, UNREADABLE }

/**
 * The inputs of the account-create gate. Primitive values only, so the decision is a pure function and can be tested without a device.
 * [legacyReport] is the last value reported by the shell (`found`, `absent`, `unreadable`), or `null` when none could be read.
 */
internal data class CreateGuardInputs(
    val key: KeyState,
    val legacyReport: LegacyReportState,
    val legacyUnreadable: Boolean,
    val pointer: Boolean,
    val pageCopy: Boolean,
    val migrating: Boolean,
    /** The identity_cleared state: a kept wallet copy is reported found, and it does not block a create. */
    val identityCleared: Boolean = false,
    /** What the mnemonic store holds (see [StoreState]). Only an empty store allows a create. */
    val store: StoreState = StoreState.EMPTY,
)

/**
 * The mnemonic store as the create gate sees it: empty (no set, or an identity-cleared store, whose retained sets are not re-adopted), an account
 * (a current set), or unknown (a set file without its `current` pointer, an invalid pointer, or a store that cannot be read: never an empty store).
 */
internal enum class StoreState { EMPTY, ACCOUNT, UNKNOWN }

/**
 * The data-safety gate of account creation (§25.46.5, §25.52W.4, §25.52T.3, §25.52U.6). Creating a new wallet must never
 * overwrite a wallet held elsewhere. A create is allowed only when the legacy store is confirmed empty, no account pointer is set, no native
 * key exists, no page copy exists, and no migration or write is pending.
 *
 * Not atomic: the guard is checked at open and again at confirm, but the write itself follows the check. A change between the last check and
 * the write is not covered by this gate. This residual window is recorded in the SDK receipt (residual risk 2).
 *
 * The refusal is answered on the bridge as the existing `not_available` (§25.46.10) and the page is not opened. The diagnostic codes below
 * are logged inside the SDK only; they never reach the page, and the page-visible state is driven by the read side.
 */
internal object AccountCreateGuard {
    const val MIGRATING = "migrating"
    const val POINTER_SET = "pointer_set"
    const val REPLICA_PRESENT = "replica_present"

    /** Denial code (SDK log only) when a set version is on disk without its pointer, or the store cannot be read: an older version may still be there. */
    const val ORPHAN_VERSION = "orphan_version"

    /** Denial code (SDK log only) when the mnemonic store already names an account: a create must not add a second one beside it. */
    const val STORE_ACCOUNT = "store_account"

    /** Denial code when the inputs cannot be read at all (closed fallback). */
    const val INPUTS_UNREADABLE = "inputs_unreadable"

    /**
     * The gate read with a closed fallback: any exception while reading the inputs is a denial, never a create. Used by the open path.
     */
    fun denialOrClosed(read: () -> CreateGuardInputs): String? = try {
        denial(read())
    } catch (_: Exception) {
        INPUTS_UNREADABLE
    }

    /** Diagnostic code of the refusal, or `null` when a create may proceed. Order: key first, then migration, then the pointer and copies. */
    fun denial(i: CreateGuardInputs): String? = when {
        // PY.19 (1): create mode has no account context, so a key present or unreadable is migrating here. replicaAnswer and
        // needs_native_recovery are told apart only on the normal read path that has an account.
        i.key != KeyState.NONE -> MIGRATING
        i.migrating || i.legacyUnreadable -> MIGRATING
        // After an identity clear the kept wallet copy is found and never migrated: only that found state is allowed.
        i.legacyReport != LegacyReportState.ABSENT && !(i.identityCleared && i.legacyReport == LegacyReportState.FOUND) -> MIGRATING
        i.pointer -> POINTER_SET
        i.pageCopy -> REPLICA_PRESENT
        i.store == StoreState.UNKNOWN -> ORPHAN_VERSION
        i.store == StoreState.ACCOUNT -> STORE_ACCOUNT
        else -> null
    }

    /** A page copy file (§25.52AD.2): `page.v1.<address>.<name>.rec`. Any unreadable directory counts as present (fail closed). */
    private val PAGE_COPY = Regex("^page\\.v1\\..*\\.rec$")

    /** Reads the live inputs from the device. Every read that fails is the closed value (unknown key, pointer and copy present). */
    fun inputsFor(context: Context): CreateGuardInputs {
        val files = pageRecordFiles(context)
        val flags = DeviceFlagFiles(files)
        val key = try {
            when (NativeWallet.vault(context).state()) {
                is NativeWalletVault.State.NoKey -> KeyState.NONE
                is NativeWalletVault.State.Ready -> KeyState.READABLE
                else -> KeyState.UNREADABLE
            }
        } catch (_: Exception) {
            KeyState.UNREADABLE
        }
        // The create guard reads the report only through LegacyStoreReport.readReport (E9.11.33 r2-amend6, G-LR-2, G-LR-3).
        val report = LegacyStoreReport.readReport(context)
        val pageCopy = try {
            files.names().any { PAGE_COPY.matches(it) }
        } catch (_: Exception) {
            true
        }
        // The mnemonic store: a current set (an account) or an unknown store (a set without its pointer, unreadable) blocks a create. A read that
        // throws counts as unknown (fail closed). An identity_cleared store answers Absent (retained sets are not re-adopted), so it does not block.
        val store = try {
            when (MnemonicSetStore(File(context.applicationContext.noBackupFilesDir, MnemonicSetStore.DIRECTORY)).current()) {
                is MnemonicSetStore.Current.Absent -> StoreState.EMPTY
                is MnemonicSetStore.Current.Found -> StoreState.ACCOUNT
                is MnemonicSetStore.Current.Unknown -> StoreState.UNKNOWN
            }
        } catch (_: Exception) {
            StoreState.UNKNOWN
        }
        return CreateGuardInputs(
            store = store,
            identityCleared = ClearFlagFiles(files).identityCleared(),
            key = key,
            legacyReport = report,
            legacyUnreadable = flags.legacyUnreadable(),
            pointer = flags.accountPointer(),
            pageCopy = pageCopy,
            migrating = ShellRecordState.migrationPending.get(),
        )
    }
}
