package network.conet.chat.localread

/**
 * migrationState (spec r3a 11.1 M1–M7 and 11.3). The state machine only: it does not touch storage.
 * States: none, running, complete, switched, purged. Nothing goes back to none. Failures stay in running
 * (or return to running) and never delete the old copies.
 */
enum class MigrationState { NONE, RUNNING, COMPLETE, SWITCHED, PURGED }

enum class MigrationEvent {
    /** M1: start (the PWA path). */
    START,
    /** M2: rows imported (idempotent; may repeat). */
    ROWS_IMPORTED,
    /** M3 failed or M4 failed: the state is kept, the old copies are kept. */
    VERIFY_FAILED,
    /** M4: complete written atomically with verifiedDigest. */
    VERIFIED,
    /** M5: reopen and readback of the sample and all pending rows passed. */
    READBACK_OK,
    /** M5 failed: back to running (old copies kept). */
    READBACK_FAILED,
    /** M6: the UI switched to the SDK store (after M5, A-4). */
    SWITCH_UI,
    /** M7: chat plaintext removed from the profile and the cache backup. */
    PURGE,
    /** 11.3 (Android, iOS): no legacy store, the first full sync completes the migration. */
    FIRST_FULL_SYNC,
}

class IllegalMigrationTransition(val from: MigrationState, val event: MigrationEvent) :
    IllegalStateException("migration ${from.name.lowercase()} cannot take ${event.name.lowercase()}")

object MigrationMachine {
    /** Pure transition function. Throws for any transition the spec does not allow. */
    fun next(from: MigrationState, event: MigrationEvent): MigrationState = when (from) {
        MigrationState.NONE -> when (event) {
            MigrationEvent.START -> MigrationState.RUNNING
            MigrationEvent.FIRST_FULL_SYNC -> MigrationState.COMPLETE
            else -> throw IllegalMigrationTransition(from, event)
        }
        MigrationState.RUNNING -> when (event) {
            MigrationEvent.ROWS_IMPORTED, MigrationEvent.VERIFY_FAILED -> MigrationState.RUNNING
            MigrationEvent.VERIFIED -> MigrationState.COMPLETE
            else -> throw IllegalMigrationTransition(from, event)
        }
        MigrationState.COMPLETE -> when (event) {
            MigrationEvent.READBACK_OK -> MigrationState.COMPLETE
            MigrationEvent.READBACK_FAILED -> MigrationState.RUNNING
            MigrationEvent.SWITCH_UI -> MigrationState.SWITCHED
            else -> throw IllegalMigrationTransition(from, event)
        }
        MigrationState.SWITCHED -> when (event) {
            MigrationEvent.PURGE -> MigrationState.PURGED
            else -> throw IllegalMigrationTransition(from, event)
        }
        MigrationState.PURGED -> throw IllegalMigrationTransition(from, event)
    }

    /**
     * M6 requires a passed readback (M5) since the last change: the UI may only switch after it (A-4).
     * [readbackPassed] is the result of the latest readback.
     */
    fun canSwitchUi(state: MigrationState, readbackPassed: Boolean): Boolean =
        state == MigrationState.COMPLETE && readbackPassed

    /** M7 may remove plaintext only after the UI switched (M6). */
    fun canPurge(state: MigrationState): Boolean = state == MigrationState.SWITCHED
}
