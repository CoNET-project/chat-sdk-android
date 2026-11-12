package network.conet.chat.passcode

/**
 * One row of `stateMachine.transitions` in `spec/passcode-vectors.v1.json`. `"*"` matches any mode or
 * state. `message` is the UI message key, `result` the outcome of the flow, `specAdded` and `pwaAdded`
 * mark rows that came from the spec and from the PWA review (spec r3b 25.17).
 */
data class PasscodeTransition(
    val mode: String,
    val from: String,
    val event: String,
    val to: String,
    val message: String? = null,
    val result: String? = null,
    val specAdded: Boolean = false,
    val pwaAdded: Boolean = false,
)

object PasscodeStateMachine {
    val MODES = listOf("enable", "change", "disable", "unlock")
    val RESULTS = listOf("ok", "cancelled", "backoff", "error")
    val APP_STATES = listOf("NO_PASSCODE", "LOCKED", "UNLOCKED")

    /** The 19 rows, in the vector's order. The test compares this table with the file row by row. */
    val TRANSITIONS: List<PasscodeTransition> = listOf(
        PasscodeTransition("enable", "setup_new", "submit_valid", "setup_confirm"),
        PasscodeTransition("enable", "setup_new", "submit_invalid", "setup_new", message = "policy"),
        PasscodeTransition("enable", "setup_confirm", "submit_match", "done", result = "ok"),
        PasscodeTransition("enable", "setup_confirm", "submit_mismatch", "setup_new", message = "mismatch"),
        PasscodeTransition("change", "verify_old", "submit_match", "setup_new", message = null),
        PasscodeTransition("change", "verify_old", "submit_wrong", "verify_old", message = "wrong"),
        PasscodeTransition("change", "verify_old", "cooldown", "done", result = "backoff"),
        PasscodeTransition("change", "setup_confirm", "submit_match", "done", result = "ok"),
        PasscodeTransition("disable", "verify", "submit_match", "done", result = "ok"),
        PasscodeTransition("disable", "verify", "submit_wrong", "verify", message = "wrong"),
        PasscodeTransition("unlock", "unlock", "submit_match", "done", result = "ok"),
        PasscodeTransition("unlock", "unlock", "submit_wrong", "unlock", message = "wrong"),
        PasscodeTransition("unlock", "unlock", "cooldown", "done", result = "backoff"),
        PasscodeTransition("*", "*", "cancel", "done", result = "cancelled"),
        PasscodeTransition("change", "setup_new", "submit_valid", "setup_confirm", specAdded = true),
        PasscodeTransition("change", "setup_new", "submit_invalid", "setup_new", message = "policy", specAdded = true),
        PasscodeTransition("change", "setup_confirm", "submit_mismatch", "setup_new", message = "mismatch", pwaAdded = true),
        PasscodeTransition("disable", "verify", "cooldown", "done", result = "backoff", pwaAdded = true),
        PasscodeTransition("*", "*", "internal_error", "done", result = "error", pwaAdded = true),
    )

    /** The row for (mode, from, event): an exact row first, then the wildcard row. `null` = not a legal transition. */
    fun next(mode: String, from: String, event: String): PasscodeTransition? =
        TRANSITIONS.firstOrNull { it.mode == mode && it.from == from && it.event == event }
            ?: TRANSITIONS.firstOrNull { it.mode == "*" && it.from == "*" && it.event == event }
}
