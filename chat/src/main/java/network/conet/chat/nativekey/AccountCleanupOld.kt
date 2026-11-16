package network.conet.chat.nativekey

/**
 * `accountCleanupOld` (25.52Y.91; Y.85 第 3 項 (c)): after the user has recovered and confirmed on the native confirmation screen, delete the
 * old storage of every account except the new one. This object is the decision only: the input check, the preflight in its order, and the
 * execution with its idempotent resume. It is not registered on the bridge yet (see the receipt): the store inventory and the persisted
 * resume journal are not wired.
 *
 * Trigger (25.52Y.91 第 2 項): the page sends `{type:"accountCleanupOld", reqId, accountKey, idempotencyKey}` after recovery is complete.
 * The user's confirmation is never carried in the payload; the native confirmation screen records it in the native state.
 */
internal object AccountCleanupOld {
    const val NAME = "accountCleanupOld"
    const val OK = "ok"
    const val CLEAR_INCOMPLETE = "clear_incomplete"
    const val BAD_REQUEST = "bad_request"
    const val CONFIRMATION_NOT_NATIVE = "confirmation_not_native"
    const val KEY_REFUSED = "key_over_bridge_refused"
    const val NOT_CONFIRMED = "not_confirmed"
    const val ACCOUNT_MISMATCH = "account_mismatch"
    const val NOT_AVAILABLE = "not_available"
    const val NOT_READY = "not_ready"

    /** A confirmation carried by the page is refused: the confirmation is native only (25.52Y.91 第 3 項). */
    val CONFIRM_FIELDS: Set<String> = setOf("confirm", "confirmed", "userConfirmed", "confirmToken")

    /** Key, passphrase, mnemonic or armor fields are refused before anything else (25.52Y.91 第 3 項). */
    val KEY_FIELDS: Set<String> = setOf(
        "privateKeyHex", "privateKeyArmor", "privateKeyArmored", "pgpPrivateKeyArmored", "pgpPassphrase", "walletPrivateKey",
        "mnemonic", "mnemonicPhrase", "recoveryCode", "pin", "password", "accountPassword",
    )

    private val ALLOWED_FIELDS: Set<String> = setOf("accountKey", "idempotencyKey")

    /** One stored item and the accountKey it belongs to (`eoa:workspace`, 25.52Y.77). */
    data class Item(val name: String, val accountKey: String)

    /** The result: [code], the names deleted by this call, the names of the new account kept, and whether a resume is pending. */
    class Outcome(val code: String, val deleted: List<String>, val kept: List<String>, val cleanupPending: Boolean)

    /**
     * The input check, before any store is read. [payloadFields] are the payload keys other than `type` and `reqId`. Returns the refusal
     * code, or null when the shape is right.
     */
    fun refuseInput(payloadFields: Collection<String>, accountKey: String?, idempotencyKey: String?): String? {
        if (payloadFields.any { it in CONFIRM_FIELDS }) return CONFIRMATION_NOT_NATIVE
        if (payloadFields.any { it in KEY_FIELDS }) return KEY_REFUSED
        if (payloadFields.any { it !in ALLOWED_FIELDS }) return BAD_REQUEST
        if (accountKey.isNullOrEmpty() || idempotencyKey.isNullOrEmpty()) return BAD_REQUEST
        return null
    }

    /**
     * The preflight, in the order of 25.52Y.91 第 4 項 (a) to (d). Returns the refusal code, or null when every check passes. No item is deleted
     * on a refusal.
     */
    fun preflight(gateNotReady: Boolean, newAccountReadable: Boolean, nativeConfirmed: Boolean, accountKeyMatch: Boolean): String? = when {
        gateNotReady -> NOT_READY
        !newAccountReadable -> NOT_AVAILABLE
        !nativeConfirmed -> NOT_CONFIRMED
        !accountKeyMatch -> ACCOUNT_MISMATCH
        else -> null
    }

    /**
     * The execution (25.52Y.91 第 5 項 to 7 項). Removes every item whose accountKey is not [newAccountKey]; an item of the new account is never a
     * candidate. [remove] returns true when the item is gone. A failed item is kept and the others still go on. [done] holds the names an
     * earlier call with the same idempotencyKey already removed, so they are not handled again (第 7 項). The result is `ok`, or
     * `clear_incomplete` with `cleanupPending` true: the removed items stay removed, and a later call finishes the rest.
     */
    fun execute(newAccountKey: String, items: List<Item>, done: MutableSet<String>, remove: (Item) -> Boolean): Outcome {
        val old = items.filter { it.accountKey != newAccountKey && it.name !in done }
        val deleted = mutableListOf<String>()
        var failed = false
        for (item in old) {
            if (remove(item)) {
                done += item.name
                deleted += item.name
            } else {
                failed = true
            }
        }
        val kept = items.filter { it.accountKey == newAccountKey }.map { it.name }
        return if (failed) Outcome(CLEAR_INCOMPLETE, deleted, kept, cleanupPending = true)
        else Outcome(OK, deleted, kept, cleanupPending = false)
    }
}
