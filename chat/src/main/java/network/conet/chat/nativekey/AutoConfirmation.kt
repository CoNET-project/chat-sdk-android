package network.conet.chat.nativekey

/**
 * The automatic confirmation of the silent cleanup: after a successful recovery, the page sends its confirmation command on its
 * own, with the page-derived address as accountKey. The marker is written only when the read-back passes ([ReadBackCheck.Verdict.PASS]); a mismatch,
 * an unreadable side, or an unfinished recovery writes nothing. No user action is involved (silent cleanup, v193 213 and v195 215). The cleanup itself still requires the other checks.
 */
internal object AutoConfirmation {
    enum class Result { RECORDED, NOT_RECORDED }

    /** Writes the marker for the account of [accountKey] only when the read-back passes. Returns whether it was recorded. */
    fun onPageConfirm(
        confirmation: CleanupConfirmation,
        accountKey: String?,
        pageEoa: String?,
        nativeEoa: String?,
        atMs: Long,
    ): Result {
        if (ReadBackCheck.verdict(accountKey, pageEoa, nativeEoa) != ReadBackCheck.Verdict.PASS) return Result.NOT_RECORDED
        val account = accountKey!!.substringBefore(':').lowercase()
        confirmation.record("$account:default", atMs)
        return Result.RECORDED
    }
}
