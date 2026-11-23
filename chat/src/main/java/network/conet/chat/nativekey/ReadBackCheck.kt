package network.conet.chat.nativekey

/**
 * The read-back check of the cleanup confirmation (v182 §202, v185, PWA reply 2026-11-21): the account is read back only when the page's derived
 * address and the native re-read address both equal the account of [accountKey]. A missing or unreadable address on either side is not a pass, so
 * the check fails and nothing is deleted. The page address is only the lower-case `eoa` the page sends (never a key or phrase); nothing here derives an
 * address from a phrase on the page side. The native address is supplied by the caller from the vault (the SDK side), so a test can stand in for it.
 */
internal object ReadBackCheck {
    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")

    /** The three verdicts of the read-back. */
    enum class Verdict { PASS, MISMATCH, UNREADABLE }

    /**
     * Both sides readable and equal the account: PASS. Both readable and at least one differs from the account: MISMATCH (account_mismatch).
     * A side missing, malformed or unreadable: UNREADABLE (not_ready). Never PASS on an unreadable side.
     */
    fun verdict(accountKey: String?, pageEoa: String?, nativeEoa: String?): Verdict {
        val account = accountKey?.substringBefore(':')?.lowercase() ?: return Verdict.UNREADABLE
        if (!EOA_RE.matches(account)) return Verdict.UNREADABLE
        val page = pageEoa ?: return Verdict.UNREADABLE
        val native = nativeEoa ?: return Verdict.UNREADABLE
        if (!EOA_RE.matches(page) || !EOA_RE.matches(native)) return Verdict.UNREADABLE
        return if (page == account && native == account) Verdict.PASS else Verdict.MISMATCH
    }

    /** True only when both addresses are valid and equal the account part of [accountKey] (`eoa:workspace`). */
    fun passes(accountKey: String?, pageEoa: String?, nativeEoa: String?): Boolean {
        val account = accountKey?.substringBefore(':')?.lowercase() ?: return false
        val page = pageEoa ?: return false
        val native = nativeEoa ?: return false
        if (!EOA_RE.matches(account) || !EOA_RE.matches(page) || !EOA_RE.matches(native)) return false
        return page == account && native == account
    }

    /** The log form of an address: the first 6 and the last 4 characters only (PWA reply, v182 §202). Never the full address. */
    fun logForm(address: String): String =
        if (address.length <= 10) "masked" else address.take(6) + "…" + address.takeLast(4)
}
