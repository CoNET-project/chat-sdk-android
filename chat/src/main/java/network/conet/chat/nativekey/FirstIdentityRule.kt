package network.conet.chat.nativekey

/**
 * The `legacy` and `chain` fields of `pgpRestoreEvaluate` (frozen shell passcode protocol §13; passcode vectors `pgpRestoreEvaluateReply`,
 * cases S-1…S-10). Pure: the caller supplies the readings. Anything missing or unknown is `unknown` (fail closed).
 *
 * Chain caliber (single RPC): the primary endpoint answers registered → `registered`; a successful read with no
 * registration → `unregistered`; a failure, timeout, malformed answer or wrong chain id → `unknown`. No second endpoint is needed.
 */
internal object FirstIdentityRule {
    /** The `legacy` field from the two legacy sources: the start-up report and the native copy's armor (null when unreadable). */
    fun legacyVerdict(report: LegacyReportState, armorRead: String?): String {
        val armorPresent = armorRead != null && armorRead.isNotEmpty()
        return when {
            report == LegacyReportState.FOUND || armorPresent -> "PRESENT"
            report == LegacyReportState.ABSENT && armorRead == "" -> "ABSENT"
            else -> "UNREADABLE"
        }
    }

    /** The `chain` field from one RPC outcome: `registered`, `unregistered`, or anything else (timeout, error, malformed) as unknown. */
    fun chainVerdict(outcome: String?): String = when (outcome) {
        "registered", "unregistered" -> outcome
        else -> "unknown"
    }

    /** The `chain` field from a single-RPC read of the chain (the same mapping as [chainVerdict], from the three-state identity read). */
    fun chainOfRead(chain: AddressPgpChain): String = when (chain.identityRead()) {
        is IdentityRead.Present -> "registered"
        IdentityRead.Absent -> "unregistered"
        IdentityRead.Unknown -> "unknown"
    }

    /** The creation entry opens only for a first identity with no legacy copy and an unregistered chain (protocol §13 rule). */
    fun creationEntryOpen(state: String, legacy: String, chain: String): Boolean =
        state == "first_identity" && legacy == "ABSENT" && chain == "unregistered"
}
