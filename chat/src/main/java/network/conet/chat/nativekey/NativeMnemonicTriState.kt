package network.conet.chat.nativekey

/**
 * The native recovery-phrase state of 25.52Y.89 (vectors TS-01 to TS-06): `has`, `confirmed_none`, or `unknown`. It is built only from answers
 * that already exist: `walletStatus` and the `kPresent` of the identityPublic G0 `no_key` answer (25.52Y.90). No command is added. Locked,
 * unreadable and timed-out states are unknown, never "none" (25.52Y.85 第 5 項).
 */
internal object NativeMnemonicTriState {
    const val HAS = "has"
    const val CONFIRMED_NONE = "confirmed_none"
    const val UNKNOWN = "unknown"

    /**
     * [snapshotUnknown]: the snapshot is not known (TS-05). [walletStatus] is the walletStatus `status` and [reason] its `notReadyReason`.
     * [kPresent] is the boolean of the G0 `no_key` answer; null when it is absent or not a boolean, which is unknown (TS-06).
     */
    fun classify(snapshotUnknown: Boolean, walletStatus: String?, reason: String?, kPresent: Boolean?): String {
        if (snapshotUnknown) return UNKNOWN
        return when (walletStatus) {
            // G2: an unlocked or locked record with its account (25.52Y.89 第 2 項).
            "unlocked", "locked" -> HAS
            // G1 with a readable record that is not initialised: the record exists.
            //  (c, Q3, E9): key_only is a native record that confirms no valid phrase (noValidPhraseConfirmed: every phrase position read).
            "not_ready" -> when (reason) {
                NoKeyGate.NOT_READY_G1_UNINITIALIZED -> HAS
                NoKeyGate.NOT_READY_KEY_ONLY -> CONFIRMED_NONE
                else -> UNKNOWN
            }
            // G0 with the reads complete: confirmed none whatever kPresent is (25.52Y.107 第 3 条, 25.52Y.108 第 1 条). kPresent missing or not a boolean
            // is a read error (Y.90): unknown.
            "no_key" -> if (kPresent == null) UNKNOWN else CONFIRMED_NONE
            else -> UNKNOWN
        }
    }
}
