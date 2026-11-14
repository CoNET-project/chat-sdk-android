package network.conet.chat.nativekey

/**
 * Synthetic fixture for the write-side form and derived-address check (§25.52N.9 Q1, F2 condition 4): a private key that really derives the
 * account address it is stored under. These are test values, not wallets; the keys are not used anywhere else. The synthetic account
 * `PgpMigrationKeys.ACCOUNT` (0x2222…) has no key that derives it, so the record tests use these instead.
 */
internal object DerivedAccount {
    /** A synthetic private key (32 bytes of 0x11), in the canonical form the page writes. */
    const val KEY = "0x1111111111111111111111111111111111111111111111111111111111111111"

    /** The address that [KEY] derives, lower case. */
    val ADDRESS: String = requireNotNull(ShellRecordPolicy.addressOfArmor(KEY))

    /** A second synthetic private key (32 bytes of 0x22), for a second account. */
    const val KEY2 = "0x2222222222222222222222222222222222222222222222222222222222222222"

    /** The address that [KEY2] derives, lower case. */
    val ADDRESS2: String = requireNotNull(ShellRecordPolicy.addressOfArmor(KEY2))
}
