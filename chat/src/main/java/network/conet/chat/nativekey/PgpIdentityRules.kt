package network.conet.chat.nativekey

/**
 * The PGP identity rules of §25.52Y.60 (PWA and iOS conventions): the user ID of a new key is the lower-case account EOA (name only); an existing key
 * keeps its user ID. The user ID never takes part in a match: the account is compared lower-case, the keyID after removing whitespace and upper-casing.
 * The registry records the upper-case subkey keyId.
 */
internal object PgpIdentityRules {
    /** The user ID name written for a key: the lower-case EOA for a new key; an existing key keeps [existingName] (PI-01, PI-02). */
    fun userIdName(eoa: String, isNewKey: Boolean, existingName: String): String =
        if (isNewKey) eoa.lowercase() else existingName

    /** Account equality after lower-casing (PI-03, PI-06). */
    fun accountMatch(eoa: String, profileAccount: String): Boolean = eoa.lowercase() == profileAccount.lowercase()

    /** The keyID in its canonical form: whitespace removed and upper-cased (PI-04). */
    fun normalizeKeyId(raw: String): String = raw.filterNot { it.isWhitespace() }.uppercase()

    /** keyID equality after normalization (PI-02, PI-04). */
    fun keyIdMatch(local: String, remote: String): Boolean = normalizeKeyId(local) == normalizeKeyId(remote)

    /** The keyID recorded in the registry: the upper-case canonical subkey keyId (PI-07). */
    fun registryKeyId(local: String): String = normalizeKeyId(local)
}
