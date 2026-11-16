package network.conet.chat.nativekey

/**
 * The decision of `pgpRegistrationMaterial` (§25.52Y.61, vectors `registrationMaterialCases` RM-01 to RM-15). Pure: the caller seals the backup,
 * reads it back, checks the keyId, signs, and submits; this function gives the code and the fields that may be returned. Only a success returns
 * fields (pubArmor, keyId, backupCiphertext, walletSignature, wallet); a private key is never returned.
 */
internal object RegistrationMaterialPolicy {
    data class Input(
        val payloadKeys: List<String>,
        val accountMatch: Boolean = true,
        val unlocked: Boolean = true,
        val storageLocked: Boolean = false,
        val kPgpExists: Boolean = true,
        val sealOk: Boolean = true,
        val openOk: Boolean = true,
        val keyIdMatchesStored: Boolean = true,
        val signOk: Boolean = true,
        val shell: Boolean = false,
        /** The shell submission outcome: "accepted", "unreachable" (both routes), or "refused" by the server. */
        val submitOk: String = "accepted",
    )

    data class Result(val code: String, val returned: List<String>)

    val SUCCESS_FIELDS = listOf("pubArmor", "keyId", "backupCiphertext", "walletSignature", "wallet")

    fun decide(i: Input): Result {
        if ("privateKeyArmor" in i.payloadKeys) return Result("key_over_bridge_refused", emptyList())
        if (!i.accountMatch) return Result("account_mismatch", emptyList())
        if (!i.unlocked) return Result(if (i.storageLocked) "not_ready" else "locked", emptyList())
        if (!i.kPgpExists) return Result("no_pgp_key", emptyList())
        if (!i.sealOk) return Result("backup_failed", emptyList())
        if (!i.openOk) return Result("backup_readback_failed", emptyList())
        if (!i.keyIdMatchesStored) return Result("key_mismatch", emptyList())
        if (!i.signOk) return Result("sign_failed", emptyList())
        if (!i.shell) return Result("ok", SUCCESS_FIELDS)
        return when (i.submitOk) {
            "accepted" -> Result("submitted", emptyList())
            "unreachable" -> Result("network_unavailable", emptyList())
            else -> Result("chain_refused", emptyList())
        }
    }
}
