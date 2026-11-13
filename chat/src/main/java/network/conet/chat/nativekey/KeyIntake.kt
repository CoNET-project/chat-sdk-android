package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * Key fields the bridge refuses (spec 25.20.1 rule 1; negative cases T-127, T-127b, T-103). Only a non-blank
 * value counts. Callers log field names and never values.
 *
 * `init` refuses wallet keys. The PGP armor it still carries is not listed here: `init` writes that armor only into the
 * native PGP record (R7, commit 81fc851; spec 25.22.2), never into the session or back to the page. The field is removed
 * when P-IMP-PGP is decided (§36-B). `provisionIdentity` refuses every key field.
 */
object KeyIntake {
    val INIT_REFUSED: List<String> = listOf("privateKeyHex", "walletPrivateKey")

    val PROVISION_REFUSED: List<String> = listOf(
        "privateKeyHex",
        "walletPrivateKey",
        "privateKeyArmor",
        "pgpPrivateKeyArmored",
        "pgpPassphrase",
        "mnemonic",
    )

    fun refusedIn(obj: JSONObject?, names: List<String>): List<String> {
        if (obj == null) return emptyList()
        return names.filter { obj.optString(it, "").isNotBlank() }
    }

    /** `init` payload: key fields at the top level or under `identity`. */
    fun initRefused(payload: JSONObject): List<String> =
        (refusedIn(payload, INIT_REFUSED) + refusedIn(payload.optJSONObject("identity"), INIT_REFUSED)).distinct()

    /** `provisionIdentity` payload: key fields at the top level or under `identity`. */
    fun provisionRefused(payload: JSONObject): List<String> =
        (refusedIn(payload, PROVISION_REFUSED) + refusedIn(payload.optJSONObject("identity"), PROVISION_REFUSED)).distinct()
}
