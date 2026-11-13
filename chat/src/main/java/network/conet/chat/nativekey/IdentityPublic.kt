package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * `identityPublic` (spec r3ae §25.48): the account's public material, for G2 only. It is read-only: it writes nothing,
 * signs nothing and unlocks nothing, so the passcode lock does not affect it.
 *
 * Order: the gate first (G0 `no_key`, G1 `not_ready`), with the payload not read. Then the input: a credential or key field
 * is `key_over_bridge_refused` (only its name is kept, for the log), any other field besides `type` and `reqId` is
 * `bad_request`, and a `reqId` that is not a string or a non-negative integer is `bad_request` (§25.28.3). Then the result.
 *
 * The result is built from the fixed fields below and nothing else, so no secret, hash, stored block or ciphertext can reach
 * it (§25.48.5). `pgpReady` is true only when the native record holds the key ID, the PGP public armor and the route public
 * armor together. The PGP fields are not taken from the PWA's copies in the session.
 */
internal object IdentityPublic {
    const val NO_KEY = NoKeyGate.NO_KEY
    const val NOT_READY = NoKeyGate.NOT_READY
    const val BAD_REQUEST = "bad_request"
    const val KEY_REFUSED = "key_over_bridge_refused"

    /** §25.41.3 credential fields, plus `privateKeyArmor` and `encrypKeyArmored` (§25.48.3). */
    val CREDENTIAL_FIELDS: Set<String> = setOf(
        "privateKeyHex", "privateKeyArmor", "privateKeyArmored", "pgpPrivateKeyArmored", "encrypKeyArmored",
        "pgpPassphrase", "walletPrivateKey", "mnemonic", "recoveryCode", "pin", "password", "accountPassword",
    )

    private val ALLOWED_FIELDS: Set<String> = setOf("type", "reqId")

    /** The PGP public material of the native record. The three values are all needed for `pgpReady`. */
    class PgpPublic(val keyId: String, val publicArmor: String, val routeArmor: String)

    /** The public facts the decision reads. Each one comes from the native layer, never from the payload. */
    interface Source {
        /** The account of this session, `0x…` (any case), or null when there is none. */
        fun eoa(): String?

        /** The native PGP public material, or null when the native record does not hold it. */
        fun pgp(): PgpPublic?
    }

    /** The decision. [error] is null for ok; [refused] is the first credential field name, for the log only. */
    class Reply(val error: String?, val result: JSONObject?, val refused: String? = null) {
        val ok: Boolean get() = error == null
    }

    /**
     * The answer for one call. [fieldsOf] is read only in G2, so the payload of a refused call is not inspected.
     */
    fun answer(gate: NoKeyGate.Gate, fieldsOf: () -> Collection<String>, reqId: Any?, source: Source): Reply {
        when (gate) {
            NoKeyGate.Gate.G0 -> return Reply(NO_KEY, null)
            NoKeyGate.Gate.G1 -> return Reply(NOT_READY, null)
            NoKeyGate.Gate.G2 -> Unit
        }
        val fields = fieldsOf()
        fields.firstOrNull { it in CREDENTIAL_FIELDS }?.let { return Reply(KEY_REFUSED, null, refused = it) }
        if (fields.any { it !in ALLOWED_FIELDS }) return Reply(BAD_REQUEST, null)
        if (reqId == null) return Reply(BAD_REQUEST, null)
        val eoa = source.eoa()?.takeIf { it.isNotEmpty() }?.lowercase() ?: return Reply(NOT_READY, null)
        val result = JSONObject()
            .put("eoa", eoa)
            .put("accountKey", NoKeyGate.accountKeyOf(eoa))
            .put("pgpReady", false)
        val pgp = source.pgp()
        if (pgp != null && pgp.keyId.isNotEmpty() && pgp.publicArmor.isNotEmpty() && pgp.routeArmor.isNotEmpty()) {
            result.put("pgpReady", true)
                .put("pgpKeyID", pgp.keyId)
                .put("pgpPublicKeyArmored", pgp.publicArmor)
                .put("ownRouteArmoredPublicKey", pgp.routeArmor)
        }
        return Reply(null, result)
    }

    /** The ack envelope (§25.45): `result` only on success. `reqId` is echoed as sent, or null. */
    fun ackPayload(reqId: Any?, reply: Reply): JSONObject {
        val payload = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", reply.ok)
        if (reply.ok) {
            reply.result?.let { payload.put("result", it) }
        } else {
            payload.put("error", reply.error)
        }
        return payload
    }
}
