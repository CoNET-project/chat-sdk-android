package network.conet.chat.nativekey

import network.conet.chat.identity.IdentityProvisionContract
import org.json.JSONObject

/**
 * `identityPublic` (spec r3ae §25.48, r3ag): the account's public material, for G2 only. It is read-only: it writes nothing,
 * signs nothing, unlocks nothing and migrates nothing, so the passcode lock does not affect it.
 *
 * Order: the gate first (G0 `no_key`, G1 `not_ready`), with the payload not read. Then the input: a credential or key field is
 * `key_over_bridge_refused` (only its name is kept, for the log), any other field besides `type` and `reqId` is `bad_request`,
 * and a `reqId` that is not a string or a non-negative integer is `bad_request` (§25.28.3). Then the result.
 *
 * The result is built from fixed fields only, so no secret, hash, stored block or ciphertext can reach it (§25.48.5).
 * `pgpReady` is true only when the current-layout PGP record holds a key ID, a PGP public armor and a route public armor, all
 * non-empty, and both armors are public armor in the form the production save accepts (§25.48.4, r3ag). An old-layout record,
 * or no record, gives `pgpReady` false with no PGP fields. That is not an error and not "no identity" (§25.48.9). Nothing here
 * creates, restores or overwrites a key, and nobody may act on `pgpReady` false alone (§25.30.3).
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

    /** What the native PGP record gives this read. The read path never migrates an old layout (§25.48.9). */
    sealed interface PgpRecord {
        /** No native source for the record is read here yet. */
        object NotRead : PgpRecord

        /** The account has no PGP record. */
        object Absent : PgpRecord

        /** The record is in the old layout. The read path leaves it as it is. */
        object LegacyLayout : PgpRecord

        /** The current layout, with its public parts as stored. */
        class Current(val keyId: String, val publicArmor: String, val routeArmor: String) : PgpRecord
    }

    /** The public facts the decision reads. Each one comes from the native layer, never from the payload. */
    interface Source {
        /** The account of this session, `0x…` (any case), or null when there is none. */
        fun eoa(): String?

        /** What the native PGP record gives this read. */
        fun pgp(): PgpRecord
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
        // Only the current layout can be ready. NotRead, Absent and LegacyLayout leave pgpReady false, with no PGP fields.
        val current = (source.pgp() as? PgpRecord.Current)?.takeIf { isReady(it) }
        if (current != null) {
            result.put("pgpReady", true)
                .put("pgpKeyID", current.keyId)
                .put("pgpPublicKeyArmored", current.publicArmor)
                .put("ownRouteArmoredPublicKey", current.routeArmor)
        }
        return Reply(null, result)
    }

    /** `pgpReady` (§25.48.4, r3ag): the three values are non-empty, and both armors are PGP public armor. */
    private fun isReady(c: PgpRecord.Current): Boolean =
        c.keyId.isNotEmpty() &&
            IdentityProvisionContract.isPublicArmor(c.publicArmor) &&
            IdentityProvisionContract.isPublicArmor(c.routeArmor)

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
