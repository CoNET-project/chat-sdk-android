package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The bridge side of `pgpMigrate` (spec r3at §25.52.4, §25.52.5, §25.52.14; T-261, R-01, R-02). The request carries `type` and
 * `reqId` and nothing else. The decision is a pure function of the request, the gate and the running flag, so the vectors can run
 * it without an Android context. The module does the I/O: it sends the ack, runs [BeamioPgpMigrationImport.run] on a worker, and sends
 * the result event.
 */
internal object PgpMigrationBridge {
    /** Fields that carry key material. A request with one of them is refused, and only the field names are reported (R-02). */
    val KEY_FIELDS: Set<String> = network.conet.chat.identity.CredFields.NAMES.toSet()

    private val FIELDS = setOf("type", "reqId")

    /** The answer to a request. [Refused] carries the code and, for `bad_request` and `key_over_bridge_refused`, the field names. */
    sealed class Ack {
        class Refused(val code: String, val fields: List<String> = emptyList()) : Ack()
        object Busy : Ack()
        object Accepted : Ack()
    }

    /**
     * Order (vectors R-02, R-01, M-01 to M-04): key fields first, then unknown fields, then `reqId`, then the gate (G0 `no_key`,
     * G1 `not_ready`, a locked record `locked`), then the running flag (`busy`). Nothing in the request is read beyond names.
     */
    fun ackFor(body: JSONObject, gate: NoKeyGate.Gate, locked: Boolean, running: Boolean): Ack {
        val names = body.keys().asSequence().map { it.toString() }.toList()
        val keyFields = names.filter { it in KEY_FIELDS }.sorted()
        if (keyFields.isNotEmpty()) return Ack.Refused("key_over_bridge_refused", keyFields)
        val extra = names.filter { it !in FIELDS }.sorted()
        if (extra.isNotEmpty()) return Ack.Refused("bad_request", extra)
        if (PgpDecryptInbound.reqIdOf(body) == null) return Ack.Refused("bad_request")
        when (gate) {
            NoKeyGate.Gate.G0 -> return Ack.Refused("no_key")
            NoKeyGate.Gate.G1 -> return Ack.Refused("not_ready")
            NoKeyGate.Gate.G2 -> Unit
        }
        if (locked) return Ack.Refused("locked")
        if (running) return Ack.Busy
        return Ack.Accepted
    }

    /** The result event (§25.52.5). `fp` is the first 16 characters of the fingerprint, or `null`. */
    fun eventFor(reqId: Any, result: MigrationResult): JSONObject = JSONObject()
        .put("type", "pgpMigrateResult")
        .put("reqId", reqId)
        .put("code", result.code.wire)
        .put("fp", result.fp?.take(16) ?: JSONObject.NULL)
}
