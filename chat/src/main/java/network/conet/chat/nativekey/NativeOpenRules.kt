package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The three page-open commands (spec r3t §25.41.3, r3x §25.46.10): `nativeImportOpen`, `nativeRecoveryOpen` and
 * `nativeAccountCreateOpen`. Each command has one pure decision here. The module sends the ack from it, and the vector
 * harness (`NativeOpenVectorsTest`) runs the same functions against the real hosts, so the answer checked is the answer sent.
 *
 * Order, the same for all three:
 *  1. Input. A credential field is `key_over_bridge_refused`; only its name is logged, never its value. Any other field
 *     besides `type` and `reqId`, or a `reqId` that is not a string or a non-negative integer, is `bad_request`.
 *  2. Host. Not registered is `not_supported`, in every state.
 *  3. Account create only: G1 and G2 answer `not_available` and the host is not called. G0 continues.
 *  4. The host opens its page: ok. The host refuses, or throws: `not_available`.
 *
 * The gate is never `no_key` or `not_ready` for these names. Nothing here reads a credential value.
 */
internal object NativeOpenRules {
    const val BAD_REQUEST = "bad_request"
    const val KEY_REFUSED = "key_over_bridge_refused"
    const val NOT_SUPPORTED = "not_supported"
    const val NOT_AVAILABLE = "not_available"

    /** Credential fields (vector `credentialFields`). A payload with one is refused before any other check. */
    val CREDENTIAL_FIELDS: Set<String> = setOf(
        "privateKeyHex", "privateKeyArmored", "pgpPrivateKeyArmored", "pgpPassphrase", "walletPrivateKey", "mnemonic",
        "recoveryCode", "pin", "password", "accountPassword",
    )

    private val ALLOWED_FIELDS: Set<String> = setOf("type", "reqId")

    /** `nativeAccountCreateOpen` takes `{type, reqId, account}` (spec §25.52Z.2, r3bv). */
    private val ACCOUNT_CREATE_FIELDS: Set<String> = setOf("type", "reqId", "account")

    /** BeamioTag: 1 to 64 visible ASCII characters, not starting with `0x`. EOA: `0x` plus 40 lowercase hex digits. */
    private val BEAMIO_TAG = Regex("^[\\x21-\\x7E]{1,64}$")
    private val CANONICAL_EOA_ACCOUNT = Regex("^0x[0-9a-f]{40}$")

    /** One page's host. [open] is called only when the decision needs it. */
    internal interface Host {
        /** `false` means the shell never registered this page: `not_supported`. */
        fun registered(): Boolean

        /** `true` when the page opened. Only called when [registered] is true. */
        fun open(reqId: Any): Boolean
    }

    /**
     * The decision. [error] is `null` for ok. [page] is set only by `nativeAccountCreateOpen` when it opened the page
     * (`opened`), so the ack carries `page` (spec §25.52Z, accountAckPage).
     */
    internal class Reply(val error: String?, val page: String? = null) {
        val ok: Boolean get() = error == null
    }

    /** The first credential field name, for the log line only. */
    fun firstCredentialField(fields: Collection<String>): String? = fields.firstOrNull { it in CREDENTIAL_FIELDS }

    fun importOpen(fields: Collection<String>, reqId: Any?, host: Host): Reply =
        decide(fields, reqId, host, gate = null, allowed = ALLOWED_FIELDS)

    fun recoveryOpen(fields: Collection<String>, reqId: Any?, host: Host): Reply =
        decide(fields, reqId, host, gate = null, allowed = ALLOWED_FIELDS)

    /**
     * `nativeAccountCreateOpen` (§25.46.10, §25.52Z.2). [account] is the value of the `account` field (`null` when absent).
     * Missing or malformed `account` is `bad_request`, checked with the input, before the host is asked.
     */
    fun accountCreateOpen(
        fields: Collection<String>,
        reqId: Any?,
        account: Any?,
        gate: NoKeyGate.Gate,
        host: Host,
        guardDenial: String? = null,
    ): Reply =
        decide(fields, reqId, host, gate, allowed = ACCOUNT_CREATE_FIELDS, account = account, accountRequired = true, guardDenial = guardDenial)

    /** `true` when [account] is a BeamioTag or a canonical EOA address (§25.52Z.2). */
    fun isValidAccount(account: Any?): Boolean {
        val s = account as? String ?: return false
        return CANONICAL_EOA_ACCOUNT.matches(s) || (!s.startsWith("0x") && BEAMIO_TAG.matches(s))
    }

    private fun decide(
        fields: Collection<String>,
        reqId: Any?,
        host: Host,
        gate: NoKeyGate.Gate?,
        allowed: Set<String>,
        account: Any? = null,
        accountRequired: Boolean = false,
        guardDenial: String? = null,
    ): Reply {
        if (fields.any { it in CREDENTIAL_FIELDS }) return Reply(KEY_REFUSED)
        if (fields.any { it !in allowed }) return Reply(BAD_REQUEST)
        if (accountRequired && !isValidAccount(account)) return Reply(BAD_REQUEST)
        val id = reqId ?: return Reply(BAD_REQUEST)
        if (!host.registered()) return Reply(NOT_SUPPORTED)
        if (gate != null && gate != NoKeyGate.Gate.G0) return Reply(NOT_AVAILABLE)
        // The create guard (AccountCreateGuard): a create that is not allowed never opens the page; the diagnostic code stays in the SDK.
        if (guardDenial != null) return Reply(NOT_AVAILABLE)
        return if (host.open(id)) {
            Reply(null, page = if (accountRequired) PAGE_OPENED else null)
        } else {
            Reply(NOT_AVAILABLE)
        }
    }

    const val PAGE_OPENED = "opened"

    /**
     * The ack the module emits: `{type, reqId, ok}`, with `error` only when not ok, and `page` only when the account page
     * opened. `reqId` is echoed as sent, or `null`.
     */
    fun ackPayload(reqId: Any?, reply: Reply): JSONObject {
        val payload = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", reply.ok)
        reply.error?.let { payload.put("error", it) }
        reply.page?.let { payload.put("page", it) }
        return payload
    }

    /** The shell's page for each command. A page that is not registered is `not_supported`. */
    val importHost: Host = object : Host {
        override fun registered(): Boolean = NativeImportHost.launcher != null
        override fun open(reqId: Any): Boolean = NativeImportHost.open()
    }

    val recoveryHost: Host = object : Host {
        override fun registered(): Boolean = NativeRecoveryHost.launcher != null
        override fun open(reqId: Any): Boolean = NativeRecoveryHost.open(reqId) == NativeRecoveryHost.OpenAnswer.OPENED
    }

    val accountHost: Host = object : Host {
        override fun registered(): Boolean = NativeAccountCreateHost.launcher != null
        override fun open(reqId: Any): Boolean = NativeAccountCreateHost.open(reqId)
    }
}
