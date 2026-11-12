package network.conet.chat.identity

import org.json.JSONArray
import org.json.JSONObject

/**
 * identity.native-keys.v1: request checks and ready report (spec r3b 25.19.2, batch 19 vectors
 * `spec/identity-native-keys-vectors.v1.json`, sha256 6bdbb384…).
 *
 * Field placement: `provisionIdentity` carries the public fields flat in the payload; `init` carries
 * them under `payload.identity`, never at the top level of `init`.
 *
 * I-4: key names are matched case-insensitively, and any string value (at any depth, arrays included)
 * that contains "PRIVATE KEY BLOCK" or is a 64-hex value is refused. Only the field name is reported.
 *
 * Pure logic. The native side supplies a [NativeKeyState] from its own key store, and production
 * readback must be verified before it reports [NativeKeyState.HAS_KEY_READBACK_OK].
 *
 * NOT wired into `provisionIdentity` or `init` yet. The capability is not declared in hello until
 * both platforms pass the vectors and the native store exists (spec 12.3, 25.19.3). Until then the
 * legacy payload path is unchanged.
 */
object IdentityProvisionContract {
    enum class Command(val wire: String) { PROVISION_IDENTITY("provisionIdentity"), INIT("init") }

    /** Forbidden key names as written in the spec; matched case-insensitively. */
    val FORBIDDEN_KEYS: List<String> = listOf(
        "privateKeyHex",
        "walletPrivateKey",
        "privateKeyArmor",
        "pgpPrivateKeyArmored",
        "pgpPassphrase",
        "mnemonic",
    )

    private val FORBIDDEN_LOWER: Set<String> = FORBIDDEN_KEYS.map { it.lowercase() }.toSet()

    /** Only these keys may appear in the response body (the `result` object). `ok` belongs to the ack envelope. */
    val RESPONSE_KEYS: Set<String> = setOf("ready", "eoa")

    enum class NativeKeyState { HAS_KEY_READBACK_OK, NO_KEY, KEY_ADDRESS_MISMATCH }

    sealed class Result {
        data class Accept(val eoa: String) : Result()
        data class Reject(val error: String, val field: String? = null) : Result()
    }

    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")
    private val HEX64_RE = Regex("^(0x)?[0-9a-fA-F]{64}$")
    private const val PGP_PUBLIC_HEADER = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    private const val PRIVATE_BLOCK_MARK = "PRIVATE KEY BLOCK"

    /**
     * Checks one request. Order: forbidden key names (any depth), value shapes (any depth), then the
     * public identity at the placement the command requires.
     */
    fun validate(command: Command, body: JSONObject): Result {
        findForbiddenKey(body)?.let { return Result.Reject("key_over_bridge_refused", it) }
        findBadValue(body, null)?.let { return Result.Reject("key_over_bridge_refused", it) }
        val identity: JSONObject = when (command) {
            Command.PROVISION_IDENTITY -> body
            Command.INIT -> body.optJSONObject("identity") ?: return Result.Reject("missing_identity")
        }
        val rawEoa = identity.opt("eoa") ?: return Result.Reject("missing_identity")
        val eoa = rawEoa as? String ?: return Result.Reject("bad_identity")
        if (!EOA_RE.matches(eoa)) return Result.Reject("bad_identity")
        val rawPgp = identity.opt("pgpPublicKeyArmored") ?: return Result.Reject("missing_identity")
        val pgp = rawPgp as? String ?: return Result.Reject("bad_identity")
        if (!pgp.trimStart().startsWith(PGP_PUBLIC_HEADER)) return Result.Reject("bad_identity")
        return Result.Accept(eoa)
    }

    /** `{ready, eoa}`. `ready` is true only when the native store holds this account's key, read back and checked. */
    fun readyResponse(eoa: String, state: NativeKeyState): JSONObject =
        JSONObject()
            .put("ready", state == NativeKeyState.HAS_KEY_READBACK_OK)
            .put("eoa", eoa)

    /** The key name as written in the input, if any object at any depth has a forbidden name. */
    private fun findForbiddenKey(node: Any?): String? = when (node) {
        is JSONObject -> node.keys().asSequence().firstNotNullOfOrNull { k ->
            if (k.lowercase() in FORBIDDEN_LOWER) k else findForbiddenKey(node.opt(k))
        }
        is JSONArray -> (0 until node.length()).firstNotNullOfOrNull { findForbiddenKey(node.opt(it)) }
        else -> null
    }

    /**
     * The field that holds a string value with a private-key block or a 64-hex value. For an array item,
     * the field is the array's key. Only the field name is returned, never the value.
     */
    private fun findBadValue(node: Any?, parentKey: String?): String? = when (node) {
        is JSONObject -> node.keys().asSequence().firstNotNullOfOrNull { k -> findBadValue(node.opt(k), k) }
        is JSONArray -> (0 until node.length()).firstNotNullOfOrNull { findBadValue(node.opt(it), parentKey) }
        is String -> if (isBadValue(node)) parentKey ?: "" else null
        else -> null
    }

    private fun isBadValue(s: String): Boolean =
        s.uppercase().contains(PRIVATE_BLOCK_MARK) || HEX64_RE.matches(s)
}
