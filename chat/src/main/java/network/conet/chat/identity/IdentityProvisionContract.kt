package network.conet.chat.identity

import org.json.JSONArray
import org.json.JSONObject

/**
 * identity.native-keys.v1: request checks and ready report (spec r3b 25.19.2, batch 22 vectors
 * `spec/identity-native-keys-vectors.v1.json`, sha256 922d75f5…).
 *
 * Field placement: `provisionIdentity` carries the public fields flat in the payload; `init` carries
 * them under `payload.identity`, never at the top level of `init`.
 *
 * Normalization (valueShapeRules rule 0): before any comparison, every character of the set S is removed,
 * not only leading and trailing ones, for key names and values alike. S is Unicode White_Space plus
 * U+FEFF, U+200B–U+200D, U+2060 and U+00AD. No platform trim() is used.
 *
 * I-4: a normalized key name is matched case-insensitively at any depth. A normalized string value that
 * contains "PRIVATEKEYBLOCK" is refused at any depth, `payload.nodes` included. A normalized string that
 * matches 64 hex digits (optional 0x) is refused everywhere except the exact path `payload.nodes`. Only the
 * field name is reported, never the value.
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

    /** Forbidden key names as written in the spec; matched after normalization, case-insensitively. */
    val FORBIDDEN_KEYS: List<String> = listOf(
        "privateKeyHex",
        "walletPrivateKey",
        "privateKeyArmor",
        "pgpPrivateKeyArmored",
        "pgpPassphrase",
        "mnemonic",
    )

    /** Only these keys may appear in the response body (the `result` object). `ok` belongs to the ack envelope. */
    val RESPONSE_KEYS: Set<String> = setOf("ready", "eoa")

    enum class NativeKeyState { HAS_KEY_READBACK_OK, NO_KEY, KEY_ADDRESS_MISMATCH }

    sealed class Result {
        data class Accept(val eoa: String) : Result()
        data class Reject(val error: String, val field: String? = null) : Result()
    }

    /**
     * The set S of valueShapeRules rule 0: Unicode White_Space plus the zero-width and soft-hyphen code points.
     * All members are in the BMP, so removing UTF-16 units is exact.
     */
    private val WHITESPACE_SET_S: Set<Int> = buildSet {
        for (c in 0x0009..0x000D) add(c)
        add(0x0020); add(0x0085); add(0x00A0); add(0x1680)
        for (c in 0x2000..0x200A) add(c)
        add(0x2028); add(0x2029); add(0x202F); add(0x205F); add(0x3000)
        add(0xFEFF); add(0x200B); add(0x200C); add(0x200D); add(0x2060); add(0x00AD)
    }

    /** Removes every character of S (not only at the ends). Used before any comparison. */
    fun normalize(s: String): String {
        val sb = StringBuilder(s.length)
        for (ch in s) if (ch.code !in WHITESPACE_SET_S) sb.append(ch)
        return sb.toString()
    }

    /** Declared after [WHITESPACE_SET_S] and [normalize]: object properties initialize in declaration order. */
    private val FORBIDDEN_NORMALIZED: Set<String> = FORBIDDEN_KEYS.map { normalize(it).lowercase() }.toSet()

    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")
    private val HEX64_RE = Regex("^(0x)?[0-9a-fA-F]{64}$")
    private val PGP_PUBLIC_HEADER_NORMALIZED = normalize("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    /** Matched on the normalized string: "PRIVATE KEY BLOCK" with its whitespace removed. */
    private const val PRIVATE_BLOCK_MARK = "PRIVATEKEYBLOCK"
    /** Exact path `payload.nodes` is exempt from the 64-hex rule only. The key name itself is not normalized. */
    private const val NODES_KEY = "nodes"

    /**
     * Checks one request. Order (rule 5): key names, then "PRIVATEKEYBLOCK" in any string value (any depth), then
     * 64-hex values outside the exact path `payload.nodes`, then the public identity at the placement the
     * command requires.
     */
    fun validate(command: Command, body: JSONObject): Result {
        findForbiddenKey(body)?.let { return Result.Reject("key_over_bridge_refused", it) }
        findPrivateBlock(body, null)?.let { return Result.Reject("key_over_bridge_refused", it) }
        findHex64(body)?.let { return Result.Reject("key_over_bridge_refused", it) }
        val identity: JSONObject = when (command) {
            Command.PROVISION_IDENTITY -> body
            Command.INIT -> body.optJSONObject("identity") ?: return Result.Reject("missing_identity")
        }
        val rawEoa = identity.opt("eoa") ?: return Result.Reject("missing_identity")
        val eoa = normalize(rawEoa as? String ?: return Result.Reject("bad_identity"))
        if (!EOA_RE.matches(eoa)) return Result.Reject("bad_identity")
        val rawPgp = identity.opt("pgpPublicKeyArmored") ?: return Result.Reject("missing_identity")
        val pgp = normalize(rawPgp as? String ?: return Result.Reject("bad_identity"))
        if (!pgp.startsWith(PGP_PUBLIC_HEADER_NORMALIZED)) return Result.Reject("bad_identity")
        return Result.Accept(eoa)
    }

    /** `{ready, eoa}`. `ready` is true only when the native store holds this account's key, read back and checked. */
    fun readyResponse(eoa: String, state: NativeKeyState): JSONObject =
        JSONObject()
            .put("ready", state == NativeKeyState.HAS_KEY_READBACK_OK)
            .put("eoa", eoa)

    /** The key name as written in the input (raw, not normalized), if an object at any depth has a forbidden name. */
    private fun findForbiddenKey(node: Any?): String? = when (node) {
        is JSONObject -> node.keys().asSequence().firstNotNullOfOrNull { k ->
            if (normalize(k).lowercase() in FORBIDDEN_NORMALIZED) k else findForbiddenKey(node.opt(k))
        }
        is JSONArray -> (0 until node.length()).firstNotNullOfOrNull { findForbiddenKey(node.opt(it)) }
        else -> null
    }

    /**
     * The field that holds a string value whose normalized form contains "PRIVATEKEYBLOCK", at any depth. For an
     * array item, the field is the array's key. Only the field name is returned, never the value.
     */
    private fun findPrivateBlock(node: Any?, parentKey: String?): String? = when (node) {
        is JSONObject -> node.keys().asSequence().firstNotNullOfOrNull { k -> findPrivateBlock(node.opt(k), k) }
        is JSONArray -> (0 until node.length()).firstNotNullOfOrNull { findPrivateBlock(node.opt(it), parentKey) }
        is String -> if (normalize(node).uppercase().contains(PRIVATE_BLOCK_MARK)) parentKey ?: "" else null
        else -> null
    }

    /**
     * The field that holds a normalized string that matches 64 hex digits. The exemption is the exact path
     * `payload.nodes` only: a root key named `nodes` and its subtree. Nested `nodes` keys are not exempt.
     * For an array item, the field is the array's key. Only the field name is returned, never the value.
     */
    private fun findHex64(root: JSONObject): String? = root.keys().asSequence().firstNotNullOfOrNull { k ->
        hex64Under(root.opt(k), k, exempt = k == NODES_KEY)
    }

    private fun hex64Under(node: Any?, parentKey: String?, exempt: Boolean): String? = when (node) {
        is JSONObject -> node.keys().asSequence().firstNotNullOfOrNull { k -> hex64Under(node.opt(k), k, exempt) }
        is JSONArray -> (0 until node.length()).firstNotNullOfOrNull { hex64Under(node.opt(it), parentKey, exempt) }
        is String -> if (!exempt && HEX64_RE.matches(normalize(node))) parentKey ?: "" else null
        else -> null
    }
}
