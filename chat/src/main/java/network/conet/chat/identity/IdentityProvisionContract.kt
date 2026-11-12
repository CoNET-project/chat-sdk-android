package network.conet.chat.identity

import org.json.JSONArray
import org.json.JSONObject

/**
 * identity.native-keys.v1: request checks and ready report (spec r3b 25.19, vectors batch 17
 * `spec/identity-native-keys-vectors.v1.json`, sha256 0dea5599…).
 *
 * Pure logic. The native side supplies a [NativeKeyState] from its own key store, and production
 * readback must be verified before it reports [NativeKeyState.HAS_KEY_READBACK_OK].
 *
 * NOT wired into `provisionIdentity` or `init` yet. The capability is not declared in hello until
 * both platforms pass the vectors and the native store exists (spec 12.3, 25.19.3). Until then the
 * legacy payload path is unchanged.
 */
object IdentityProvisionContract {
    /** Keys that must never cross the bridge on this path, at any depth (vector `forbiddenKeys`). */
    val FORBIDDEN_KEYS: List<String> = listOf(
        "privateKeyHex",
        "walletPrivateKey",
        "privateKeyArmor",
        "pgpPrivateKeyArmored",
        "pgpPassphrase",
        "mnemonic",
    )

    /** Only these keys may appear in the response (vector `responseShape.allowedKeys`). */
    val RESPONSE_KEYS: Set<String> = setOf("ready", "eoa")

    enum class NativeKeyState { HAS_KEY_READBACK_OK, NO_KEY, KEY_ADDRESS_MISMATCH }

    sealed class Result {
        data class Accept(val eoa: String) : Result()
        data class Reject(val error: String, val field: String? = null) : Result()
    }

    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")
    private const val PGP_PUBLIC_HEADER = "-----BEGIN PGP PUBLIC KEY BLOCK-----"

    /** Checks the request. Forbidden keys are refused first, at any depth; then eoa; then the PGP public armor. */
    fun validate(body: JSONObject): Result {
        findForbidden(body)?.let { return Result.Reject("key_over_bridge_refused", it) }
        val rawEoa = body.opt("eoa") ?: return Result.Reject("missing_identity")
        val eoa = rawEoa as? String ?: return Result.Reject("bad_identity")
        if (!EOA_RE.matches(eoa)) return Result.Reject("bad_identity")
        val rawPgp = body.opt("pgpPublicKeyArmored") ?: return Result.Reject("missing_identity")
        val pgp = rawPgp as? String ?: return Result.Reject("bad_identity")
        if (!pgp.trimStart().startsWith(PGP_PUBLIC_HEADER)) return Result.Reject("bad_identity")
        return Result.Accept(eoa)
    }

    /** `{ready, eoa}`. `ready` is true only when the native store holds this account's key, read back and checked. */
    fun readyResponse(eoa: String, state: NativeKeyState): JSONObject =
        JSONObject()
            .put("ready", state == NativeKeyState.HAS_KEY_READBACK_OK)
            .put("eoa", eoa)

    private fun findForbidden(node: Any?): String? = when (node) {
        is JSONObject -> node.keys().asSequence().firstNotNullOfOrNull { k ->
            if (k in FORBIDDEN_KEYS) k else findForbidden(node.opt(k))
        }
        is JSONArray -> (0 until node.length()).firstNotNullOfOrNull { findForbidden(node.opt(it)) }
        else -> null
    }
}
