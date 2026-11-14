package network.conet.chat.identity

import org.json.JSONArray
import org.json.JSONObject
import java.text.Normalizer

/**
 * identity.native-keys.v1: request checks and ready report (spec r3b 25.19.2, batch 24 vectors
 * `spec/identity-native-keys-vectors.v1.json`, sha256 7aa7b4db…). Batch 24 is the last change to the character set.
 *
 * Field placement: `provisionIdentity` carries the public fields flat in the payload; `init` carries
 * them under `payload.identity`, never at the top level of `init`.
 *
 * Canonical form N (valueShapeRules rule 0, batch 23): NFKC first, then every character of the set S is removed,
 * not only leading and trailing ones. S is Unicode White_Space plus U+FEFF, U+200B–U+200D, U+2060 and U+00AD.
 * N is used for detection only. No platform trim() is used.
 *
 * eoa must be canonical: the raw value equals N(raw) and is lowercase 0x plus 40 lowercase hex digits.
 * Anything else is bad_identity, and nothing is stripped and accepted.
 *
 * PGP public armor: the header is detected on N(text). The stored value is never rewritten, and its raw
 * characters may not include S beyond space, tab, CR and LF.
 *
 * I-4: a normalized key name is matched case-insensitively at any depth. A normalized string value that
 * contains "PRIVATEKEYBLOCK" is refused at any depth, `payload.nodes` included. A normalized string that
 * matches 64 hex digits (optional 0x) is refused everywhere except the exact path `payload.nodes`. Only the
 * field name is reported, never the value.
 *
 * Pure logic. The native side supplies a [NativeKeyState] from its own key store, and production
 * readback must be verified before it reports [NativeKeyState.HAS_KEY_READBACK_OK].
 *
 * Wired into `provisionIdentity`: its ready report comes from the native vault state, which is
 * `Ready` only after readback (NativeWalletVault). The capability is NOT declared in hello yet: the
 * declaration waits for the conditions of spec 25.37.4 (vectors on both platforms, commands, audit,
 * device evidence), and until then the legacy payload path stays in place (spec 12.3, 25.19.3).
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

    /**
     * Canonical form N (batch 24): NFKD first (decomposes, so combining marks separate from their base letters;
     * fullwidth and compatibility characters map to ASCII), then every character of S is removed, then every
     * character whose general category is Mn, Me or Cf is removed. Used for detection only, never to rewrite a
     * stored value. NFKC is not used: it would recompose "E" + U+0301 into "É" and let the mark escape removal.
     */
    fun normalize(s: String): String {
        val nfkd = Normalizer.normalize(s, Normalizer.Form.NFKD)
        val noWhitespace = StringBuilder(nfkd.length)
        for (ch in nfkd) if (ch.code !in WHITESPACE_SET_S) noWhitespace.append(ch)
        val out = StringBuilder(noWhitespace.length)
        var i = 0
        while (i < noWhitespace.length) {
            val cp = noWhitespace.codePointAt(i)
            val category = Character.getType(cp).toByte()
            if (category != Character.NON_SPACING_MARK && category != Character.ENCLOSING_MARK && category != Character.FORMAT) {
                out.appendCodePoint(cp)
            }
            i += Character.charCount(cp)
        }
        return out.toString()
    }

    /** Key names after normalization may contain only ASCII letters, digits and underscore (batch 24). */
    private val KEY_NAME_RE = Regex("^[A-Za-z0-9_]+$")

    /** Characters of S that a PGP public armor value may still contain: space, tab, CR, LF (batch 23). */
    private val PGP_ALLOWED_S: Set<Int> = setOf(0x20, 0x09, 0x0D, 0x0A)

    /** Declared after [WHITESPACE_SET_S] and [normalize]: object properties initialize in declaration order. */
    private val FORBIDDEN_NORMALIZED: Set<String> = FORBIDDEN_KEYS.map { normalize(it).lowercase() }.toSet()

    private val EOA_RE = Regex("^0x[0-9a-f]{40}$")
    /** Batch 23: the prefix is 0x or 0X, and the match runs on the canonical form N. */
    private val HEX64_RE = Regex("^(0[xX])?[0-9a-fA-F]{64}$")
    private val PGP_PUBLIC_HEADER_NORMALIZED = normalize("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    /** Matched on the normalized string: "PRIVATE KEY BLOCK" with its whitespace removed. */
    private const val PRIVATE_BLOCK_MARK = "PRIVATEKEYBLOCK"
    /** Exact path `payload.nodes` is exempt from the 64-hex rule only. The key name itself is not normalized. */
    private const val NODES_KEY = "nodes"

    /**
     * A PGP public armor in the form the production save accepts (§25.48.4, r3ag): its raw characters may not include S beyond
     * space, tab, CR and LF, and the header is detected on N(text). The value is only checked, never rewritten.
     */
    internal fun isPublicArmor(raw: String): Boolean =
        raw.none { it.code in WHITESPACE_SET_S && it.code !in PGP_ALLOWED_S } &&
            normalize(raw).startsWith(PGP_PUBLIC_HEADER_NORMALIZED)

    /**
     * Checks one request. Order (rule 5): key names, then "PRIVATEKEYBLOCK" in any string value (any depth), then
     * 64-hex values outside the exact path `payload.nodes`, then the public identity at the placement the
     * command requires.
     */
    fun validate(command: Command, body: JSONObject): Result {
        findForbiddenKey(body)?.let { return Result.Reject("key_over_bridge_refused", it) }
        findPrivateBlock(body, null)?.let { return Result.Reject("key_over_bridge_refused", it) }
        findHex64(body)?.let { return Result.Reject("key_over_bridge_refused", it) }
        findBadKeyName(body)?.let { return Result.Reject("bad_identity", it) }
        val identity: JSONObject = when (command) {
            Command.PROVISION_IDENTITY -> body
            Command.INIT -> body.optJSONObject("identity") ?: return Result.Reject("missing_identity")
        }
        // eoa must already be canonical (batch 23): the raw value equals N(raw) and is lowercase 0x + 40 hex.
        // Nothing is stripped and accepted.
        val rawEoa = identity.opt("eoa") ?: return Result.Reject("missing_identity")
        val eoa = rawEoa as? String ?: return Result.Reject("bad_identity")
        if (eoa != normalize(eoa) || !EOA_RE.matches(eoa)) return Result.Reject("bad_identity")
        // The PGP public key is optional here. A recovered wallet has none until pgpRestore (§25.30.2), and G2 needs only the
        // EOA (§25.26.4c). When it is present it must be a public armor: the stored value is never rewritten, its raw
        // characters may not include S beyond space, tab, CR and LF, and the header is detected on N(text).
        identity.opt("pgpPublicKeyArmored")?.let { rawPgp ->
            val pgpRaw = rawPgp as? String ?: return Result.Reject("bad_identity")
            if (!isPublicArmor(pgpRaw)) return Result.Reject("bad_identity")
        }
        // The route public key is optional too (r3aj, §25.30.2, §25.48.10): an omitted key is absent, never an empty string.
        // When present, it must be PGP public armor, under the name the PWA sends and under the legacy alias.
        for (name in listOf("ownRouteArmoredPublicKey", "routePublicKeyArmored")) {
            identity.opt(name)?.let { rawRoute ->
                val routeRaw = rawRoute as? String ?: return Result.Reject("bad_identity")
                if (!isPublicArmor(routeRaw)) return Result.Reject("bad_identity")
            }
        }
        return Result.Accept(eoa)
    }

    /** `{ready, eoa}`. `ready` is true only when the native store holds this account's key, read back and checked. */
    fun readyResponse(eoa: String, state: NativeKeyState): JSONObject =
        JSONObject()
            .put("ready", state == NativeKeyState.HAS_KEY_READBACK_OK)
            .put("eoa", eoa)

    /**
     * The state the reply reports, from the native wallet vault. [vaultEoa] is the account of a record that passed
     * readback, or null when there is no such record (no key, or a locked one). Only a record for [requestedEoa] is
     * HAS_KEY_READBACK_OK; a record for another account is a mismatch. Anything else fails closed as NO_KEY.
     */
    fun nativeKeyState(vaultEoa: String?, requestedEoa: String): NativeKeyState = when {
        vaultEoa == null -> NativeKeyState.NO_KEY
        vaultEoa.equals(requestedEoa, ignoreCase = true) -> NativeKeyState.HAS_KEY_READBACK_OK
        else -> NativeKeyState.KEY_ADDRESS_MISMATCH
    }

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

    /**
     * The first key name, at any depth and in any position including `payload.nodes`, that is not canonical or
     * is not made only of ASCII letters, digits and underscore after normalization. The raw name is returned.
     */
    private fun findBadKeyName(node: Any?): String? = when (node) {
        is JSONObject -> node.keys().asSequence().firstNotNullOfOrNull { k ->
            val n = normalize(k)
            if (k != n || !KEY_NAME_RE.matches(n)) k else findBadKeyName(node.opt(k))
        }
        is JSONArray -> (0 until node.length()).firstNotNullOfOrNull { findBadKeyName(node.opt(it)) }
        else -> null
    }
}
