package network.conet.chat.nativekey

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import network.conet.chat.identity.IdentityProvisionContract
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The page-record bridge of the native layer (spec r3bg §25.52G, §25.52H, §25.52I, §25.52J, §25.52K; Android SDK per PM R389).
 *
 * The page keeps its wallet copy here. The page's commands are `shellRecordRead` and `shellRecordWrite`. The migration state is a native
 * read-only query (§25.52L.6), not a page command.
 * The copy is an encrypted native store (§25.52F.3). A read carries the W fields (the EOA private key and the mnemonic) and strips the
 * PGP fields (§25.52I.2). The first copy comes from the legacy wallet record at the first start (§25.52K). Nothing here logs record content.
 */
enum class ShellOrigin {
    /** The embedded page, as the shell's origin check (§25.52D.5) verified it. */
    EMBEDDED_PAGE,

    /** Any other origin: refused with `origin_refused`. */
    OTHER,
}

/**
 * The shell's reader output for the legacy wallet store (§25.52K.7). `absent` and `empty` are the only confirmed-absent states. The
 * found record has its PGP fields removed by the reader; the bytes are zero-filled after use.
 */
sealed class LegacyWalletRecord {
    /** Confirmed absent, or empty: the one state in which a read may answer `absent` (§25.52K.4). */
    object Absent : LegacyWalletRecord()

    /** Temporarily unreadable, with a reason code. Nothing is imported and no new wallet is made (§25.52K.3). */
    class Unreadable(val reason: String) : LegacyWalletRecord()

    /** The wallet record as UTF-8 JSON, PGP fields removed. */
    class Found(val record: ByteArray) : LegacyWalletRecord()
}

/** The result of the first-run import (§25.52K.6). [wire] is the code the shell logs. */
enum class ShellImportCode(val wire: String) {
    IMPORT_OK("import_ok"),
    EXISTS("exists"),
    ABSENT("absent"),
    LEGACY_UNREADABLE("legacy_unreadable"),
    IMPORT_FAILED("import_failed"),
    ADDRESS_MISMATCH("address_mismatch"),

    /** An account that is not a canonical EOA: no profile can match it, so nothing is read or written (R444, fail closed). */
    ACCOUNT_MISMATCH("account_mismatch"),
}

/** What the import has established for the page store, read by the bridge (§25.52K.4). `null` means the import has not run. */
internal enum class ImportOutcome {
    ABSENT,
    LEGACY_UNREADABLE,

    /** The legacy record was found and its import did not finish (§25.52K.5): the only case of `import_not_done`. */
    NOT_DONE,
    DONE,

    /** The account is not a canonical EOA: the legacy store is not read; reads answer account_mismatch, writes wait (R444). */
    ACCOUNT_MISMATCH,
}

/** The wallet-field merge (§25.52H.2): the merged record, the conflicting paths (sorted) and the reason when there is a conflict. */
internal data class WalletMerge(val record: JSONObject, val names: List<String>, val reason: String?)

/** Byte order of UTF-8 strings (§25.52N.9.2): the order of `names` and of the canonical keys. */
internal val UTF8_ORDER: Comparator<String> = Comparator { a, b ->
    val x = a.toByteArray(Charsets.UTF_8)
    val y = b.toByteArray(Charsets.UTF_8)
    for (i in 0 until minOf(x.size, y.size)) {
        val d = (x[i].toInt() and 0xff) - (y[i].toInt() and 0xff)
        if (d != 0) return@Comparator d
    }
    x.size - y.size
}

/**
 * The canonical JSON of a page copy (§25.52M.4, tentative; vectors CJ-01, CJ-02): UTF-8, object keys in UTF-8 byte order, no whitespace,
 * array order kept, strings escaped by the JSON rules. The stored plaintext is this byte string.
 */
internal object CanonicalJson {
    fun encode(value: Any?): String = StringBuilder().also { write(value, it) }.toString()

    private fun write(value: Any?, out: StringBuilder) {
        when (value) {
            null, JSONObject.NULL -> out.append("null")
            is JSONObject -> {
                out.append('{')
                val keys = value.keys().asSequence().map { it.toString() }.sortedWith(UTF8_ORDER)
                keys.forEachIndexed { i, k ->
                    if (i > 0) out.append(',')
                    quote(k, out)
                    out.append(':')
                    write(value.opt(k), out)
                }
                out.append('}')
            }
            is JSONArray -> {
                out.append('[')
                for (i in 0 until value.length()) {
                    if (i > 0) out.append(',')
                    write(value.opt(i), out)
                }
                out.append(']')
            }
            is String -> quote(value, out)
            is Boolean, is Number -> out.append(value.toString())
            else -> quote(value.toString(), out)
        }
    }

    private fun quote(s: String, out: StringBuilder) {
        out.append('"')
        for (c in s) {
            when (c) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                '\b' -> out.append("\\b")
                '\u000c' -> out.append("\\f")
                else -> if (c < ' ') out.append(String.format("\\u%04x", c.code)) else out.append(c)
            }
        }
        out.append('"')
    }
}

/** The rules of §25.52N to §25.52S: the W paths, the PGP paths, the whitelist, the key-shape scan, the merge and the strip. */
internal object ShellRecordPolicy {
    /** A request and a response are each at most 2 MB, in UTF-8 bytes (§25.52D.5, §25.52L.10). */
    const val MAX_BYTES = 2 * 1024 * 1024

    /** The bridge response schema (§25.52D.6). The record's own `schemaVersion` is separate. */
    const val RESPONSE_SCHEMA = 1

    /** The record schema that may hold W fields (§25.52F.5). Older pages get `wallet_copy_not_approved`. */
    const val WALLET_SCHEMA_MIN = 2

    const val PGP_HEADER = "BEGIN PGP PRIVATE KEY"

    /** §25.52N.3: the W path of the account's profile. */
    const val W_PROFILE_PATH = "profiles[*].privateKeyArmor"

    /** §25.52N.5: PGP private paths, refused with `pgp_private_in_payload` and the path names. */
    val FORBIDDEN_PATHS: Set<String> = setOf(
        "profiles[*].chatManager.pgpKey.privateKey",
        "profiles[*].chatManager.pgpKey.privateKeyArmor",
        "profiles[*].chatManager.pgpKey.privateKeyArmorWrap",
        "profiles[*].pgpKey.privateKeyArmor",
        "profiles[*].pgpKey.privateKeyArmorWrap",
        "pgpPassphrase",
        "profiles[*].chats[*].chatData.privateArmored",
    )

    /** §25.52N.5, §25.52P.5, §25.52Q.3, §25.52R.3: PGP public paths. A write is `bad_request` with the names; the page refuses to send them. */
    val PGP_PUBLIC_PATHS: Set<String> = setOf(
        "profiles[*].chatManager.pgpKey.publicKey",
        "profiles[*].chatManager.pgpKey.keyID",
        "profiles[*].chatManager.pgpKey.routes",
        "profiles[*].pgpKey.publicKeyArmor",
        "profiles[*].pgpKey.publicKeyObj",
        "beamio.pgpPublicKeyArmor",
        "beamio.pgpPublicKeyID",
        "profiles[*].chats[*].chatData.publicArmored",
        "profiles[*].chats[*].chatData.routePgpKeyID",
        "profiles[*].chats[*].chatData.routersArmoreds",
    )

    /** §25.52N.5, §25.52S.2: removed from a read copy and from a first import. The whole `chatManager.pgpKey` and `pgpKey` go. */
    private val PGP_STRIP_PATHS: List<String> = listOf(
        "profiles[*].chatManager.pgpKey",
        "profiles[*].pgpKey",
        "pgpPassphrase",
        "profiles[*].chats[*].chatData.privateArmored",
    ) + PGP_PUBLIC_PATHS.toList()

    /** §25.52N.3, §25.52P.2, §25.52R.2: the W paths. Held only in a record of [WALLET_SCHEMA_MIN] or later. */
    val WALLET_PATHS: Set<String> = setOf(W_PROFILE_PATH, "mnemonicPhrase", "recoveryWords")

    /** §25.52N.3: the W paths are the only exemptions from the key-shape scan. */
    val W_EXACT_PATHS: Set<String> = WALLET_PATHS

    /** §25.52M.2, §25.52S.4: removed at the unregister. The retired names are removed too. */
    private val WALLET_REMOVAL_PATHS: List<String> = listOf(W_PROFILE_PATH, "mnemonicPhrase", "recoveryWords", "mnemonic", "walletVault.mnemonic")

    /** §25.52O.2: key names shaped like secret material, beside the prefixes of [isKeyShaped]. */
    private val KEY_SHAPED_EXACT: Set<String> = setOf(
        "seed", "walletPrivateKey", "recoveryCode", "recoveryPhrase", "recoveryWords", "duplicatePassword", "duplicateMnemonicPhrase",
        "_duplicateCode",
    )

    /** The whitelist as a tree (§25.52N.4, §25.52O.2, §25.52Q.3). Leaves are scalars; subtrees are containers; the rest is exact. */
    private sealed class Rule
    private object Leaf : Rule()
    private object Subtree : Rule()
    private class Exact(val keys: Map<String, Rule>) : Rule()
    private class Each(val item: Rule) : Rule()

    private val LEAF: Rule = Leaf
    private val SUBTREE: Rule = Subtree

    private val BEAMIO_KEYS = listOf(
        "accountName", "image", "darkTheme", "isUSDCFaucet", "isETHFaucet", "initialLoading", "firstName", "lastName", "createdAt",
        "language", "currency", "address", "payme", "tax", "localeCurrencyConfigured",
    )
    private val PROFILE_LEAVES = listOf(
        "isPrimary", "emailAddr", "hdPath", "index", "isNode", "referrer", "nodeID", "nodeIP_address", "nodeRegion", "vpnTimeUsedInMin",
        "webFilter", "aaAccount", "keyID", "type", "publicKeyArmor", "privateKeyArmor",
    )
    private val PROFILE_SUBTREES = listOf(
        "tokens", "spClub", "SpClubPoints", "spChannel", "airdropEvent", "data", "activePassport", "silentPassPassports", "chats",
        "phoneCalls", "issuedCards",
    )
    private val ROOT_LEAVES = listOf("schemaVersion", "rev", "isReady", "ver", "nonce", "upgradev2", "webFilter", "mnemonicPhrase", "recoveryWords")
    private val ROOT_SUBTREES = listOf("preferences", "fx168Order", "cardRedeems", "ChannelPartners", "referrals", "fragmentClass", "search")

    private val PROFILE_RULE: Rule = Exact(
        PROFILE_LEAVES.associateWith { LEAF } + PROFILE_SUBTREES.associateWith { SUBTREE } +
            mapOf("chatManager" to Exact(mapOf("router" to LEAF))),
    )
    private val ROOT_RULE: Rule = Exact(
        ROOT_LEAVES.associateWith { LEAF } + ROOT_SUBTREES.associateWith { SUBTREE } + mapOf(
            "beamio" to Exact(BEAMIO_KEYS.associateWith { LEAF }),
            "profiles" to Each(PROFILE_RULE),
        ),
    )

    val READ_FIELDS: Set<String> = setOf("type", "reqId")
    val WRITE_FIELDS: Set<String> = setOf("type", "reqId", "record")

    /** The reqId rule of §25.28.3: a string of 1 to 64 printable ASCII bytes, or an integer from 0 to 2^53 - 1. */
    fun reqIdValid(value: Any?): Boolean = when (value) {
        is String -> value.isNotEmpty() && value.length <= 64 && value.all { it.code in 0x20..0x7E }
        is Int -> value >= 0
        is Long -> value in 0..((1L shl 53) - 1)
        else -> false
    }

    /**
     * §25.52BB.3: a legacy private key in the read form of Q1. The 64 hex digits may carry "0x" or "0X" and may be in either case; the result is
     * "0x" plus 64 lower-case hex digits. `null` when the value is not 64 hex digits, so the import is import_failed.
     */
    fun normalizeLegacyKey(value: String): String? {
        val hex = if (value.startsWith("0x") || value.startsWith("0X")) value.substring(2) else value
        return if (HEX_KEY.matches(hex)) "0x" + hex.lowercase() else null
    }

    /** Every path of [value], with `[*]` for array elements, as §25.52D.7 writes them. */
    fun pathsOf(value: Any?, path: String = "", out: MutableSet<String> = mutableSetOf()): Set<String> {
        when (value) {
            is JSONObject -> for (key in keysOf(value)) {
                val p = if (path.isEmpty()) key else "$path.$key"
                out += p
                pathsOf(value.opt(key), p, out)
            }
            is JSONArray -> for (i in 0 until value.length()) pathsOf(value.opt(i), "$path[*]", out)
        }
        return out
    }

    /**
     * True when any string value, at any depth, holds the PGP private key header (§25.52D.7 step 5). Values only. The test is on a canonical
     * form (letters and digits, upper case), so spacing, punctuation and letter case do not hide the header (F2 condition 3).
     */
    fun hasPgpHeader(value: Any?): Boolean = when (value) {
        is String -> canonicalText(value).contains(CANONICAL_PGP_HEADER)
        is JSONObject -> keysOf(value).any { hasPgpHeader(value.opt(it)) }
        is JSONArray -> (0 until value.length()).any { hasPgpHeader(value.opt(it)) }
        else -> false
    }

    /**
     * The canonical form of §25.19.2 N (NFKD, then S, Mn, Me and Cf removed; the same function the identity contract uses), then letters and digits
     * only, in upper case. Full-width letters, compatibility forms, combining marks and zero-width characters do not hide a header (F2 condition 3).
     */
    private fun canonicalText(value: String): String =
        IdentityProvisionContract.normalize(value).filter { it.isLetterOrDigit() }.uppercase()

    private val CANONICAL_PGP_HEADER: String = canonicalText(PGP_HEADER)

    /** The form the page writes a private key in: `0x` and 64 lower-case hex digits (§25.52N.9 Q1). */
    private val CANONICAL_KEY_ARMOR = Regex("0x[0-9a-f]{64}")

    private val HEX_KEY = Regex("[0-9a-fA-F]{64}")

    /**
     * The EOA address of a private-key string (`0x` optional, then 64 hex digits), lower case, or `null`. Only hex digits are accepted, so a sign
     * or other character cannot stand in for a digit. The key bytes are zero-filled after use.
     */
    fun addressOfArmor(armor: String): String? {
        val hex = armor.removePrefix("0x")
        if (!HEX_KEY.matches(hex)) return null
        val key = ByteArray(32) { i -> hex.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
        try {
            return WalletAddress.fromPrivateKey(key)
        } finally {
            key.fill(0)
        }
    }

    /**
     * The W-class type check (§25.52AF.3 rules 1 and 4, r3cd): a value of `mnemonicPhrase`, `recoveryWords` or a profile's `privateKeyArmor` that
     * is an object or an array is refused (`bad_request`, names the path, nothing echoed or stored). Scalars, including null, are not refused here:
     * they follow the current W merge rules (§25.52H.2, §25.52R.2). A wrapper object (the 0.53.x device-key form) is an array or an object, so it is
     * refused. Returns the failing path names, sorted; empty when all pass. The key-shape scan runs before this check (AF.3 rule 3).
     */
    fun walletTypeRefusal(record: JSONObject): List<String> {
        fun objectOrArray(value: Any?): Boolean = value is JSONObject || value is JSONArray
        val names = sortedSetOf<String>()
        for (key in listOf("mnemonicPhrase", "recoveryWords")) {
            if (objectOrArray(record.opt(key))) names += key
        }
        record.optJSONArray("profiles")?.let { profiles ->
            for (i in 0 until profiles.length()) {
                val profile = profiles.optJSONObject(i) ?: continue
                if (objectOrArray(profile.opt("privateKeyArmor"))) names += W_PROFILE_PATH
            }
        }
        return names.toList()
    }

    /**
     * The form check on write (§25.52N.9 Q1, F2 condition 4), for the profile whose keyID is the account only (the exact W path, 25.52N.3). A
     * `privateKeyArmor` that is a string must be the canonical form (`0x` and 64 lower-case hex digits) and must derive that keyID. Otherwise
     * bad_request, naming the path, nothing echoed. A null or a non-string scalar is not judged here (25.52AF.3 rule 4). Without a known account the
     * check does not apply.
     */
    fun walletFormRefusal(record: JSONObject, account: String): List<String> {
        if (account.isEmpty()) return emptyList()
        val names = sortedSetOf<String>()
        record.optJSONArray("profiles")?.let { profiles ->
            for (i in 0 until profiles.length()) {
                val profile = profiles.optJSONObject(i) ?: continue
                val keyId = profile.optString("keyID", "")
                if (!keyId.equals(account, ignoreCase = true)) continue
                val armor = profile.opt("privateKeyArmor")
                if (armor !is String) continue
                val valid = CANONICAL_KEY_ARMOR.matches(armor) && addressOfArmor(armor)?.equals(keyId, ignoreCase = true) == true
                if (!valid) names += W_PROFILE_PATH
            }
        }
        return names.toList()
    }

    /**
     * 25.52AG.2 (r3ch, r3cj): a profile whose keyID is not the account, and which carries a `privateKeyArmor` (a null value included: the key is
     * present), is a conflict with reason `w_account_unmatched`. The names are the W path. Nothing is written, and no value is echoed. This applies to
     * native writes too (it is not the merge's rule). Without a known account it does not apply.
     */
    fun walletAccountMismatch(record: JSONObject, account: String): List<String> {
        if (account.isEmpty()) return emptyList()
        var mismatch = false
        record.optJSONArray("profiles")?.let { profiles ->
            for (i in 0 until profiles.length()) {
                val profile = profiles.optJSONObject(i) ?: continue
                if (!profile.optString("keyID", "").equals(account, ignoreCase = true) && profile.has("privateKeyArmor")) mismatch = true
            }
        }
        return if (mismatch) listOf(W_PROFILE_PATH) else emptyList()
    }

    /** True for a key name of §25.52O.2: `privateKey*`, `mnemonic*`, `pgpPassphrase*`, `pgpPrivate*`, `duplicateCode*`, or an exact name. */
    fun isKeyShaped(key: String): Boolean =
        key.startsWith("privateKey") || key.startsWith("mnemonic") || key.startsWith("pgpPassphrase") ||
            key.startsWith("pgpPrivate") || key.startsWith("duplicateCode") || key in KEY_SHAPED_EXACT

    /** The key-shaped paths outside the W paths, sorted in UTF-8 byte order (§25.52N.4, §25.52O.5). */
    fun keyShapedIn(record: JSONObject): List<String> =
        pathsOf(record).filter { it !in W_EXACT_PATHS && isKeyShaped(it.substringAfterLast('.')) }.sortedWith(UTF8_ORDER)

    /** The forbidden PGP private paths present in [record], sorted (§25.52N.5). */
    fun forbiddenIn(record: JSONObject): List<String> = pathsOf(record).filter { it in FORBIDDEN_PATHS }.sortedWith(UTF8_ORDER)

    /** The PGP public paths present in [record], sorted (§25.52N.5, §25.52Q.3). */
    fun pgpPublicIn(record: JSONObject): List<String> = pathsOf(record).filter { it in PGP_PUBLIC_PATHS }.sortedWith(UTF8_ORDER)

    /** The W paths present in [record], sorted (§25.52N.3). */
    fun walletIn(record: JSONObject): List<String> = pathsOf(record).filter { it in WALLET_PATHS }.sortedWith(UTF8_ORDER)

    /**
     * The native pre-write check (§25.52E.5, §25.52O.5 step 2): a PGP header or a forbidden PGP private path refuses the write as
     * `pgp_private_in_payload`. The header refusal carries no names. Returns the code and the names, or `null` when clean.
     */
    fun preWriteRefusal(record: JSONObject): Pair<String, List<String>>? {
        if (hasPgpHeader(record)) return "pgp_private_in_payload" to emptyList()
        val names = (forbiddenIn(record) + profilePgpKeyIn(record)).distinct().sortedWith(UTF8_ORDER)
        return if (names.isEmpty()) null else "pgp_private_in_payload" to names
    }

    /**
     * §25.52N.5 and §25.52B.5: a profile-level `pgpKey` is a private path, `profiles[*].pgpKey.*`, except the listed PGP public paths. The name is the
     * leaf path that carries the value (25.52BG.1; vector PR-04 is `profiles[*].pgpKey.publicKey`).
     */
    fun profilePgpKeyIn(record: JSONObject): List<String> {
        val all = pathsOf(record)
        // Leaves only (25.52BG.1): a container path such as profiles[*].pgpKey is not named when a leaf below it is.
        val children = all.filter { it.startsWith("profiles[*].pgpKey.") && it !in PGP_PUBLIC_PATHS }
        val leaves = children.filter { c -> children.none { it != c && it.startsWith("$c.") } }
        val bare = if (children.isEmpty() && "profiles[*].pgpKey" in all) listOf("profiles[*].pgpKey") else emptyList()
        return (leaves + bare).distinct()
    }

    /**
     * The whitelist violations of [record] (§25.52O.5, §25.52Q.3), sorted in UTF-8 byte order: the leaf paths outside the whitelist (an empty
     * object or array outside it is a leaf), and the PGP public paths. Values are never named.
     */
    fun whitelistViolations(record: JSONObject): List<String> {
        val out = mutableSetOf<String>()
        walk(record, ROOT_RULE, "", out)
        out += pgpPublicIn(record)
        return out.sortedWith(UTF8_ORDER)
    }

    private fun walk(value: Any?, rule: Rule, path: String, out: MutableSet<String>) {
        when (rule) {
            is Leaf, is Subtree -> Unit
            is Exact -> {
                if (value !is JSONObject) {
                    out += path
                    return
                }
                for (key in keysOf(value)) {
                    val childPath = if (path.isEmpty()) key else "$path.$key"
                    val child = value.opt(key)
                    val childRule = rule.keys[key]
                    if (childRule == null) reportAll(child, childPath, out) else walk(child, childRule, childPath, out)
                }
            }
            is Each -> {
                if (value !is JSONArray) {
                    out += path
                    return
                }
                for (i in 0 until value.length()) walk(value.opt(i), rule.item, "$path[*]", out)
            }
        }
    }

    private fun reportAll(value: Any?, path: String, out: MutableSet<String>) {
        when {
            value is JSONObject && value.length() > 0 -> for (key in keysOf(value)) reportAll(value.opt(key), "$path.$key", out)
            value is JSONArray && value.length() > 0 -> for (i in 0 until value.length()) reportAll(value.opt(i), "$path[*]", out)
            else -> out += path
        }
    }

    /** The read copy (§25.52S.2): removes the PGP fields in place, an emptied `chatManager` and an emptied `beamio`. The W fields stay. */
    fun stripPgpForRead(record: JSONObject) {
        for (path in PGP_STRIP_PATHS) removePath(record, path.split('.'))
        record.optJSONArray("profiles")?.let { profiles ->
            for (i in 0 until profiles.length()) {
                val profile = profiles.optJSONObject(i) ?: continue
                val chatManager = profile.optJSONObject("chatManager") ?: continue
                if (chatManager.length() == 0) profile.remove("chatManager")
            }
        }
        record.optJSONObject("beamio")?.let { if (it.length() == 0) record.remove("beamio") }
    }

    /** Removes the W fields (§25.52H.2 rule 5, §25.52M.2, §25.52S.4): the account's `privateKeyArmor`, `mnemonicPhrase`, `recoveryWords`. */
    fun removeWallet(record: JSONObject) {
        for (path in WALLET_REMOVAL_PATHS) removePath(record, path.split('.'))
        record.optJSONObject("walletVault")?.let { if (it.length() == 0) record.remove("walletVault") }
    }

    /** Removes the value at a path. A segment ending in `[*]` is an array whose elements are each searched. */
    private fun removePath(node: JSONObject, segments: List<String>) {
        val head = segments[0]
        val isArray = head.endsWith("[*]")
        val key = head.removeSuffix("[*]")
        if (segments.size == 1) {
            node.remove(key)
            return
        }
        if (isArray) {
            val array = node.optJSONArray(key) ?: return
            for (i in 0 until array.length()) array.optJSONObject(i)?.let { removePath(it, segments.drop(1)) }
        } else {
            node.optJSONObject(key)?.let { removePath(it, segments.drop(1)) }
        }
    }

    /** The keys of an object, in the order the object holds them. */
    fun keysOf(obj: JSONObject): List<String> = obj.keys().asSequence().map { it.toString() }.toList()

    /**
     * The account's record in `profiles` (§25.52B.6, §25.52L.5): the one whose `keyID` equals the account, compared without case. Several
     * matches give no slot, and nothing is guessed among profiles. Conditional fallback (PM R424, accepted with this documentation): while
     * no profile of the record carries a `keyID` at all, `profiles[0]` is the account's record, as §25.52B.6 has it "until confirmed". This
     * fallback is for the W placement only. The first-run import always matches by keyID (§25.52K.5). Android measurement must confirm the
     * keyID match before release; see docs/page-record-bridge.md.
     */
    fun accountSlot(record: JSONObject, eoa: String): Int? {
        val profiles = record.optJSONArray("profiles") ?: return null
        val ids = (0 until profiles.length()).map { profiles.optJSONObject(it)?.optString("keyID", "").orEmpty() }
        if (ids.none { it.isNotEmpty() }) return if (profiles.length() >= 1) 0 else null
        val matches = ids.indices.filter { ids[it].isNotEmpty() && ids[it].equals(eoa, ignoreCase = true) }
        return matches.singleOrNull()
    }

    /** The profiles whose `keyID` equals [eoa], compared without case (§25.52U.4). Nothing falls back to an index here. */
    fun matchingProfiles(record: JSONObject, eoa: String): List<JSONObject> {
        val profiles = record.optJSONArray("profiles") ?: return emptyList()
        return (0 until profiles.length()).mapNotNull { i ->
            profiles.optJSONObject(i)?.takeIf { p ->
                val id = p.optString("keyID", "")
                id.isNotEmpty() && id.equals(eoa, ignoreCase = true)
            }
        }
    }

    /**
     * The read judgement of a schema 2 record (§25.52S.3, §25.52U.4, R432): `account_mismatch` when no profile, or more than one, matches the
     * account (fail closed); `needs_native_recovery` when the matching profile has no `privateKeyArmor`; `null` when the record is usable.
     * A missing `mnemonicPhrase` does not matter (§25.52R.5).
     */
    fun accountJudgement(record: JSONObject, eoa: String): String? {
        val matches = matchingProfiles(record, eoa)
        return when {
            matches.size != 1 -> "account_mismatch"
            !matches[0].has("privateKeyArmor") -> "needs_native_recovery"
            else -> null
        }
    }

    /** True when a profile matching the account holds the EOA private key (§25.52P.4, §25.52U.4): the write rule. */
    fun accountHoldsEoaKey(record: JSONObject, eoa: String): Boolean = matchingProfiles(record, eoa).any { it.has("privateKeyArmor") }

    /** True when some profile of [record] holds [key]. */
    private fun hasProfileKey(record: JSONObject, key: String): Boolean {
        val profiles = record.optJSONArray("profiles") ?: return false
        return (0 until profiles.length()).any { profiles.optJSONObject(it)?.has(key) == true }
    }

    /**
     * The page's record merged with the stored wallet fields (§25.52H.2, §25.52H.3, §25.52L.5, §25.52N.3): an omitted W field keeps the
     * stored value; the same value is accepted; a different value, `null` included, is `w_differs`. A W field in a profile other than the
     * account's record is `w_account_unmatched`, and so is a stored W field the page does not place in the account's record, so an omission
     * cannot delete it. [replaceWallet] (native creation or recovery) replaces the stored W fields; the placement rule still holds. Non-W
     * fields come from the payload alone (§25.52S.5). Nothing is overwritten on a conflict.
     */
    fun mergeWallet(page: JSONObject, stored: JSONObject, eoa: String, replaceWallet: Boolean = false): WalletMerge {
        val out = JSONObject(page.toString())
        val differs = mutableSetOf<String>()
        val unmatched = mutableSetOf<String>()
        val pageSlot = accountSlot(page, eoa)
        val storedSlot = accountSlot(stored, eoa)

        page.optJSONArray("profiles")?.let { profiles ->
            for (i in 0 until profiles.length()) {
                if (profiles.optJSONObject(i)?.has("privateKeyArmor") == true && i != pageSlot) unmatched += W_PROFILE_PATH
            }
        }
        if (!replaceWallet) {
            for (key in listOf("mnemonicPhrase", "recoveryWords")) mergeKey(page, stored, out, key, key, differs)
            val storedProfile = storedSlot?.let { stored.optJSONArray("profiles")?.optJSONObject(it) }
            if (storedProfile != null && storedProfile.has("privateKeyArmor")) {
                if (pageSlot == null) {
                    unmatched += W_PROFILE_PATH
                } else {
                    val pageProfile = page.optJSONArray("profiles")?.optJSONObject(pageSlot)
                    mergeKey(
                        pageProfile,
                        storedProfile,
                        out.optJSONArray("profiles")?.optJSONObject(pageSlot),
                        "privateKeyArmor",
                        W_PROFILE_PATH,
                        differs,
                    )
                }
            } else if (storedSlot == null && hasProfileKey(stored, "privateKeyArmor")) {
                unmatched += W_PROFILE_PATH
            }
        }
        val names = (differs + unmatched).sortedWith(UTF8_ORDER)
        val reason = when {
            unmatched.isNotEmpty() -> "w_account_unmatched"
            differs.isNotEmpty() -> "w_differs"
            else -> null
        }
        return WalletMerge(out, names, reason)
    }

    private fun mergeKey(
        page: JSONObject?,
        stored: JSONObject,
        out: JSONObject?,
        key: String,
        name: String,
        conflicts: MutableSet<String>,
    ) {
        if (!stored.has(key) || out == null) return
        val value = stored.get(key)
        if (page == null || !page.has(key)) {
            out.put(key, value)
        } else if (!sameValue(page.get(key), value)) {
            conflicts += name
        }
    }

    private fun sameValue(a: Any?, b: Any?): Boolean = when {
        a == JSONObject.NULL || b == JSONObject.NULL -> a == b
        a is String && b is String -> a == b
        else -> a?.toString() == b?.toString()
    }
}

/**
 * The page store for one account: the whole record, W fields included, sealed with the non-exportable Keystore key (§25.52F.3). The file
 * is one version byte, then the AEAD output. The AAD is the account key (`eoa:default`, lower case) and the version byte. A file that does
 * not open is unreadable. There is no plaintext fallback.
 */
internal class SealedPageRecordStore(
    private val wrap: KeyWrap,
    private val files: VaultFiles,
    private val accountKey: String,
) {
    private val name = "page.v1.${accountKey.substringBefore(':').removePrefix("0x")}.${accountKey.substringAfter(':')}.rec"
    private val aad = accountKey.toByteArray(Charsets.UTF_8) + FORMAT_VERSION

    /** The stored record, or `null` when there is none. Throws [IOException] when present but unreadable. */
    fun read(): JSONObject? {
        val bytes = files.read(name) ?: return null
        if (bytes.size < MIN_FILE_BYTES || bytes[0] != FORMAT_VERSION[0]) throw IOException("page record is malformed")
        val plain = wrap.open(aad, bytes.copyOfRange(1, bytes.size)) ?: throw IOException("page record does not open")
        return try {
            JSONObject(String(plain, Charsets.UTF_8))
        } catch (_: Exception) {
            throw IOException("page record is malformed")
        } finally {
            plain.fill(0)
        }
    }

    /** Removes the sealed file of this account. Used when the copy cannot be read at the unregister (see [PageWalletRemoval]). */
    fun erase() = files.delete(name)

    /** Replaces the whole record in one step. Throws [IOException] on any failure, and the earlier record is unchanged. */
    fun write(record: JSONObject) {
        val plain = CanonicalJson.encode(record).toByteArray(Charsets.UTF_8)
        try {
            val sealed = try {
                wrap.seal(aad, plain)
            } catch (e: Exception) {
                throw IOException("page record cannot be sealed", e)
            }
            files.write(name, FORMAT_VERSION + sealed)
        } finally {
            plain.fill(0)
        }
    }

    companion object {
        /** The version byte (1), the nonce (12) and the GCM tag (16): a file is at least 29 bytes (§25.52L.2). */
        const val MIN_FILE_BYTES = 29
        private val FORMAT_VERSION = byteArrayOf(1)
    }
}

/**
 * The page copy's W fields as the unregister removes them (§25.52H.2 rule 5, §25.52J.3). Only the W fields go: the rest of the copy stays,
 * and the revision moves on, so a page that still holds an older copy gets `conflict` on its next write. A copy that cannot be read is
 * erased whole, since its W fields cannot be told apart from the rest.
 */
internal class PageWalletRemoval(private val store: SealedPageRecordStore) : MigrationWallet {
    override fun present(): Boolean = try {
        store.read()?.let { ShellRecordPolicy.walletIn(it).isNotEmpty() } ?: false
    } catch (_: IOException) {
        true
    }

    override fun remove() {
        val record: JSONObject = try {
            store.read() ?: return
        } catch (_: IOException) {
            store.erase()
            return
        }
        if (ShellRecordPolicy.walletIn(record).isEmpty()) return
        ShellRecordPolicy.removeWallet(record)
        record.put("rev", record.optInt("rev", 0) + 1)
        store.write(record)
    }
}

/**
 * Runs [block] with [flag] set, and restores the flag's earlier value afterwards, whatever the outcome. A shell that set the flag before a
 * call keeps it set after the call.
 */
internal fun <T> markingMigration(flag: AtomicBoolean, block: () -> T): T {
    val previous = flag.getAndSet(true)
    try {
        return block()
    } finally {
        flag.set(previous)
    }
}

/**
 * The device-level flags of the page-record bridge (§25.52T.4, §25.52T.5, R436): the account pointer, which says that this device has
 * established an account, and the marker of an unreadable legacy store. Both are non-secret and kept apart from the sealed copies.
 */
internal interface DeviceFlags {
    /** §25.52T.4: set by the first successful native write (the import or the native creation). Read and write never clear it. */
    fun accountPointer(): Boolean

    fun setAccountPointer()

    /**
     * The account this device has bound, kept across a cold start (R488): the lower-case EOA, a public value. Null when the address is missing or
     * malformed; the bridge then finds the account from the copy (§25.52AD.2).
     */
    fun accountAddress(): String?

    fun setAccountAddress(eoa: String)

    /** §25.52T.5: set when the legacy store is unreadable while no pointer and no record exist. */
    fun legacyUnreadable(): Boolean

    fun setLegacyUnreadable()

    fun clearLegacyUnreadable()
}

/** No flags: the pure bridge and the vectors' defaults. */
internal object NoDeviceFlags : DeviceFlags {
    override fun accountPointer(): Boolean = false

    override fun setAccountPointer() = Unit

    override fun accountAddress(): String? = null

    override fun setAccountAddress(eoa: String) = Unit

    override fun legacyUnreadable(): Boolean = false

    override fun setLegacyUnreadable() = Unit

    override fun clearLegacyUnreadable() = Unit
}

/**
 * The flags as one file each in the no-backup directory. A flag that cannot be read counts as set: the pointer then fails closed to
 * `account_record_missing`, and the marker to `legacy_store_unreadable`. The files hold one byte and no key material.
 */
internal class DeviceFlagFiles(private val files: VaultFiles) : DeviceFlags {
    override fun accountPointer(): Boolean = flag(POINTER)

    override fun setAccountPointer() = files.write(POINTER, byteArrayOf(1))

    override fun accountAddress(): String? = try {
        files.read(ADDRESS)?.toString(Charsets.UTF_8)?.takeIf { ShellRecordAccounts.isAddress(it) }
    } catch (_: Exception) {
        null
    }

    override fun setAccountAddress(eoa: String) = files.write(ADDRESS, eoa.lowercase().toByteArray(Charsets.UTF_8))

    override fun legacyUnreadable(): Boolean = flag(LEGACY)

    override fun setLegacyUnreadable() = files.write(LEGACY, byteArrayOf(1))

    override fun clearLegacyUnreadable() = files.delete(LEGACY)

    private fun flag(name: String): Boolean = try {
        files.read(name) != null
    } catch (_: Exception) {
        true
    }

    companion object {
        const val POINTER = "account_pointer.v1"
        const val ADDRESS = "account_address.v1"
        const val LEGACY = "legacy_store_unreadable.v1"
    }
}

/**
 * The flags after a first-run import (§25.52T.4, §25.52T.5, §25.52T.6): an unreadable legacy store sets the marker while no pointer exists;
 * a confirmed absence clears it; a successful import sets the pointer and clears the marker; an existing copy clears the marker.
 */
internal fun applyImportMarker(flags: DeviceFlags, code: ShellImportCode) {
    when (code) {
        ShellImportCode.LEGACY_UNREADABLE -> if (!flags.accountPointer()) flags.setLegacyUnreadable()
        ShellImportCode.ABSENT -> flags.clearLegacyUnreadable()
        ShellImportCode.IMPORT_OK -> {
            flags.setAccountPointer()
            flags.clearLegacyUnreadable()
        }
        ShellImportCode.EXISTS -> flags.clearLegacyUnreadable()
        else -> Unit
    }
}

/**
 * The Keystore key of the page store (§25.52F.3): AES-256-GCM, not exportable, randomized encryption required, StrongBox when available
 * and the TEE otherwise. Not verified on a device in this build: the Keystore behaviour is a device-acceptance item.
 */
class AndroidPageRecordKeyWrap(private val alias: String = KEY_ALIAS) : KeyWrap {
    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun existingKey(): SecretKey? = keyStore().getKey(alias, null) as? SecretKey

    private fun createKey(): SecretKey =
        try {
            generate(strongBox = true)
        } catch (_: Exception) {
            generate(strongBox = false)
        }

    private fun generate(strongBox: Boolean): SecretKey {
        if (strongBox && Build.VERSION.SDK_INT < 28) throw IllegalStateException("StrongBox needs API 28")
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (strongBox && Build.VERSION.SDK_INT >= 28) spec.setIsStrongBoxBacked(true)
        gen.init(spec.build())
        return gen.generateKey()
    }

    override fun seal(aad: ByteArray, plain: ByteArray): ByteArray {
        val key = existingKey() ?: createKey()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)
        c.updateAAD(aad)
        return c.iv + c.doFinal(plain)
    }

    override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? {
        if (sealed.size < 28) return null
        return try {
            val key = existingKey() ?: return null
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
            c.updateAAD(aad)
            c.doFinal(sealed.copyOfRange(12, sealed.size))
        } catch (_: Exception) {
            null
        }
    }

    override fun deleteKey(): Boolean = try {
        keyStore().deleteEntry(alias)
        !keyStore().containsAlias(alias)
    } catch (_: Exception) {
        false
    }

    companion object {
        const val KEY_ALIAS = "beamio.page.record.v1"
    }
}

/** The extra fields of a bridge reply. */
internal typealias ShellReplyFields = List<Pair<String, Any?>>

/** What the bridge needs about the account before it can answer. */
internal sealed class ShellRecordAccount {
    /** The account is known, and its page store is [store]. */
    class Ready(val store: SealedPageRecordStore, val eoa: String) : ShellRecordAccount()

    /** No wallet and no imported account. Nothing can be read or held for it yet. */
    object Unknown : ShellRecordAccount()

    /** A page copy exists but no profile of it holds the EOA private key: the copy is a record of another account (§25.52Y.15 第 2 项, r3mh). Reads answer account_mismatch. */
    object Mismatch : ShellRecordAccount()

    /** The vault is locked and no account is bound. */
    object Locked : ShellRecordAccount()

    /** A native record exists but this session has not initialised for it (G1, §25.26.4c): `not_ready`, and the payload is not read. */
    object NotReady : ShellRecordAccount()
}

/**
 * The first-run import (§25.52K.3 to §25.52K.6): the legacy wallet record becomes the page wallet copy, rev 0 → 1, in an encrypted store, and
 * the PGP part goes to the migration. The import never creates a new wallet, and a failed import leaves the legacy store untouched.
 */
internal class ShellImportFlow(
    private val storeFor: (String) -> SealedPageRecordStore,
    private val addressOf: (String) -> String?,
    private val pgpStep: (String, LegacyPgpSource?) -> Unit,
    private val outcome: AtomicReference<ImportOutcome?>,
) {
    fun run(eoa: String, wallet: LegacyWalletRecord, pgp: LegacyPgpSource?): ShellImportCode {
        var pgpConsumed = false
        try {
            val code = importWallet(eoa, wallet)
            if (code == ShellImportCode.IMPORT_OK) {
                pgpStep(eoa, pgp)
                pgpConsumed = true
            }
            return code
        } finally {
            if (!pgpConsumed) pgp?.wipe()
        }
    }

    private fun importWallet(eoa: String, wallet: LegacyWalletRecord): ShellImportCode {
        if (!PgpMigrationPolicy.EOA_RE.matches(eoa)) {
            // R444: the legacy store is not read for an account that cannot match any profile. This is account_mismatch, not import_not_done.
            outcome.set(ImportOutcome.ACCOUNT_MISMATCH)
            return ShellImportCode.ACCOUNT_MISMATCH
        }
        val store = storeFor(eoa)
        // §25.52K.3 step 1: an existing copy is never imported over (IM-07). An unreadable copy is existing too.
        val exists = try {
            store.read() != null
        } catch (_: IOException) {
            true
        }
        if (exists) {
            outcome.set(ImportOutcome.DONE)
            return ShellImportCode.EXISTS
        }
        return when (wallet) {
            is LegacyWalletRecord.Absent -> {
                outcome.set(ImportOutcome.ABSENT)
                ShellImportCode.ABSENT
            }
            is LegacyWalletRecord.Unreadable -> {
                outcome.set(ImportOutcome.LEGACY_UNREADABLE)
                ShellImportCode.LEGACY_UNREADABLE
            }
            is LegacyWalletRecord.Found -> importFound(eoa, store, wallet.record)
        }
    }

    private fun importFound(eoa: String, store: SealedPageRecordStore, bytes: ByteArray): ShellImportCode {
        val json = try {
            JSONObject(String(bytes, Charsets.UTF_8))
        } catch (_: Exception) {
            null
        } finally {
            bytes.fill(0)
        }
        if (json == null) {
            outcome.set(ImportOutcome.LEGACY_UNREADABLE)
            return ShellImportCode.LEGACY_UNREADABLE
        }
        // PGP never enters the page copy, even if the reader let a field through (§25.52I.2).
        ShellRecordPolicy.stripPgpForRead(json)
        // F2 condition 1: a PGP header that survives the strip, at any path, fails the import closed. This is an SDK rule, pending the interface
        // owner's ruling; the import is not done, so the legacy store is left untouched.
        if (ShellRecordPolicy.hasPgpHeader(json)) {
            outcome.set(ImportOutcome.NOT_DONE)
            return ShellImportCode.IMPORT_FAILED
        }
        // §25.52K.5: the account of the record is profiles[k].keyID, and the key of that profile must derive it.
        val profiles = json.optJSONArray("profiles")
        var index = -1
        if (profiles != null) {
            for (i in 0 until profiles.length()) {
                val keyId = profiles.optJSONObject(i)?.optString("keyID", "") ?: continue
                if (keyId.equals(eoa, ignoreCase = true)) {
                    index = i
                    break
                }
            }
        }
        val profile = if (index >= 0) profiles?.optJSONObject(index) else null
        // §25.52N.6, §25.52R.5 (暂定): a matching profile without its privateKeyArmor is import_failed; a key that derives another address
        // is address_mismatch (§25.52K.5).
        // §25.52BB.3 (r3cz, R673): the legacy key is normalized first (Q1 read rule) and the stored form is "0x" plus 64 lower-case hex digits. A
        // key that cannot be normalized is import_failed. After normalization, a key that derives another address is address_mismatch. The
        // normalized key is what the write check sees, and what is stored.
        val armor = profile?.optString("privateKeyArmor", "").orEmpty()
        if (profile == null || armor.isEmpty()) {
            outcome.set(ImportOutcome.NOT_DONE)
            return ShellImportCode.IMPORT_FAILED
        }
        val canonical = ShellRecordPolicy.normalizeLegacyKey(armor)
        if (canonical == null) {
            outcome.set(ImportOutcome.NOT_DONE)
            return ShellImportCode.IMPORT_FAILED
        }
        profile.put("privateKeyArmor", canonical)
        val derived = addressOf(canonical)
        if (derived == null || !derived.equals(eoa, ignoreCase = true)) {
            outcome.set(ImportOutcome.NOT_DONE)
            return ShellImportCode.ADDRESS_MISMATCH
        }
        json.put("schemaVersion", ShellRecordPolicy.WALLET_SCHEMA_MIN).put("rev", 1)
        return try {
            store.write(json)
            outcome.set(ImportOutcome.DONE)
            ShellImportCode.IMPORT_OK
        } catch (_: IOException) {
            outcome.set(ImportOutcome.NOT_DONE)
            ShellImportCode.IMPORT_FAILED
        }
    }
}

/**
 * The codes that the ack refuses at the envelope level (§25.52T.2, §25.52AD.4): the request is not processed, so the ack has `ok: false` and an
 * `error`. `not_ready` is the G1 answer of the gate (§25.26.4c), given before the payload is read.
 */
// unknown_command (25.52AU.1, BU.1, R709): an unknown shellRecord* name on the window channel is an envelope-level answer, with no result.
private val ENVELOPE_CODES = setOf("origin_refused", "too_large", "not_ready", "unknown_command")

/**
 * The ack envelope of a page-record answer (§25.28.3, §25.52T.2): `{type: "ack", reqId, ok: true, result: {code, ...}}` for every answer
 * that the bridge reached, with the outcome in `result.code` (errors carry `sub` in `result`). Only an envelope-level refusal is `ok: false`:
 * `origin_refused`, `too_large`, and a `bad_request` without path names (a bad reqId, a missing record, a non-integer rev). A `bad_request`
 * with path names is a content refusal and goes in `result`. No separate event is sent.
 */
internal fun shellAck(reqId: Any, code: String, fields: ShellReplyFields): JSONObject {
    val out = JSONObject().put("type", "ack").put("reqId", reqId)
    val envelopeRefusal = code in ENVELOPE_CODES || (code == "bad_request" && fields.none { it.first == "names" })
    if (envelopeRefusal) return out.put("ok", false).put("error", code)
    val result = JSONObject().put("code", code)
    for ((k, v) in fields) result.put(k, v ?: JSONObject.NULL)
    return out.put("ok", true).put("result", result)
}

/**
 * The bridge logic of the page's `shellRecordRead` and `shellRecordWrite` (§25.52D.6, §25.52D.7, §25.52E, §25.52K.4, §25.52L, §25.52O.5,
 * §25.52S, §25.52T). The checks run in the order §25.52O.5 gives. Each request gets exactly one ack. `shellRecordMigrationState` is not a
 * page command (§25.52L.6): any other type is `bad_request`.
 */
internal class ShellRecordBridge(
    private val account: () -> ShellRecordAccount,
    private val migrating: () -> Boolean,
    private val outcome: () -> ImportOutcome?,
    private val flags: DeviceFlags = NoDeviceFlags,
    /** The creation mode and the explicit choice of the creation flow (§25.52Y.54 PY.18(b)). Off unless the creation flow sets them. */
    private val creationMode: () -> Boolean = { false },
    private val explicitChoice: () -> Boolean = { false },
    /** The vault and the gate for walletEoaAddress (PM R1921). Null means the name is not served by this bridge. */
    private val walletEoaAddress: (() -> Pair<NativeWalletVault, NoKeyGate.Gate>)? = null,
    /** The vault and the gate for walletCredential (PM R2048). Null means the name is not served by this bridge. */
    private val walletCredential: (() -> Pair<NativeWalletVault, NoKeyGate.Gate>)? = null,
    /** The SDK's own declaration of wallet.credential.v1 (spec 25.52Y.38 第 2 项 (e)): true only in a QA build. */
    private val walletCredentialDeclared: Boolean = WalletCredentialBridge.sdkDeclares(),
) {
    /**
     * [nativeWrite] is true only for the native account creation or recovery (§25.52H.2, rule 4). It lets a write replace the W fields.
     * The page path never sets it.
     */
    fun handle(origin: ShellOrigin, body: JSONObject, requestBytes: Int, nativeWrite: Boolean = false): JSONObject {
        val type = body.optString("type", "")
        val rawId = body.opt("reqId")
        val idOk = ShellRecordPolicy.reqIdValid(rawId)
        val echo: Any = if (idOk) rawId!! else JSONObject.NULL
        val reply: (String, ShellReplyFields) -> JSONObject = { code, fields -> shellAck(echo, code, fields) }

        if (origin != ShellOrigin.EMBEDDED_PAGE) return reply("origin_refused", emptyList())
        if (!idOk) return reply("bad_request", emptyList())

        // walletEoaAddress (spec 25.52Y.42 第 5 项 (c)): the origin is already checked above (EMBEDDED_PAGE, the main frame at the boundary).
        // It returns the address only (PM R1907, R1912). Served here so the shell's window call reaches it (PM R1921).
        if (type == WalletEoaAddressBridge.NAME) {
            val current = walletEoaAddress ?: return reply("unknown_command", emptyList())
            return WalletEoaAddressBridge.answer(originAllowed = true, body = body, current = current)
        }
        // walletCredential (spec 25.52Y.38, 25.52Y.44; PM R2048): the SDK's declaration is checked inside (not_trusted, before any read).
        if (type == WalletCredentialBridge.NAME) {
            val current = walletCredential ?: return reply("unknown_command", emptyList())
            return WalletCredentialBridge.answer(walletCredentialDeclared, body, current)
        }

        val allowed = when (type) {
            "shellRecordRead" -> ShellRecordPolicy.READ_FIELDS
            "shellRecordWrite" -> ShellRecordPolicy.WRITE_FIELDS
            // 25.52AU.1, BU.1 (r3dt): an unknown top-level action on the window channel is the envelope-level unknown_command, once.
            else -> return reply("unknown_command", emptyList())
        }
        // §25.52AD.4 step 2: the gate answers before the payload is read. G1 is not_ready (§25.26.4c).
        val acc = account()
        if (acc is ShellRecordAccount.NotReady) return reply("not_ready", emptyList())
        val extra = ShellRecordPolicy.keysOf(body).filter { it !in allowed }
        // spec 25.52Y.41 第 6 项: a read that names a key-shaped field is refused as key material, with the names only and no value. Other
        // unknown names stay bad_request.
        if (type == "shellRecordRead") {
            val keyNames = extra.filter { ShellRecordPolicy.isKeyShaped(it) }
            if (keyNames.isNotEmpty()) return reply("key_over_bridge_refused", listOf("names" to JSONArray(keyNames.sortedWith(UTF8_ORDER))))
        }
        if (extra.isNotEmpty()) return reply("bad_request", listOf("names" to JSONArray(extra.sortedWith(UTF8_ORDER))))

        // 25.52CF.1 (r3ef): an exception in the handler gives the fallback, once, with the reqId as sent. No detail is returned.
        return try {
            if (type == "shellRecordRead") read(acc, reply) else write(body, requestBytes, nativeWrite, acc, reply)
        } catch (_: Exception) {
            if (type == "shellRecordRead") reply("error", listOf("sub" to "record_unreadable")) else reply("write_failed", emptyList())
        }
    }

    private fun read(acc: ShellRecordAccount, reply: (String, ShellReplyFields) -> JSONObject): JSONObject {
        // 25.52CH.1 (r3eg): a locked store is a business result, ok:true, with sub storage_locked.
        if (acc is ShellRecordAccount.Locked) return reply("error", listOf("sub" to "storage_locked"))
        if (migrating()) return reply("migrating", emptyList())
        // §25.52Y.54 PY.18(b), §25.52Y.55 (a): creation mode with an explicit choice and a pointer set does not enter creation (AK-48, AK-49).
        // A legacy store found answers import_not_done first (AK-50). Nothing is written, the pointer is not switched, no key is deleted.
        if (creationMode() && explicitChoice() && flags.accountPointer()) {
            // §25.52Y.56 (r3lt 第 (1) 项): DONE is found already cleared, so it is not import_not_done; NOT_DONE is the only source of it here.
            return when (outcome()) {
                ImportOutcome.NOT_DONE -> reply("error", listOf("sub" to "import_not_done"))
                else -> reply("migrating", emptyList())
            }
        }
        // §25.52Y.15 第 2 项 (r3mh, AK-61): a page copy that no profile of which holds the EOA key answers account_mismatch.
        if (acc is ShellRecordAccount.Mismatch) return reply("error", listOf("sub" to "account_mismatch"))
        if (acc is ShellRecordAccount.Ready) {
            val current: JSONObject? = try {
                acc.store.read()
            } catch (_: IOException) {
                return reply("error", listOf("sub" to "record_unreadable"))
            }
            if (current != null) {
                val rev = current.opt("rev") as? Int ?: return reply("error", listOf("sub" to "record_unreadable"))
                // §25.52U.5: a record is the source of truth. It clears the device marker, and repairs an empty account pointer when a
                // profile matches the account. The marker has no say while a record exists.
                // §25.52S.3, §25.52U.4: a schema 2 copy is judged against the account's profile (needs_native_recovery, account_mismatch).
                val judgement = if (current.optInt("schemaVersion", -1) >= ShellRecordPolicy.WALLET_SCHEMA_MIN) {
                    ShellRecordPolicy.accountJudgement(current, acc.eoa)
                } else {
                    null
                }
                ShellRecordPolicy.stripPgpForRead(current)
                // §25.52I.2: PGP fields never reach the page. A PGP header that survives the strip, at any path, fails the read closed
                // (F2 condition 2). The error is an SDK choice pending the interface owner's ruling; the device flags are not touched.
                if (ShellRecordPolicy.hasPgpHeader(current)) return reply("error", listOf("sub" to "record_unreadable"))
                repairFlags(current, acc.eoa, valid = judgement == null)
                val out = reply(
                    "ok",
                    listOf("rev" to rev, "schemaVersion" to ShellRecordPolicy.RESPONSE_SCHEMA, "record" to current),
                )
                if (out.toString().toByteArray(Charsets.UTF_8).size > ShellRecordPolicy.MAX_BYTES) return reply("too_large", emptyList())
                judgement?.let { sub -> return reply("error", listOf("sub" to sub)) }
                return out
            }
        }
        return noRecord(reply)
    }

    /** The flags a readable record sets: the marker is cleared, and an empty pointer is repaired when a profile matches (§25.52U.5). */
    private fun repairFlags(record: JSONObject, eoa: String, valid: Boolean) {
        try {
            if (valid) flags.clearLegacyUnreadable()
            if (!flags.accountPointer() && ShellRecordPolicy.matchingProfiles(record, eoa).isNotEmpty()) flags.setAccountPointer()
            // R488: a readable record that holds the account's key persists the address, which the cold start restores.
            if (valid && ShellRecordPolicy.accountHoldsEoaKey(record, eoa) && flags.accountAddress() != eoa.lowercase()) {
                flags.setAccountAddress(eoa)
            }
        } catch (_: IOException) {
            // The flags are not critical for a readable record: the next read repairs them.
        }
    }

    /**
     * No native record (§25.52T.3, §25.52T.6). The pointer comes first: a device that has established an account never answers absent.
     * `absent` needs the legacy store confirmed absent, which also clears the marker. An unreadable legacy store sets the marker.
     */
    private fun noRecord(reply: (String, ShellReplyFields) -> JSONObject): JSONObject {
        if (flags.accountPointer()) return reply("error", listOf("sub" to "account_record_missing"))
        // §25.52U.6 (r3rz): an unreadable or unread legacy store answers migrating, never error(legacy_store_unreadable).
        return when (outcome()) {
            null -> reply("migrating", emptyList())
            ImportOutcome.ABSENT -> {
                flags.clearLegacyUnreadable()
                reply("absent", emptyList())
            }
            ImportOutcome.LEGACY_UNREADABLE -> {
                flags.setLegacyUnreadable()
                reply("migrating", emptyList())
            }
            // §25.52Y.56: NOT_DONE is the only source of import_not_done; DONE (found cleared, no record here) fails closed as migrating.
            ImportOutcome.NOT_DONE -> reply("error", listOf("sub" to "import_not_done"))
            // PENDING interface ruling (25.52Y.56 follow-up): U.6 has no row for DONE with no pointer and no record. Held as migrating; not a pass basis.
            ImportOutcome.DONE -> reply("migrating", emptyList())
            ImportOutcome.ACCOUNT_MISMATCH -> reply("error", listOf("sub" to "account_mismatch"))
        }
    }

    private fun write(
        body: JSONObject,
        requestBytes: Int,
        nativeWrite: Boolean,
        acc: ShellRecordAccount,
        reply: (String, ShellReplyFields) -> JSONObject,
    ): JSONObject {
        if (requestBytes > ShellRecordPolicy.MAX_BYTES) return reply("too_large", emptyList())
        val record = body.optJSONObject("record") ?: return reply("bad_request", emptyList())
        val rev = record.opt("rev")
        if (rev !is Int) return reply("bad_request", emptyList())

        // §25.52O.5 step 2: PGP private material is refused first.
        ShellRecordPolicy.preWriteRefusal(record)?.let { (code, names) ->
            return if (names.isEmpty()) reply(code, emptyList()) else reply(code, listOf("names" to JSONArray(names)))
        }

        // §25.52Y.10 (r3lm; AK-39): the write guards (migrating, device marker) come before the storage lock, so they are checked before the read.
        if (migrating() || flags.legacyUnreadable()) return reply("migrating", emptyList())
        // 25.52CH.1 (r3eg): a locked store on a write is write_failed, once.
        if (acc is ShellRecordAccount.Locked) return reply("write_failed", emptyList())
        val ready = acc as? ShellRecordAccount.Ready
        val store = ready?.store
        val current: JSONObject? = if (store == null) {
            null
        } else {
            try {
                store.read()
            } catch (_: IOException) {
                // 25.52CK.8 (r3ek): a read failure before a write is write_failed; record_unreadable is for reads only (25.52CH.1).
                return reply("write_failed", emptyList())
            }
        }

        // §25.52O.5 step 3: W fields need schema 2, and a stored copy with W fields takes only schema 2 writes (§25.52F.5, §25.52L.4).
        // r3lo, AK-30 (ruling 2026-11-15): the revision check comes before the W-field and schema checks, so a stale rev is conflict (currentRev).
        // A missing or non-integer schemaVersion stays bad_request below (DL-10a), so the early check applies only to an integer schemaVersion.
        val schema = record.opt("schemaVersion")
        if (current != null && schema is Int && rev != ((current.opt("rev") as? Int) ?: 0)) {
            return reply("conflict", listOf("currentRev" to ((current.opt("rev") as? Int) ?: 0)))
        }
        val storedWallet = current?.let { ShellRecordPolicy.walletIn(it) }.orEmpty()
        if (storedWallet.isNotEmpty() && (schema !is Int || schema < ShellRecordPolicy.WALLET_SCHEMA_MIN)) {
            return reply("wallet_copy_not_approved", listOf("names" to JSONArray(storedWallet)))
        }
        // A missing or non-integer schemaVersion is refused as bad_request naming the path. The spec does not say what this case gets (R553
        // review §2.2): this is the SDK's rule, pending the interface owner's ruling.
        if (schema !is Int) return reply("bad_request", listOf("names" to JSONArray(listOf("schemaVersion"))))
        val wallet = ShellRecordPolicy.walletIn(record)
        if (wallet.isNotEmpty() && schema < ShellRecordPolicy.WALLET_SCHEMA_MIN) {
            return reply("wallet_copy_not_approved", listOf("names" to JSONArray(wallet)))
        }
        // §25.52O.5 steps 4 and 5: key-shaped content first (this also covers privateKeyArmorWrap, §25.52AF.3 rule 2), then the W-class type
        // check (§25.52AF.3 rule 3), then the whitelist (§25.52N.4).
        val keyShaped = ShellRecordPolicy.keyShapedIn(record)
        if (keyShaped.isNotEmpty()) return reply("key_shaped_content", listOf("names" to JSONArray(keyShaped)))
        // §25.52O.3, §25.52AF.3 (r3cd): a W-class object or array is bad_request naming the path. Before the whitelist, so the path is named and not
        // its sub-paths.
        val walletRefusal = ShellRecordPolicy.walletTypeRefusal(record)
        if (walletRefusal.isNotEmpty()) return reply("bad_request", listOf("names" to JSONArray(walletRefusal)))
        val violations = ShellRecordPolicy.whitelistViolations(record)
        if (violations.isNotEmpty()) return reply("bad_request", listOf("names" to JSONArray(violations)))

        // Step 6: migrating. Step 7: the revision. The first write carries rev 0 (§25.52E.3).
        if (migrating()) return reply("migrating", emptyList())
        // §25.52AA, AK-28: a device marker holds the write back, with or without a record (the record is not yet read as valid).
        if (flags.legacyUnreadable()) return reply("migrating", emptyList())
        if (current == null) {
            // §25.52W.3, AK-23 to AK-25, AK-27, R445: with no native record, a write waits for a completed read. A pointer, a marker, or any
            // outcome other than a confirmed absence answers migrating; the first write goes ahead only after the legacy store is confirmed
            // absent. Never a new wallet on a failure. A content refusal above has already answered, so the guard only stops valid writes.
            if (flags.accountPointer() || flags.legacyUnreadable()) return reply("migrating", emptyList())
            when (outcome()) {
                // AK-10 (ruling 2026-11-15): no account and no record with the legacy store confirmed empty: migrating, not ok or no_key.
                ImportOutcome.ABSENT -> if (store == null) return reply("migrating", emptyList())
                null, ImportOutcome.LEGACY_UNREADABLE, ImportOutcome.NOT_DONE, ImportOutcome.DONE, ImportOutcome.ACCOUNT_MISMATCH ->
                    return reply("migrating", emptyList())
            }
        }
        val target = store ?: return reply("error", listOf("sub" to "no_key"))
        val currentRev = (current?.opt("rev") as? Int) ?: 0
        if (rev != currentRev) return reply("conflict", listOf("currentRev" to currentRev))

        // §25.52AG.2 (b): a profile not of the account that carries privateKeyArmor is a conflict (w_account_unmatched), for native writes too.
        val mismatch = ShellRecordPolicy.walletAccountMismatch(record, ready?.eoa.orEmpty())
        if (mismatch.isNotEmpty()) {
            return reply(
                "conflict",
                listOf("currentRev" to currentRev, "reason" to "w_account_unmatched", "names" to JSONArray(mismatch)),
            )
        }

        // Step 9: the wallet-field merge (§25.52H.2, §25.52S.4).
        val merge = ShellRecordPolicy.mergeWallet(record, current ?: JSONObject(), ready?.eoa.orEmpty(), replaceWallet = nativeWrite)
        if (merge.names.isNotEmpty()) {
            return reply(
                "conflict",
                listOf("currentRev" to currentRev, "reason" to merge.reason, "names" to JSONArray(merge.names)),
            )
        }
        // §25.52N.9 Q1 (F2 condition 4): after the merge conflicts (§25.52H.2), a string privateKeyArmor of the account's profile must be the canonical form
        // and derive its keyID; otherwise bad_request, naming the path.
        // §25.52N.9 Q1 (F2 condition 4): a string privateKeyArmor must be the canonical form and derive its profile's keyID.
        val formRefusal = ShellRecordPolicy.walletFormRefusal(record, ready?.eoa.orEmpty())
        if (formRefusal.isNotEmpty()) return reply("bad_request", listOf("names" to JSONArray(formRefusal)))
        // §25.52P.4: a schema 2 copy must hold the EOA private key after the merge; otherwise the write is refused and nothing is stored.
        if (schema >= ShellRecordPolicy.WALLET_SCHEMA_MIN && !ShellRecordPolicy.accountHoldsEoaKey(merge.record, ready?.eoa.orEmpty())) {
            return reply("wallet_fields_missing", listOf("names" to JSONArray(listOf(ShellRecordPolicy.W_PROFILE_PATH))))
        }
        val next = currentRev + 1
        val toStore = merge.record.put("rev", next)
        try {
            target.write(toStore)
        } catch (_: IOException) {
            return reply("write_failed", emptyList())
        }
        // §25.52T.4: the first successful native write establishes the account pointer. The record is already stored, so a failure here
        // only leaves the pointer unset.
        try {
            flags.setAccountPointer()
            if (ready != null) flags.setAccountAddress(ready.eoa)
        } catch (_: IOException) {
            // Read later from the record; the pointer is set by the next successful write.
        }
        return reply("ok", listOf("rev" to next))
    }
}

/**
 * The boundary decision of the window channel (§25.52AB.5, OR-01 to OR-03, §25.52CJ.3 (r3ej)): a request from a source that is not allowed is
 * not processed, and is answered `origin_refused`, once. The source is judged before the reqId. An allowed request is answered once, by [answer],
 * whether its reqId is valid or not.
 */
internal fun answerAtBoundary(originAllowed: Boolean, body: JSONObject, requestBytes: Int, answer: (JSONObject, Int) -> JSONObject): JSONObject =
    if (originAllowed) answer(body, requestBytes) else originRefused(body)

/**
 * `origin_refused` (§25.52CJ.3, r3ej): the ack for a request from a source that is not allowed. The reqId is echoed when it is valid, else null.
 * Nothing of the request is read or logged, and nothing is processed.
 */
internal fun originRefused(body: JSONObject): JSONObject {
    val rawId = body.opt("reqId")
    val echo: Any = if (ShellRecordPolicy.reqIdValid(rawId)) rawId!! else JSONObject.NULL
    return shellAck(echo, "origin_refused", emptyList())
}

/** The state the production bridge shares: the import outcome, the bound account and the startup flag. One process, one account. */
internal object ShellRecordState {
    val outcome: AtomicReference<ImportOutcome?> = AtomicReference(null)
    val bound: AtomicReference<String?> = AtomicReference(null)
    val migrationPending: AtomicBoolean = AtomicBoolean(false)
}

/**
 * Decides the account that a shell record request is answered for (§25.26.4c, §25.52AD.2 to §25.52AD.4). Pure: the vault state, the session
 * flag, the bound account and the page copies are passed in, so the decision can be tested without a device.
 *  - A vault with a record (Ready or Locked): G1 (this session not initialised) is [ShellRecordAccount.NotReady] when [sessionGate] holds;
 *    otherwise the record's account, or Locked.
 *  - No vault record (G0): the account bound by this process's import, else the persisted address (R488), else the held copy ([heldCopy]),
 *    else Unknown.
 */
internal object ShellRecordAccounts {
    private val COPY_NAME = Regex("""page\.v1\.([0-9a-f]{40})\.default\.rec""")
    private val ADDRESS = Regex("""0x[0-9a-f]{40}""")

    /** A lower-case account address: `0x` and 40 hex digits. */
    fun isAddress(value: String): Boolean = ADDRESS.matches(value)

    fun resolve(
        vault: NativeWalletVault.State,
        sessionReady: Boolean,
        sessionGate: Boolean,
        bound: String?,
        copyNames: () -> List<String>,
        storeOf: (String) -> SealedPageRecordStore,
        persisted: () -> String? = { null },
    ): ShellRecordAccount = when (vault) {
        is NativeWalletVault.State.Ready, is NativeWalletVault.State.Locked -> when {
            sessionGate && !sessionReady -> ShellRecordAccount.NotReady
            vault is NativeWalletVault.State.Ready -> {
                val eoa = vault.eoa.lowercase()
                ShellRecordAccount.Ready(storeOf(eoa), eoa)
            }
            bound != null -> ShellRecordAccount.Ready(storeOf(bound), bound)
            else -> ShellRecordAccount.Locked
        }
        is NativeWalletVault.State.NoKey -> {
            // R488: the bound account survives a cold start. It is restored from the persisted address before the copy is searched.
            val restored = bound ?: persisted()?.takeIf { isAddress(it) }
            if (restored != null) ShellRecordAccount.Ready(storeOf(restored), restored)
            else {
                val names = copyNames()
                // §25.52Y.56: one or more copies and none holding the EOA key of its own account is account_mismatch; otherwise Unknown.
                heldCopy(names, storeOf) ?: if (copiesPresentNoneHeld(names, storeOf)) ShellRecordAccount.Mismatch else ShellRecordAccount.Unknown
            }
        }
    }

    /** True when at least one page copy is named and no copy holds the EOA key of its own account. An unreadable copy counts as not held (fail closed). */
    private fun copiesPresentNoneHeld(names: List<String>, storeOf: (String) -> SealedPageRecordStore): Boolean {
        val eoas = names.mapNotNull { COPY_NAME.matchEntire(it)?.groupValues?.get(1)?.let { hex -> "0x$hex" } }
        if (eoas.isEmpty()) return false
        return eoas.none { eoa ->
            try {
                storeOf(eoa).read()?.let { ShellRecordPolicy.accountHoldsEoaKey(it, eoa) } ?: false
            } catch (_: IOException) {
                false
            }
        }
    }

    /**
     * The held copy of the only page record on the device (§25.52AD.2). The single file `page.v1.<address>.default.rec` names the account; the
     * copy is held when it opens and a profile of that account holds the EOA private key. A copy that is present but cannot be opened is still
     * a record: the account is returned, so reads and writes answer `record_unreadable` and never `absent`. Null when the file names are not
     * exactly one copy, or when the copy opens and is not held.
     */
    fun heldCopy(names: List<String>, storeOf: (String) -> SealedPageRecordStore): ShellRecordAccount.Ready? {
        val hits = names.mapNotNull { COPY_NAME.matchEntire(it)?.groupValues?.get(1) }
        val eoa = hits.singleOrNull()?.let { "0x$it" } ?: return null
        val store = storeOf(eoa)
        return try {
            val record = store.read() ?: return null
            if (ShellRecordPolicy.accountHoldsEoaKey(record, eoa)) ShellRecordAccount.Ready(store, eoa) else null
        } catch (_: IOException) {
            ShellRecordAccount.Ready(store, eoa)
        }
    }
}

/**
 * The public entry of the page-record bridge for the Android shell (§25.52G, §25.52K). The shell verifies the origin of the message
 * (`https://appassets.androidplatform.net`, through `WebViewCompat.addWebMessageListener`) and passes the result as [ShellOrigin]. The
 * returned object is the reply to that message. The calls read and write files: run them off the main thread.
 */
object BeamioShellRecordImport {
    /** The native read-only migration state (§25.52L.6). The page does not call it: the bridge refuses it as an unknown command. */
    fun migrationState(context: Context): String = migrationStateOf(context)

    /** Set by the shell while its start-up import and migration (§25.52K.3) are not finished. Reads and writes then answer `migrating`. */
    fun setMigrationPending(pending: Boolean) {
        ShellRecordState.migrationPending.set(pending)
    }

    /** Answers one page request. [requestBytes] is the size of the message as received, in UTF-8 bytes. */
    fun handle(context: Context, origin: ShellOrigin, body: JSONObject, requestBytes: Int): JSONObject =
        bridge(context).handle(origin, body, requestBytes)

    /**
     * The window channel on Android (§25.52AB.2, §25.52AB.5): the shell's `WebViewCompat.addWebMessageListener` hands over the message with the
     * source origin and the frame kind. The source is checked here at the native boundary (the platform filter is the first check). A source
     * that is not [ALLOWED_ORIGIN], or a frame that is not the main frame, is not processed and is answered origin_refused, once (25.52CJ.3). Otherwise
     * the answer is exactly one ack, which the shell sends through the reply proxy to the page's `onmessage` (`JavaScriptReplyProxy.postMessage`).
     */
    fun answerFromPage(
        context: Context,
        sourceOrigin: String?,
        isMainFrame: Boolean,
        body: JSONObject,
        requestBytes: Int,
    ): JSONObject? = answerAtBoundary(isMainFrame && sourceOrigin == ALLOWED_ORIGIN, body, requestBytes) { b, bytes ->
        handle(context, ShellOrigin.EMBEDDED_PAGE, b, bytes)
    }

    /** The origin the window channel accepts (§25.52D.5, §25.52AA.4). */
    const val ALLOWED_ORIGIN = "https://appassets.androidplatform.net"

    /**
     * Writes the whole record from the native account creation or recovery, which may replace the W fields (§25.52H.2, rule 4). The page
     * never calls this. The revision follows the page rule: the record's `rev` must equal the current one.
     */
    fun writeWalletNative(context: Context, record: JSONObject): JSONObject {
        val body = JSONObject().put("type", "shellRecordWrite").put("reqId", 0).put("record", record)
        val bytes = body.toString().toByteArray(Charsets.UTF_8).size
        // The native creation runs before this session is initialised (G1 is the state it creates from), so the session gate does not apply.
        return bridge(context, sessionGate = false).handle(ShellOrigin.EMBEDDED_PAGE, body, bytes, nativeWrite = true)
    }

    /** The first-run import (§25.52K), called by [BeamioPgpMigrationImport.importFirstRun]. */
    internal fun runFirstImport(
        context: Context,
        eoa: String,
        wallet: LegacyWalletRecord,
        pgp: LegacyPgpSource?,
    ): ShellImportCode {
        val app = context.applicationContext
        val flow = ShellImportFlow(
            storeFor = { e -> storeFor(app, e) },
            addressOf = { armor -> addressOfPrivateKey(armor) },
            pgpStep = { e, src -> BeamioPgpMigrationImport.run(app, e, source = src) },
            outcome = ShellRecordState.outcome,
        )
        val code = flow.run(eoa, wallet, pgp)
        applyImportMarker(flagsOf(app), code)
        if (code == ShellImportCode.IMPORT_OK || code == ShellImportCode.EXISTS) {
            ShellRecordState.bound.set(eoa)
            // R488: the binding survives a cold start, so the shell does not have to bind again on every start.
            runCatching { flagsOf(app).setAccountAddress(eoa) }
        }
        return code
    }

    private fun bridge(context: Context, sessionGate: Boolean = true): ShellRecordBridge = ShellRecordBridge(
        account = { accountOf(context, sessionGate) },
        migrating = { ShellRecordState.migrationPending.get() },
        outcome = { ShellRecordState.outcome.get() },
        flags = flagsOf(context.applicationContext),
        walletEoaAddress = walletCurrent(context),
        walletCredential = walletCurrent(context),
    )

    /** The vault and the gate of the account on this device (shared by walletEoaAddress and walletCredential). */
    private fun walletCurrent(context: Context): () -> Pair<NativeWalletVault, NoKeyGate.Gate> = {
        val vault = NativeWallet.vault(context)
        vault to NoKeyGate.gateOf(vault.state(), NativeSessionState.isReady())
    }

    /** The device-level flags, in the same no-backup directory as the page copies (§25.52T). */
    internal fun flagsOf(app: Context): DeviceFlags = DeviceFlagFiles(AndroidVaultFiles(File(app.noBackupFilesDir, "page_record_v1")))

    private fun accountOf(context: Context, sessionGate: Boolean): ShellRecordAccount {
        val app = context.applicationContext
        return ShellRecordAccounts.resolve(
            vault = NativeWallet.vault(app).state(),
            sessionReady = NativeSessionState.isReady(),
            sessionGate = sessionGate,
            bound = ShellRecordState.bound.get(),
            copyNames = { AndroidVaultFiles(File(app.noBackupFilesDir, "page_record_v1")).names() },
            storeOf = { eoa -> storeFor(app, eoa) },
            persisted = { flagsOf(app).accountAddress() },
        )
    }

    /** The page store of [eoa] in the default workspace (§25.52F.3). */
    internal fun storeFor(app: Context, eoa: String): SealedPageRecordStore {
        val files = AndroidVaultFiles(File(app.noBackupFilesDir, "page_record_v1"))
        return SealedPageRecordStore(AndroidPageRecordKeyWrap(), files, eoa.lowercase() + ":" + PgpMigrationPolicy.WORKSPACE)
    }

    private fun migrationStateOf(context: Context): String {
        val app = context.applicationContext
        val state = NativeWallet.vault(app).state() as? NativeWalletVault.State.Ready ?: return "none"
        return BeamioPgpMigrationImport.state(app, state.eoa)
    }

    /** The EOA address of a private-key string (`0x` plus 64 hex digits), lower case, or `null`. The key bytes are zero-filled after use. */
    private fun addressOfPrivateKey(armor: String): String? = ShellRecordPolicy.addressOfArmor(armor)
}
