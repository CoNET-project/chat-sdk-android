package network.conet.chat.nativekey

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
 * The page keeps its wallet copy here. The commands are `shellRecordRead`, `shellRecordWrite` and, native-only, `shellRecordMigrationState`.
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
}

/** What the import has established for the page store, read by the bridge (§25.52K.4). `null` means the import has not run. */
internal enum class ImportOutcome { ABSENT, LEGACY_UNREADABLE, NOT_DONE, DONE }

/** The rules of §25.52D.5 to §25.52D.8, §25.52I and §25.52J. */
internal object ShellRecordPolicy {
    /** A request and a response are each at most 2 MB, in UTF-8 bytes (§25.52D.5). */
    const val MAX_BYTES = 2 * 1024 * 1024

    /** The bridge response schema (§25.52D.6). The record's own `schemaVersion` is separate. */
    const val RESPONSE_SCHEMA = 1

    /** The record schema that may hold W fields (§25.52F.5). Older pages get `wallet_copy_not_approved`. */
    const val WALLET_SCHEMA_MIN = 2

    const val PGP_HEADER = "BEGIN PGP PRIVATE KEY"

    /** §25.52D.8 and §25.52I.2: PGP paths that never enter the page record. Writing one is refused. */
    val FORBIDDEN_PATHS: Set<String> = setOf(
        "profiles[*].chatManager.pgpKey.privateKey",
        "profiles[*].chatManager.pgpKey.privateKeyArmor",
        "profiles[*].chatManager.pgpKey.privateKeyArmorWrap",
        "profiles[*].pgpKey.privateKey",
        "profiles[*].pgpKey.privateKeyArmor",
        "profiles[*].pgpKey.privateKeyArmorWrap",
        "pgpPassphrase",
        "profiles[*].chats[*].chatData.privateArmored",
    )

    /** §25.52I.2: PGP fields removed from a read copy. The whole object is removed (`chatManager.pgpKey` with its public part). */
    private val PGP_STRIP_PATHS: List<String> = listOf(
        "profiles[*].chatManager.pgpKey",
        "profiles[*].pgpKey",
        "pgpPassphrase",
        "profiles[*].chats[*].chatData.privateArmored",
    )

    /** §25.52J.2: the W-class paths, allowed only in the page wallet copy, held only in a record of [WALLET_SCHEMA_MIN] or later. */
    val WALLET_PATHS: Set<String> = setOf(
        "profiles[*].privateKeyArmor",
        "walletVault.mnemonic",
        "mnemonic",
    )

    /** §25.52D.8: the profile-level keys of the whitelist. */
    val PROFILE_KEYS: Set<String> = setOf(
        "isPrimary", "emailAddr", "hdPath", "index", "tokens", "isNode", "referrer", "spClub", "SpClubPoints",
        "spChannel", "airdropEvent", "data", "type", "nodeID", "nodeIP_address", "nodeRegion", "activePassport",
        "vpnTimeUsedInMin", "silentPassPassports", "webFilter", "chats", "phoneCalls", "aaAccount", "issuedCards", "keyID",
    )

    /** The top-level keys: the schema and revision (§25.52E.3), the profiles, and the W keys `mnemonic` and `walletVault`. */
    val TOP_KEYS: Set<String> = setOf("schemaVersion", "rev", "profiles", "mnemonic", "walletVault")

    /** §25.52I.3: under `chatManager` only `router` is whitelisted. The PGP public fields are not. */
    val CHAT_MANAGER_KEYS: Set<String> = setOf("router")

    val READ_FIELDS: Set<String> = setOf("type", "reqId")
    val WRITE_FIELDS: Set<String> = setOf("type", "reqId", "record")
    val MIGRATION_STATE_FIELDS: Set<String> = setOf("type", "reqId")

    /** The reqId rule of §25.28.3: a string of 1 to 64 printable ASCII bytes, or an integer from 0 to 2^53 - 1. */
    fun reqIdValid(value: Any?): Boolean = when (value) {
        is String -> value.isNotEmpty() && value.length <= 64 && value.all { it.code in 0x20..0x7E }
        is Int -> value >= 0
        is Long -> value in 0..((1L shl 53) - 1)
        else -> false
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

    /** True when any string value, at any depth, holds the PGP private key header (§25.52D.7 step 5). Values only. */
    fun hasPgpHeader(value: Any?): Boolean = when (value) {
        is String -> value.contains(PGP_HEADER)
        is JSONObject -> keysOf(value).any { hasPgpHeader(value.opt(it)) }
        is JSONArray -> (0 until value.length()).any { hasPgpHeader(value.opt(it)) }
        else -> false
    }

    /** The forbidden paths present in [record], sorted (§25.52D.8). */
    fun forbiddenIn(record: JSONObject): List<String> = pathsOf(record).filter { it in FORBIDDEN_PATHS }.sorted()

    /** The W-class paths present in [record], sorted (§25.52J.2). */
    fun walletIn(record: JSONObject): List<String> = pathsOf(record).filter { it in WALLET_PATHS }.sorted()

    /**
     * The native pre-write check (§25.52E.5, the native half of PW-01 and PW-02). A PGP header or a forbidden path refuses the write as
     * `pgp_private_in_payload`. The header refusal carries no names (§25.52D.6). Returns the code and the names, or `null` when clean.
     */
    fun preWriteRefusal(record: JSONObject): Pair<String, List<String>>? {
        if (hasPgpHeader(record)) return "pgp_private_in_payload" to emptyList()
        val names = forbiddenIn(record)
        return if (names.isEmpty()) null else "pgp_private_in_payload" to names
    }

    /**
     * Whitelist violations (§25.52D.8, §25.52I.3, §25.52J.2), sorted. The W paths are allowed here; the schema check decides them. Any
     * PGP public field is outside the whitelist and is named as a violation.
     */
    fun whitelistViolations(record: JSONObject): List<String> {
        val out = mutableSetOf<String>()
        for (key in keysOf(record)) if (key !in TOP_KEYS) out += key
        val profiles = record.opt("profiles")
        if (profiles != null) {
            if (profiles !is JSONArray) {
                out += "profiles"
            } else {
                for (i in 0 until profiles.length()) {
                    val profile = profiles.opt(i)
                    if (profile !is JSONObject) out += "profiles[*]" else profileViolations(profile, out)
                }
            }
        }
        if (record.has("walletVault")) {
            val vault = record.optJSONObject("walletVault")
            if (vault == null) {
                out += "walletVault"
            } else {
                for (key in keysOf(vault)) if (key != "mnemonic") out += "walletVault.$key"
            }
        }
        return out.sorted()
    }

    private fun profileViolations(profile: JSONObject, out: MutableSet<String>) {
        for (key in keysOf(profile)) {
            when {
                key in PROFILE_KEYS -> Unit
                key == "privateKeyArmor" -> Unit
                key == "chatManager" -> chatManagerViolations(profile.optJSONObject(key), out)
                else -> out += "profiles[*].$key"
            }
        }
    }

    private fun chatManagerViolations(chatManager: JSONObject?, out: MutableSet<String>) {
        if (chatManager == null) {
            out += "profiles[*].chatManager"
            return
        }
        for (key in keysOf(chatManager)) {
            if (key in CHAT_MANAGER_KEYS) continue
            if (key == "pgpKey") {
                val pgpKey = chatManager.optJSONObject(key)
                if (pgpKey == null) {
                    out += "profiles[*].chatManager.pgpKey"
                } else {
                    for (k in keysOf(pgpKey)) out += "profiles[*].chatManager.pgpKey.$k"
                }
            } else {
                out += "profiles[*].chatManager.$key"
            }
        }
    }

    /**
     * The read copy of a record (§25.52I.2): removes the PGP fields in place, and an empty `chatManager`. The W fields stay: a read
     * carries them to the page.
     */
    fun stripPgpForRead(record: JSONObject) {
        for (path in PGP_STRIP_PATHS) removePath(record, path.split('.'))
        record.optJSONArray("profiles")?.let { profiles ->
            for (i in 0 until profiles.length()) {
                val profile = profiles.optJSONObject(i) ?: continue
                val chatManager = profile.optJSONObject("chatManager") ?: continue
                if (chatManager.length() == 0) profile.remove("chatManager")
            }
        }
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
     * The index of the account's record in `profiles` (§25.52B.6, §25.52H.3): the profile whose keyID is the account, compared without case.
     * While no profile carries a keyID, the measured layout's `profiles[0]` is the account (§25.52B.6, "until confirmed"). Several matches, or
     * a keyID that belongs to another account only, give no slot. Nothing is guessed among profiles.
     */
    fun accountSlot(record: JSONObject, eoa: String): Int? {
        val profiles = record.optJSONArray("profiles") ?: return null
        val ids: List<String> = (0 until profiles.length()).map { profiles.optJSONObject(it)?.optString("keyID", "").orEmpty() }
        val matches = ids.indices.filter { ids[it].isNotEmpty() && ids[it].equals(eoa, ignoreCase = true) }
        if (matches.size == 1) return matches[0]
        if (matches.size > 1) return null
        if (ids.none { it.isNotEmpty() } && profiles.length() >= 1) return 0
        return null
    }

    /** True when some profile of [record] holds [key]. */
    private fun hasProfileKey(record: JSONObject, key: String): Boolean {
        val profiles = record.optJSONArray("profiles") ?: return false
        return (0 until profiles.length()).any { profiles.optJSONObject(it)?.has(key) == true }
    }

    /**
     * The page's record merged with the stored W fields (§25.52H.2, §25.52H.3). An omitted W field keeps the stored value. The same value is
     * accepted. A different value, including `null`, is a conflict, and nothing is overwritten. The W slot is the account's record (see
     * [accountSlot]). The page must carry the account's record too, or an omission would delete the stored W field: that is a conflict. A
     * stored W field that no account slot can hold is a conflict as well. Returns the merged record and the conflicting paths.
     */
    fun mergeWallet(page: JSONObject, stored: JSONObject, eoa: String): Pair<JSONObject, List<String>> {
        val out = JSONObject(page.toString())
        val conflicts = mutableSetOf<String>()
        mergeKey(page, stored, out, "mnemonic", "mnemonic", conflicts)
        val storedVault = stored.optJSONObject("walletVault")
        if (storedVault != null && storedVault.has("mnemonic")) {
            if (out.optJSONObject("walletVault") == null) out.put("walletVault", JSONObject())
            mergeKey(
                page.optJSONObject("walletVault"),
                storedVault,
                out.optJSONObject("walletVault"),
                "mnemonic",
                "walletVault.mnemonic",
                conflicts,
            )
        }
        val name = "profiles[*].privateKeyArmor"
        val storedSlot = accountSlot(stored, eoa)
        val pageSlot = accountSlot(page, eoa)
        val storedProfile = storedSlot?.let { stored.optJSONArray("profiles")?.optJSONObject(it) }
        if (storedProfile != null && storedProfile.has("privateKeyArmor")) {
            if (pageSlot == null) {
                conflicts += name
            } else {
                val pageProfile = page.optJSONArray("profiles")?.optJSONObject(pageSlot)
                mergeKey(pageProfile, storedProfile, out.optJSONArray("profiles")?.optJSONObject(pageSlot), "privateKeyArmor", name, conflicts)
            }
        } else if (storedSlot == null && hasProfileKey(stored, "privateKeyArmor")) {
            conflicts += name
        }
        return out to conflicts.sorted()
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
        if (bytes.size < 1 + 13 || bytes[0] != FORMAT_VERSION[0]) throw IOException("page record is malformed")
        val plain = wrap.open(aad, bytes.copyOfRange(1, bytes.size)) ?: throw IOException("page record does not open")
        return try {
            JSONObject(String(plain, Charsets.UTF_8))
        } catch (_: Exception) {
            throw IOException("page record is malformed")
        } finally {
            plain.fill(0)
        }
    }

    /** Replaces the whole record in one step. Throws [IOException] on any failure, and the earlier record is unchanged. */
    fun write(record: JSONObject) {
        val plain = record.toString().toByteArray(Charsets.UTF_8)
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
        private val FORMAT_VERSION = byteArrayOf(1)
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
        if (sealed.size < 13) return null
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

    override fun deleteKey() {
        try {
            keyStore().deleteEntry(alias)
        } catch (_: Exception) {
        }
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

    /** The vault is locked and no account is bound. */
    object Locked : ShellRecordAccount()
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
            outcome.set(ImportOutcome.NOT_DONE)
            return ShellImportCode.ADDRESS_MISMATCH
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
        val derived = profile?.optString("privateKeyArmor", "")?.let { addressOf(it) }
        if (profile == null || derived == null || !derived.equals(eoa, ignoreCase = true)) {
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
 * The bridge logic of `shellRecordRead`, `shellRecordWrite` and `shellRecordMigrationState` (§25.52D.6, §25.52D.7, §25.52E, §25.52K.4). The
 * checks run in the order the spec gives: origin, reqId, fields, size, the record's own checks, the account, the migration state, and the
 * revision. Each request gets exactly one response.
 */
internal class ShellRecordBridge(
    private val account: () -> ShellRecordAccount,
    private val migrating: () -> Boolean,
    private val migrationState: () -> String,
    private val outcome: () -> ImportOutcome?,
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
        val reply: (String, ShellReplyFields) -> JSONObject = { code, extra ->
            val out = JSONObject().put("type", "shellRecordResult").put("reqId", echo).put("code", code)
            for ((k, v) in extra) out.put(k, v ?: JSONObject.NULL)
            out
        }

        if (origin != ShellOrigin.EMBEDDED_PAGE) return reply("origin_refused", emptyList())
        if (!idOk) return reply("bad_request", emptyList())

        val allowed = when (type) {
            "shellRecordRead" -> ShellRecordPolicy.READ_FIELDS
            "shellRecordWrite" -> ShellRecordPolicy.WRITE_FIELDS
            "shellRecordMigrationState" -> ShellRecordPolicy.MIGRATION_STATE_FIELDS
            else -> return reply("bad_request", emptyList())
        }
        val extra = ShellRecordPolicy.keysOf(body).filter { it !in allowed }.sorted()
        if (extra.isNotEmpty()) return reply("bad_request", listOf("names" to JSONArray(extra)))

        return when (type) {
            "shellRecordRead" -> read(reply)
            "shellRecordWrite" -> write(body, requestBytes, nativeWrite, reply)
            else -> reply("ok", listOf("state" to migrationState()))
        }
    }

    private fun read(reply: (String, ShellReplyFields) -> JSONObject): JSONObject {
        val acc = account()
        if (acc is ShellRecordAccount.Locked) return reply("error", listOf("sub" to "locked"))
        if (migrating()) return reply("migrating", emptyList())
        if (acc is ShellRecordAccount.Ready) {
            val current: JSONObject?
            try {
                current = acc.store.read()
            } catch (_: IOException) {
                return reply("error", listOf("sub" to "record_unreadable"))
            }
            if (current != null) {
                val rev = current.opt("rev")
                if (rev !is Int) return reply("error", listOf("sub" to "record_unreadable"))
                ShellRecordPolicy.stripPgpForRead(current)
                val out = reply(
                    "ok",
                    listOf("rev" to rev, "schemaVersion" to ShellRecordPolicy.RESPONSE_SCHEMA, "record" to current),
                )
                if (out.toString().toByteArray(Charsets.UTF_8).size > ShellRecordPolicy.MAX_BYTES) {
                    return reply("too_large", emptyList())
                }
                return out
            }
        }
        // No copy. `absent` is answered only when the legacy store is confirmed absent (§25.52K.4).
        return when (outcome()) {
            null -> reply("migrating", emptyList())
            ImportOutcome.ABSENT -> reply("absent", emptyList())
            ImportOutcome.LEGACY_UNREADABLE -> reply("error", listOf("sub" to "legacy_store_unreadable"))
            ImportOutcome.NOT_DONE, ImportOutcome.DONE -> reply("error", listOf("sub" to "import_not_done"))
        }
    }

    private fun write(
        body: JSONObject,
        requestBytes: Int,
        nativeWrite: Boolean,
        reply: (String, ShellReplyFields) -> JSONObject,
    ): JSONObject {
        if (requestBytes > ShellRecordPolicy.MAX_BYTES) return reply("too_large", emptyList())
        val record = body.optJSONObject("record") ?: return reply("bad_request", emptyList())
        val rev = record.opt("rev")
        if (rev !is Int) return reply("bad_request", emptyList())

        ShellRecordPolicy.preWriteRefusal(record)?.let { (code, names) ->
            return if (names.isEmpty()) reply(code, emptyList()) else reply(code, listOf("names" to JSONArray(names)))
        }

        val acc = account()
        if (acc is ShellRecordAccount.Locked) return reply("error", listOf("sub" to "locked"))
        val ready = acc as? ShellRecordAccount.Ready
        val store = ready?.store
        val current: JSONObject? = if (store == null) {
            null
        } else {
            try {
                store.read()
            } catch (_: IOException) {
                return reply("error", listOf("sub" to "record_unreadable"))
            }
        }

        // W fields (§25.52J.2, §25.52F.5, R412): a copy that holds W fields takes only schema 2 writes, so an older or schema-less page
        // cannot drop or change them. Without a stored copy, a W field needs schema 2 as well.
        val schema = record.opt("schemaVersion")
        val storedWallet = current?.let { ShellRecordPolicy.walletIn(it) }.orEmpty()
        if (storedWallet.isNotEmpty() && (schema !is Int || schema < ShellRecordPolicy.WALLET_SCHEMA_MIN)) {
            return reply("wallet_copy_not_approved", listOf("names" to JSONArray(storedWallet)))
        }
        if (schema !is Int) return reply("bad_request", emptyList())
        val wallet = ShellRecordPolicy.walletIn(record)
        if (wallet.isNotEmpty() && schema < ShellRecordPolicy.WALLET_SCHEMA_MIN) {
            return reply("wallet_copy_not_approved", listOf("names" to JSONArray(wallet)))
        }
        val violations = ShellRecordPolicy.whitelistViolations(record)
        if (violations.isNotEmpty()) return reply("bad_request", listOf("names" to JSONArray(violations)))

        if (migrating()) return reply("migrating", emptyList())
        if (current == null) {
            // No copy yet: the first write only after the import has established the state (§25.52K.4). Never a new wallet on failure.
            when (outcome()) {
                null -> return reply("migrating", emptyList())
                ImportOutcome.ABSENT -> if (store == null) return reply("error", listOf("sub" to "no_key"))
                ImportOutcome.LEGACY_UNREADABLE -> return reply("error", listOf("sub" to "legacy_store_unreadable"))
                ImportOutcome.NOT_DONE, ImportOutcome.DONE -> return reply("error", listOf("sub" to "import_not_done"))
            }
        }
        val target = store ?: return reply("error", listOf("sub" to "no_key"))

        // The first write must carry rev 0 (§25.52E.3). A later write must carry the current rev.
        val currentRev = (current?.opt("rev") as? Int) ?: 0
        if (rev != currentRev) return reply("conflict", listOf("currentRev" to currentRev))

        // The W fields (§25.52H.2): an omitted field keeps the stored one, the same value is accepted, a different value is a conflict.
        // Only the native creation or recovery replaces them.
        val merged = when {
            nativeWrite || current == null -> JSONObject(record.toString())
            else -> {
                val (out, conflicts) = ShellRecordPolicy.mergeWallet(record, current, ready?.eoa.orEmpty())
                if (conflicts.isNotEmpty()) {
                    return reply(
                        "conflict",
                        listOf("currentRev" to currentRev, "reason" to "w_differs", "names" to JSONArray(conflicts)),
                    )
                }
                out
            }
        }
        val next = currentRev + 1
        val toStore = merged.put("rev", next)
        return try {
            target.write(toStore)
            reply("ok", listOf("rev" to next))
        } catch (_: IOException) {
            reply("write_failed", emptyList())
        }
    }
}

/** The state the production bridge shares: the import outcome, the bound account and the startup flag. One process, one account. */
internal object ShellRecordState {
    val outcome: AtomicReference<ImportOutcome?> = AtomicReference(null)
    val bound: AtomicReference<String?> = AtomicReference(null)
    val migrationPending: AtomicBoolean = AtomicBoolean(false)
}

/**
 * The public entry of the page-record bridge for the Android shell (§25.52G, §25.52K). The shell verifies the origin of the message
 * (`https://appassets.androidplatform.net`, through `WebViewCompat.addWebMessageListener`) and passes the result as [ShellOrigin]. The
 * returned object is the reply to that message. The calls read and write files: run them off the main thread.
 */
object BeamioShellRecordImport {
    /** Set by the shell while its start-up import and migration (§25.52K.3) are not finished. Reads and writes then answer `migrating`. */
    fun setMigrationPending(pending: Boolean) {
        ShellRecordState.migrationPending.set(pending)
    }

    /** Answers one page request. [requestBytes] is the size of the message as received, in UTF-8 bytes. */
    fun handle(context: Context, origin: ShellOrigin, body: JSONObject, requestBytes: Int): JSONObject =
        bridge(context).handle(origin, body, requestBytes)

    /**
     * Writes the whole record from the native account creation or recovery, which may replace the W fields (§25.52H.2, rule 4). The page
     * never calls this. The revision follows the page rule: the record's `rev` must equal the current one.
     */
    fun writeWalletNative(context: Context, record: JSONObject): JSONObject {
        val body = JSONObject().put("type", "shellRecordWrite").put("reqId", 0).put("record", record)
        val bytes = body.toString().toByteArray(Charsets.UTF_8).size
        return bridge(context).handle(ShellOrigin.EMBEDDED_PAGE, body, bytes, nativeWrite = true)
    }

    /** The first-run import (§25.52K), called by [BeamioPgpMigrationImport.importFirstRun]. */
    internal fun importFirstRun(
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
        if (code == ShellImportCode.IMPORT_OK || code == ShellImportCode.EXISTS) ShellRecordState.bound.set(eoa)
        return code
    }

    private fun bridge(context: Context): ShellRecordBridge = ShellRecordBridge(
        account = { accountOf(context) },
        migrating = { ShellRecordState.migrationPending.get() },
        migrationState = { migrationStateOf(context) },
        outcome = { ShellRecordState.outcome.get() },
    )

    private fun accountOf(context: Context): ShellRecordAccount {
        val app = context.applicationContext
        val bound = ShellRecordState.bound.get()
        return when (val state = NativeWallet.vault(app).state()) {
            is NativeWalletVault.State.Ready -> ShellRecordAccount.Ready(storeFor(app, state.eoa.lowercase()), state.eoa.lowercase())
            else -> when {
                bound != null -> ShellRecordAccount.Ready(storeFor(app, bound), bound)
                state is NativeWalletVault.State.Locked -> ShellRecordAccount.Locked
                else -> ShellRecordAccount.Unknown
            }
        }
    }

    private fun storeFor(app: Context, eoa: String): SealedPageRecordStore {
        val files = AndroidVaultFiles(File(app.noBackupFilesDir, "page_record_v1"))
        return SealedPageRecordStore(AndroidPageRecordKeyWrap(), files, eoa.lowercase() + ":" + PgpMigrationPolicy.WORKSPACE)
    }

    private fun migrationStateOf(context: Context): String {
        val app = context.applicationContext
        val state = NativeWallet.vault(app).state() as? NativeWalletVault.State.Ready ?: return "none"
        return BeamioPgpMigrationImport.state(app, state.eoa)
    }

    /** The EOA address of a private-key string (`0x` plus 64 hex digits), lower case, or `null`. The key bytes are zero-filled after use. */
    private fun addressOfPrivateKey(armor: String): String? {
        val hex = armor.removePrefix("0x")
        if (hex.length != 64) return null
        val key = try {
            ByteArray(32) { i -> hex.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
        } catch (_: NumberFormatException) {
            return null
        }
        try {
            return WalletAddress.fromPrivateKey(key)
        } finally {
            key.fill(0)
        }
    }
}
