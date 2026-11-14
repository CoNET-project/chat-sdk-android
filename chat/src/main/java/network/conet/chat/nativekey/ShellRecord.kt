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
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The page-record bridge of the native layer (spec r3az §25.52D, §25.52E, §25.52F; Android SDK per PM R389). The page keeps its
 * record here. The commands are `shellRecordRead`, `shellRecordWrite` and, native-only, `shellRecordMigrationState`. The record
 * holds the wallet copy (W class: the EOA private key and the mnemonic) as an encrypted native copy (§25.52F.3). A read strips the
 * W fields, so no key field goes back through the WebView (§25.52F.4). Nothing here logs record content.
 */
enum class ShellOrigin {
    /** The embedded page, as the shell's origin check (§25.52D.5) verified it. */
    EMBEDDED_PAGE,

    /** Any other origin: refused with `origin_refused`. */
    OTHER,
}

/** The rules of §25.52D.5 to §25.52D.8 and §25.52F. */
internal object ShellRecordPolicy {
    /** A request and a response are each at most 2 MB, in UTF-8 bytes (§25.52D.5). */
    const val MAX_BYTES = 2 * 1024 * 1024

    /** The bridge response schema (§25.52D.6). The record's own `schemaVersion` is separate. */
    const val RESPONSE_SCHEMA = 1

    /** The record schema that may hold W fields (§25.52F.5). Older pages get `wallet_copy_not_approved`. */
    const val WALLET_SCHEMA_MIN = 2

    const val PGP_HEADER = "BEGIN PGP PRIVATE KEY"

    /** §25.52D.8: paths that never enter the page record. */
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

    /** §25.52D.8: W-class paths (the EOA private key and the mnemonic). Held only in a record of [WALLET_SCHEMA_MIN] or later. */
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

    /** The top-level keys: the schema and revision (§25.52E.3), the profiles, and the W key `mnemonic`. */
    val TOP_KEYS: Set<String> = setOf("schemaVersion", "rev", "profiles", "mnemonic", "walletVault")

    val CHAT_MANAGER_KEYS: Set<String> = setOf("router", "pgpKey")
    val PGP_KEY_PUBLIC_KEYS: Set<String> = setOf("publicKey", "keyID")

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

    /** The W-class paths present in [record], sorted (§25.52D.8). */
    fun walletIn(record: JSONObject): List<String> = pathsOf(record).filter { it in WALLET_PATHS }.sorted()

    /**
     * The native pre-write check (§25.52E.5, the native half of PW-01 and PW-02). A PGP header or a forbidden path refuses the
     * write as `pgp_private_in_payload`. The header refusal carries no names (§25.52D.6). Returns the code and the names, or
     * `null` when the record is clean.
     */
    fun preWriteRefusal(record: JSONObject): Pair<String, List<String>>? {
        if (hasPgpHeader(record)) return "pgp_private_in_payload" to emptyList()
        val names = forbiddenIn(record)
        return if (names.isEmpty()) null else "pgp_private_in_payload" to names
    }

    /**
     * Whitelist violations of §25.52D.8, sorted. The W paths are left out: they are checked against the schema. A record with a key
     * outside the whitelist is refused as `bad_request`, with the path.
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
            when (key) {
                "router" -> Unit
                "pgpKey" -> {
                    val pgpKey = chatManager.optJSONObject(key)
                    if (pgpKey == null) {
                        out += "profiles[*].chatManager.pgpKey"
                    } else {
                        for (k in keysOf(pgpKey)) if (k !in PGP_KEY_PUBLIC_KEYS) out += "profiles[*].chatManager.pgpKey.$k"
                    }
                }
                else -> out += "profiles[*].chatManager.$key"
            }
        }
    }

    /**
     * The read copy of a record (§25.52F.4): removes the W fields and any forbidden path, in place. Returns `true` when a W field
     * was removed, which the response reports as `walletFieldsRedacted`.
     */
    fun stripForRead(record: JSONObject): Boolean {
        val wallet = walletIn(record)
        for (path in wallet) removePath(record, path.split('.'))
        for (path in forbiddenIn(record)) removePath(record, path.split('.'))
        record.optJSONObject("walletVault")?.let { vault -> if (vault.length() == 0) record.remove("walletVault") }
        return wallet.isNotEmpty()
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
     * The page's record merged with the stored W fields (§25.52H.2). An omitted W field keeps the stored value. The same value is
     * accepted. A different value, including `null`, is a conflict, and nothing is overwritten. The W slot of a profile is the same
     * index (the measured layout puts the account at `profiles[0]`, §25.52H.3). A stored W field that the page does not carry at
     * all (no such profile) is a conflict too, so an omission never deletes it. Returns the merged record and the conflicting paths.
     */
    fun mergeWallet(page: JSONObject, stored: JSONObject): Pair<JSONObject, List<String>> {
        val out = JSONObject(page.toString())
        val conflicts = mutableSetOf<String>()
        mergeKey(page, stored, out, "mnemonic", "mnemonic", conflicts)
        val storedVault = stored.optJSONObject("walletVault")
        if (storedVault != null && storedVault.has("mnemonic")) {
            if (out.optJSONObject("walletVault") == null) out.put("walletVault", JSONObject())
            mergeKey(page.optJSONObject("walletVault"), storedVault, out.optJSONObject("walletVault"), "mnemonic", "walletVault.mnemonic", conflicts)
        }
        val storedProfiles = stored.optJSONArray("profiles")
        if (storedProfiles != null) {
            val pageProfiles = page.optJSONArray("profiles")
            val outProfiles = out.optJSONArray("profiles")
            for (i in 0 until storedProfiles.length()) {
                val storedProfile = storedProfiles.optJSONObject(i) ?: continue
                if (!storedProfile.has("privateKeyArmor")) continue
                val pageProfile = pageProfiles?.optJSONObject(i)
                if (pageProfile == null) {
                    conflicts += "profiles[*].privateKeyArmor"
                    continue
                }
                mergeKey(pageProfile, storedProfile, outProfiles?.optJSONObject(i), "privateKeyArmor", "profiles[*].privateKeyArmor", conflicts)
            }
        }
        return out to conflicts.sorted()
    }

    private fun mergeKey(page: JSONObject?, stored: JSONObject, out: JSONObject?, key: String, name: String, conflicts: MutableSet<String>) {
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
 * The page store for one account: the whole record, W fields included, sealed with the non-exportable Keystore key (§25.52F.3).
 * The file is one version byte, then the AEAD output. The AAD is the account key (`eoa:default`, lower case) and the version byte.
 * A file that does not open is unreadable. There is no plaintext fallback.
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
 * The Keystore key of the page store (§25.52F.3): AES-256-GCM, not exportable, randomized encryption required, StrongBox when
 * available and the TEE otherwise. Not verified on a device in this build: the Keystore behaviour is a device-acceptance item.
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

/** What the bridge needs about the account before it can answer: a refusal sub-code, or the store. */
internal sealed class ShellRecordAccount {
    /** `error` with the sub-code: `no_key` or `locked`. The page answers no record without a wallet. */
    class Refused(val sub: String) : ShellRecordAccount()

    class Ready(val store: SealedPageRecordStore) : ShellRecordAccount()
}

/**
 * The bridge logic of `shellRecordRead`, `shellRecordWrite` and `shellRecordMigrationState` (§25.52D.6, §25.52D.7, §25.52E.2,
 * §25.52E.3). The checks run in the order the spec gives: origin, reqId, fields, size, the record's own checks, the account, the
 * migration state, and the revision. Each request gets exactly one response.
 */
internal class ShellRecordBridge(
    private val account: () -> ShellRecordAccount,
    private val migrating: () -> Boolean,
    private val migrationState: () -> String,
) {
    /**
     * [nativeWrite] is true only for the native account creation or recovery (§25.52H.2, rule 4). It lets a write replace the W
     * fields. The page path never sets it.
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
        if (acc is ShellRecordAccount.Refused) return reply("error", listOf("sub" to acc.sub))
        if (migrating()) return reply("migrating", emptyList())
        val store = (acc as ShellRecordAccount.Ready).store
        val current: JSONObject?
        try {
            current = store.read()
        } catch (_: IOException) {
            return reply("error", listOf("sub" to "record_unreadable"))
        }
        if (current == null) return reply("absent", emptyList())
        val rev = current.opt("rev")
        if (rev !is Int) return reply("error", listOf("sub" to "record_unreadable"))
        val redacted = ShellRecordPolicy.stripForRead(current)
        val out = reply(
            "ok",
            listOf("rev" to rev, "schemaVersion" to ShellRecordPolicy.RESPONSE_SCHEMA, "record" to current),
        )
        if (redacted) out.put("walletFieldsRedacted", true)
        if (out.toString().toByteArray(Charsets.UTF_8).size > ShellRecordPolicy.MAX_BYTES) return reply("too_large", emptyList())
        return out
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
        val schema = record.opt("schemaVersion")
        if (rev !is Int || schema !is Int) return reply("bad_request", emptyList())

        ShellRecordPolicy.preWriteRefusal(record)?.let { (code, names) ->
            return if (names.isEmpty()) reply(code, emptyList()) else reply(code, listOf("names" to JSONArray(names)))
        }
        val wallet = ShellRecordPolicy.walletIn(record)
        if (wallet.isNotEmpty() && schema < ShellRecordPolicy.WALLET_SCHEMA_MIN) {
            return reply("wallet_copy_not_approved", listOf("names" to JSONArray(wallet)))
        }
        val violations = ShellRecordPolicy.whitelistViolations(record)
        if (violations.isNotEmpty()) return reply("bad_request", listOf("names" to JSONArray(violations)))

        val acc = account()
        if (acc is ShellRecordAccount.Refused) return reply("error", listOf("sub" to acc.sub))
        if (migrating()) return reply("migrating", emptyList())
        val store = (acc as ShellRecordAccount.Ready).store

        val current: JSONObject?
        try {
            current = store.read()
        } catch (_: IOException) {
            return reply("error", listOf("sub" to "record_unreadable"))
        }
        // The first write must carry rev 0 (§25.52E.3). A later write must carry the current rev.
        val currentRev = (current?.opt("rev") as? Int) ?: 0
        if (rev != currentRev) return reply("conflict", listOf("currentRev" to currentRev))

        // The W fields (§25.52H.2): an omitted field keeps the stored one, the same value is accepted, a different value is a
        // conflict. Only the native creation or recovery replaces them.
        val merged = when {
            nativeWrite || current == null -> JSONObject(record.toString())
            else -> {
                val (out, conflicts) = ShellRecordPolicy.mergeWallet(record, current)
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
            store.write(toStore)
            reply("ok", listOf("rev" to next))
        } catch (_: IOException) {
            reply("write_failed", emptyList())
        }
    }
}

/**
 * The public entry of the page-record bridge for the Android shell (§25.52D.5, §25.52F). The shell verifies the origin of the
 * message (`https://appassets.androidplatform.net`, through `WebViewCompat.addWebMessageListener`) and passes the result as
 * [ShellOrigin]. The returned object is the reply to that message. The calls read and write files: run them off the main thread.
 */
object BeamioShellRecordImport {
    /** Set by the shell while its start-up migration (§25.52D.9) is not finished. Reads and writes then answer `migrating`. */
    private val migrationPending = AtomicBoolean(false)

    fun setMigrationPending(pending: Boolean) {
        migrationPending.set(pending)
    }

    /** Answers one page request. [requestBytes] is the size of the message as received, in UTF-8 bytes. */
    fun handle(context: Context, origin: ShellOrigin, body: JSONObject, requestBytes: Int): JSONObject =
        bridge(context).handle(origin, body, requestBytes)

    /**
     * Writes the whole record from the native account creation or recovery, which may replace the W fields (§25.52H.2, rule 4).
     * The page never calls this. The revision follows the page rule: the record's `rev` must equal the current one.
     */
    fun writeWalletNative(context: Context, record: JSONObject): JSONObject {
        val body = JSONObject().put("type", "shellRecordWrite").put("reqId", 0).put("record", record)
        val bytes = body.toString().toByteArray(Charsets.UTF_8).size
        return bridge(context).handle(ShellOrigin.EMBEDDED_PAGE, body, bytes, nativeWrite = true)
    }

    private fun bridge(context: Context): ShellRecordBridge = ShellRecordBridge(
        account = { accountOf(context) },
        migrating = { migrationPending.get() },
        migrationState = { migrationStateOf(context) },
    )

    private fun accountOf(context: Context): ShellRecordAccount {
        val app = context.applicationContext
        return when (val state = NativeWallet.vault(app).state()) {
            is NativeWalletVault.State.NoKey -> ShellRecordAccount.Refused("no_key")
            is NativeWalletVault.State.Locked -> ShellRecordAccount.Refused("locked")
            is NativeWalletVault.State.Ready -> {
                val accountKey = state.eoa.lowercase() + ":" + PgpMigrationPolicy.WORKSPACE
                val files = AndroidVaultFiles(File(app.noBackupFilesDir, "page_record_v1"))
                ShellRecordAccount.Ready(SealedPageRecordStore(AndroidPageRecordKeyWrap(), files, accountKey))
            }
        }
    }

    private fun migrationStateOf(context: Context): String {
        val app = context.applicationContext
        val state = NativeWallet.vault(app).state() as? NativeWalletVault.State.Ready ?: return "none"
        return BeamioPgpMigrationImport.state(app, state.eoa)
    }
}
