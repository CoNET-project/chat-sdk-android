package network.conet.chat

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException

/**
 * Permanent store for the user **PGP** key, the mailbox route public key and the
 * Guardian **SI IP roster**. Used so a killed app can still decrypt a mailbox
 * `voice_offer_fetch` and POST to entries.
 *
 * Never stores the EOA private key, the mnemonic, or the PGP private key. The PGP private key lives in the native
 * vault (`nativekey.NativePgpVault`, spec §25.22.2). Only [legacyPrivateArmor] still reads an older copy, once, for
 * migration. Backed by EncryptedSharedPreferences.
 */
object BeamioChatPgpStore {
    private const val PREFS = "beamio_chat_pgp_v1"
    /** Fallback file when EncryptedSharedPreferences fails: never holds a private key. */
    private const val PREFS_PLAIN = "beamio_chat_pgp_plain_v1"
    private const val KEY_PRIVATE = "userPgpPrivateArmor"
    private const val KEY_PUBLIC = "userPgpPublicArmor"
    private const val KEY_KEY_ID = "userPgpKeyId"
    private const val KEY_ROUTE = "mailboxRoutePublicArmor"
    private const val KEY_ENTRIES = "entryDomainsJson"
    private const val KEY_SI_NODES = "siNodesJson"
    private const val KEY_MAILBOX_IP = "mailboxIp"
    private const val KEY_EOA = "recipientEoa"
    private const val TAG = "BeamioChatPgp"

    /**
     * Host hook: the PWA pushed a roster payload. The shell refreshes `getAllNodes`
     * itself and ignores the PWA rows (see [upsertRoster]).
     */
    @Volatile
    @JvmField
    var onRosterUpsertFromWeb: ((Context) -> Unit)? = null

    /**
     * A chain node. [armoredPublicKey] is its PGP route key. A node without one is never used as an entry, because the
     * entry wrap needs the key. Rosters stored before this field existed load with "" until a keyed roster replaces them.
     */
    data class SiNode(
        val ip: String,
        val domain: String = "",
        val region: String = "",
        val armoredPublicKey: String = "",
    )

    /** Public PGP material and routing. The PGP private key is not part of this model. */
    data class Secrets(
        val publicKeyArmor: String = "",
        val pgpKeyId: String = "",
        val routePublicKeyArmor: String = "",
        val entryDomains: List<String> = emptyList(),
        val siNodes: List<SiNode> = emptyList(),
        val mailboxIp: String = "",
        val eoa: String = "",
    ) {
        val hasRoutePublic: Boolean
            get() = routePublicKeyArmor.contains("BEGIN PGP PUBLIC KEY")
    }

    /** True when [prefs] is the encrypted store (the PGP private key goes only there). */
    @Volatile
    private var lastPrefsSecure = true

    private fun prefs(context: Context) = try {
        val masterKey = MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context.applicationContext,
            PREFS,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        ).also { lastPrefsSecure = true }
    } catch (error: Exception) {
        // Roster and public keys only: the private key is never written here.
        Log.w(TAG, "EncryptedSharedPreferences unavailable: ${error.javaClass.simpleName}")
        lastPrefsSecure = false
        context.applicationContext.getSharedPreferences(PREFS_PLAIN, Context.MODE_PRIVATE)
    }

    /**
     * Logout that keeps the legacy private copy L (r3av §25.52C.3): removes every other entry in both stores. L is the recovery
     * source of the PGP migration, so logout never removes it here.
     */
    fun clearKeepingLegacy(context: Context): Boolean {
        val stores = listOf(prefs(context), context.applicationContext.getSharedPreferences(PREFS_PLAIN, Context.MODE_PRIVATE))
        return stores.all { store ->
            runCatching {
                val editor = store.edit()
                store.all.keys.filter { it != KEY_PRIVATE }.forEach { editor.remove(it) }
                editor.commit()
            }.getOrDefault(false)
        }
    }

    /**
     * The EOA named by the legacy record L, for the account cleanup (25.52Y.91, `L` only of an old account). Null when there is no record;
     * throws when the store cannot be read.
     */
    internal fun legacyOwnerEoa(context: Context): String? =
        prefs(context).getString(KEY_EOA, "").orEmpty().trim().lowercase().ifEmpty { null }

    /** Removes the legacy record L of an old account. True only when no owner remains in the store. */
    internal fun clearLegacyRecord(context: Context): Boolean {
        clear(context)
        return runCatching { legacyOwnerEoa(context) == null }.getOrDefault(false)
    }

    /** Logout / wallet switch: forget the PGP key, route key and wallet binding. */
    fun clear(context: Context) {
        runCatching { prefs(context).edit().clear().commit() }
        runCatching {
            context.applicationContext.getSharedPreferences(PREFS_PLAIN, Context.MODE_PRIVATE).edit().clear().commit()
        }
    }

    /** Legacy copy of the PGP private key (written before the vault held it). Read once, for migration only. */
    fun legacyPrivateArmor(context: Context): String =
        prefs(context).getString(KEY_PRIVATE, "").orEmpty()

    /** Removes the legacy private copy. Not called by the PGP migration (r3as §25.52.3: L is kept in this version). */
    fun clearLegacyPrivateArmor(context: Context): Boolean =
        prefs(context).edit().remove(KEY_PRIVATE).commit()

    /** The legacy account record as stored: the account, the private armor and the public armor. Read only, no write path. */
    data class LegacyCopy(val eoa: String, val privateArmor: String, val publicArmor: String)

    /** The legacy record L (r3as §25.52.3), or `null` when no private armor is stored. Never writes and never clears. */
    fun legacyCopy(context: Context): LegacyCopy? {
        val p = prefs(context)
        val privateArmor = p.getString(KEY_PRIVATE, "").orEmpty()
        if (privateArmor.isEmpty()) return null
        return LegacyCopy(
            eoa = p.getString(KEY_EOA, "").orEmpty().trim().lowercase(),
            privateArmor = privateArmor,
            publicArmor = p.getString(KEY_PUBLIC, "").orEmpty(),
        )
    }

    /**
     * Stored public material. Throws [IOException] when the stored entry domains cannot be read: that state is unknown,
     * not empty, so no caller may write it back as an empty list.
     */
    @Throws(IOException::class)
    fun load(context: Context): Secrets? = loadFrom(prefs(context))

    @Throws(IOException::class)
    internal fun loadFrom(p: SharedPreferences): Secrets =
        Secrets(
            publicKeyArmor = p.getString(KEY_PUBLIC, "").orEmpty(),
            pgpKeyId = p.getString(KEY_KEY_ID, "").orEmpty(),
            routePublicKeyArmor = p.getString(KEY_ROUTE, "").orEmpty(),
            entryDomains = parseStoredEntryDomains(p.getString(KEY_ENTRIES, null)),
            siNodes = decodeSiNodes(p.getString(KEY_SI_NODES, "[]")),
            mailboxIp = p.getString(KEY_MAILBOX_IP, "").orEmpty(),
            eoa = p.getString(KEY_EOA, "").orEmpty(),
        )

    /**
     * Entry domains from the stored value. An absent value is an empty list; a value that is not a JSON array throws
     * [IOException] (unknown). A corrupt value never reads as empty.
     */
    @Throws(IOException::class)
    internal fun parseStoredEntryDomains(raw: String?): List<String> {
        if (raw == null) return emptyList()
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).mapNotNull { i ->
                arr.optString(i, "").trim().takeIf { it.isNotEmpty() }
            }
        } catch (e: Exception) {
            throw IOException("stored entry domains unreadable", e)
        }
    }

    fun save(context: Context, secrets: Secrets): Boolean = saveInto(prefs(context), lastPrefsSecure, secrets)

    internal fun saveInto(store: SharedPreferences, secure: Boolean, secrets: Secrets): Boolean {
        if (!secure) {
            Log.w(TAG, "secure store unavailable; public PGP material not saved")
            return false
        }
        val editor = store.edit()
        if (secrets.publicKeyArmor.isNotBlank()) {
            editor.putString(KEY_PUBLIC, secrets.publicKeyArmor)
        }
        if (secrets.pgpKeyId.isNotBlank()) {
            editor.putString(KEY_KEY_ID, secrets.pgpKeyId)
        }
        if (secrets.hasRoutePublic) {
            editor.putString(KEY_ROUTE, secrets.routePublicKeyArmor)
        }
        editor.putString(KEY_ENTRIES, JSONArray(secrets.entryDomains).toString())
        if (secrets.eoa.isNotBlank()) {
            editor.putString(KEY_EOA, secrets.eoa)
        }
        val ok = editor.commit()
        Log.i(
            TAG,
            "saved keyId=${secrets.pgpKeyId.take(12).ifBlank { "-" }} " +
                "route=${if (secrets.hasRoutePublic) "yes" else "no"} " +
                "entries=${secrets.entryDomains.size} " +
                "siNodes=${secrets.siNodes.size} " +
                "eoa=${secrets.eoa.take(10).ifBlank { "-" }}",
        )
        return ok
    }

    /**
     * Merge partial PWA JSON payload into existing store. Public fields only: a `privateKeyArmor` in the payload is
     * ignored and never stored (the vault holds the PGP private key).
     */
    fun upsertFromWeb(context: Context, json: String): Boolean {
        return try {
            upsertFromWeb(context, JSONObject(json.ifBlank { "{}" }))
        } catch (error: Exception) {
            Log.w(TAG, "upsert parse failed: ${error.message}")
            false
        }
    }

    fun upsertFromWeb(context: Context, body: JSONObject): Boolean {
        val p = prefs(context)
        return upsertInto(p, lastPrefsSecure, body)
    }

    /**
     * Writes the body's public fields over the stored ones. When the stored entry domains cannot be read the whole upsert is
     * refused and nothing is written, so an unknown stored list is never replaced by an empty one.
     */
    internal fun upsertInto(p: SharedPreferences, secure: Boolean, body: JSONObject): Boolean {
        val prev = try {
            loadFrom(p)
        } catch (_: IOException) {
            Log.w(TAG, "upsert refused: stored entry domains unreadable")
            return false
        }
        val domains = when {
            body.has("entryDomains") -> {
                val arr = body.optJSONArray("entryDomains")
                if (arr != null) {
                    (0 until arr.length()).mapNotNull { i ->
                        arr.optString(i, "").trim().takeIf { it.isNotEmpty() }
                    }
                } else {
                    prev.entryDomains
                }
            }
            else -> prev.entryDomains
        }
        val secrets = Secrets(
            publicKeyArmor = body.optString("publicKeyArmor", "").trim()
                .ifBlank { prev.publicKeyArmor },
            pgpKeyId = body.optString("pgpKeyId", "").trim()
                .ifBlank { prev.pgpKeyId },
            routePublicKeyArmor = body.optString("routePublicKeyArmor", "").trim()
                .ifBlank { prev.routePublicKeyArmor },
            entryDomains = domains,
            siNodes = prev.siNodes,
            mailboxIp = prev.mailboxIp,
            eoa = body.optString("eoa", "").trim()
                .ifBlank { prev.eoa },
        )
        return saveInto(p, secure, secrets)
    }

    /** PWA roster payloads are ignored. The shell refreshes `getAllNodes` itself. */
    @Suppress("UNUSED_PARAMETER")
    fun upsertRoster(context: Context, json: String): Boolean {
        onRosterUpsertFromWeb?.invoke(context)
        return true
    }

    fun loadSiNodes(context: Context): List<SiNode> =
        decodeSiNodes(prefs(context).getString(KEY_SI_NODES, null))

    fun loadMailboxIp(context: Context): String =
        prefs(context).getString(KEY_MAILBOX_IP, "").orEmpty()

    fun loadRoutePublicArmor(context: Context): String =
        prefs(context).getString(KEY_ROUTE, "").orEmpty()

    /** Chain refresh writer. Does not require a user PGP private key. */
    fun storeChainRoster(context: Context, nodes: List<SiNode>, mailboxIp: String?): Boolean {
        if (nodes.isEmpty()) return false
        val edit = prefs(context).edit().putString(KEY_SI_NODES, encodeSiNodes(nodes))
        if (!mailboxIp.isNullOrBlank()) edit.putString(KEY_MAILBOX_IP, mailboxIp)
        return edit.commit()
    }

    fun parseSiNodes(raw: Any?): List<SiNode> {
        val arr = when (raw) {
            is JSONArray -> raw
            is String -> try {
                JSONArray(raw)
            } catch (_: Exception) {
                return emptyList()
            }
            else -> return emptyList()
        }
        val out = ArrayList<SiNode>()
        for (i in 0 until arr.length()) {
            val item = arr.opt(i)
            if (item is String) {
                val ip = BeamioSiCipherPost.normalizeIp(item) ?: continue
                out.add(SiNode(ip))
                continue
            }
            val obj = arr.optJSONObject(i) ?: continue
            val ip = BeamioSiCipherPost.normalizeIp(
                obj.optString("ip", "").ifBlank { obj.optString("ip_addr", "") },
            ) ?: continue
            out.add(
                SiNode(
                    ip = ip,
                    domain = obj.optString("domain", "").trim(),
                    region = obj.optString("region", "").trim(),
                    armoredPublicKey = obj.optString("armoredPublicKey", "").trim(),
                ),
            )
        }
        return out
    }

    /**
     * Entries a post or a listen may use: nodes with a PGP route key, by normalized IP, minus [exclude]. A node
     * without a key is skipped. It is never posted to unwrapped.
     */
    fun keyedEntries(nodes: List<SiNode>, exclude: Set<String>): Map<String, SiNode> {
        val out = LinkedHashMap<String, SiNode>()
        for (node in nodes) {
            if (!node.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY")) continue
            val ip = BeamioSiCipherPost.normalizeIp(node.ip) ?: continue
            if (ip in exclude) continue
            out.putIfAbsent(ip, node)
        }
        return out
    }

    /**
     * The roster a background (no-page) listen starts from: the stored nodes that have a key. Null when none has one,
     * so the listen does not start. Opening the app once refreshes the roster with keys.
     */
    fun noPageRoster(stored: List<SiNode>): List<SiNode>? =
        keyedEntries(stored, emptySet()).values.toList().takeIf { it.isNotEmpty() }

    private fun decodeSiNodes(json: String?): List<SiNode> {
        if (json.isNullOrBlank()) return emptyList()
        return parseSiNodes(json)
    }

    internal fun encodeSiNodes(nodes: List<SiNode>): String {
        val arr = JSONArray()
        for (node in nodes) {
            arr.put(
                JSONObject()
                    .put("ip", node.ip)
                    .put("domain", node.domain)
                    .put("region", node.region)
                    .put("armoredPublicKey", node.armoredPublicKey),
            )
        }
        return arr.toString()
    }
}
