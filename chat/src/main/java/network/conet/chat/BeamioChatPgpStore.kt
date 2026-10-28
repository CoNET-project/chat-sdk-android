package network.conet.chat

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject

/**
 * Permanent store for the user **PGP** key, the mailbox route public key and the
 * Guardian **SI IP roster**. Used so a killed app can still decrypt a mailbox
 * `voice_offer_fetch` and POST to entries.
 *
 * Never stores the EOA private key or mnemonic. Backed by EncryptedSharedPreferences.
 */
object BeamioChatPgpStore {
    private const val PREFS = "beamio_chat_pgp_v1"
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

    data class SiNode(
        val ip: String,
        val domain: String = "",
        val region: String = "",
    )

    data class Secrets(
        val privateKeyArmor: String,
        val publicKeyArmor: String = "",
        val pgpKeyId: String = "",
        val routePublicKeyArmor: String = "",
        val entryDomains: List<String> = emptyList(),
        val siNodes: List<SiNode> = emptyList(),
        val mailboxIp: String = "",
        val eoa: String = "",
    ) {
        val hasUserPrivate: Boolean
            get() = privateKeyArmor.contains("BEGIN PGP PRIVATE KEY")
        val hasRoutePublic: Boolean
            get() = routePublicKeyArmor.contains("BEGIN PGP PUBLIC KEY")
    }

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
        )
    } catch (error: Exception) {
        Log.w(TAG, "EncryptedSharedPreferences fallback: ${error.message}")
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }

    fun load(context: Context): Secrets? {
        val p = prefs(context)
        val privateArmor = p.getString(KEY_PRIVATE, "").orEmpty()
        if (!privateArmor.contains("BEGIN PGP PRIVATE KEY")) return null
        val domainsJson = p.getString(KEY_ENTRIES, "[]").orEmpty()
        val domains = try {
            val arr = JSONArray(domainsJson)
            (0 until arr.length()).mapNotNull { i ->
                arr.optString(i, "").trim().takeIf { it.isNotEmpty() }
            }
        } catch (_: Exception) {
            emptyList()
        }
        return Secrets(
            privateKeyArmor = privateArmor,
            publicKeyArmor = p.getString(KEY_PUBLIC, "").orEmpty(),
            pgpKeyId = p.getString(KEY_KEY_ID, "").orEmpty(),
            routePublicKeyArmor = p.getString(KEY_ROUTE, "").orEmpty(),
            entryDomains = domains,
            siNodes = decodeSiNodes(p.getString(KEY_SI_NODES, "[]")),
            mailboxIp = p.getString(KEY_MAILBOX_IP, "").orEmpty(),
            eoa = p.getString(KEY_EOA, "").orEmpty(),
        )
    }

    fun save(context: Context, secrets: Secrets): Boolean {
        if (!secrets.hasUserPrivate) return false
        val editor = prefs(context).edit()
            .putString(KEY_PRIVATE, secrets.privateKeyArmor)
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

    /** Merge partial PWA JSON payload into existing store (private required). */
    fun upsertFromWeb(context: Context, json: String): Boolean {
        return try {
            upsertFromWeb(context, JSONObject(json.ifBlank { "{}" }))
        } catch (error: Exception) {
            Log.w(TAG, "upsert parse failed: ${error.message}")
            false
        }
    }

    fun upsertFromWeb(context: Context, body: JSONObject): Boolean {
        val privateArmor = body.optString("privateKeyArmor", "").trim()
        if (!privateArmor.contains("BEGIN PGP PRIVATE KEY")) return false
        val prev = load(context)
        val domains = when {
            body.has("entryDomains") -> {
                val arr = body.optJSONArray("entryDomains")
                if (arr != null) {
                    (0 until arr.length()).mapNotNull { i ->
                        arr.optString(i, "").trim().takeIf { it.isNotEmpty() }
                    }
                } else {
                    prev?.entryDomains.orEmpty()
                }
            }
            else -> prev?.entryDomains.orEmpty()
        }
        val secrets = Secrets(
            privateKeyArmor = privateArmor,
            publicKeyArmor = body.optString("publicKeyArmor", "").trim()
                .ifBlank { prev?.publicKeyArmor.orEmpty() },
            pgpKeyId = body.optString("pgpKeyId", "").trim()
                .ifBlank { prev?.pgpKeyId.orEmpty() },
            routePublicKeyArmor = body.optString("routePublicKeyArmor", "").trim()
                .ifBlank { prev?.routePublicKeyArmor.orEmpty() },
            entryDomains = domains,
            siNodes = prev?.siNodes ?: loadSiNodes(context),
            mailboxIp = prev?.mailboxIp ?: loadMailboxIp(context),
            eoa = body.optString("eoa", "").trim()
                .ifBlank { prev?.eoa.orEmpty() },
        )
        return save(context, secrets)
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
                ),
            )
        }
        return out
    }

    private fun decodeSiNodes(json: String?): List<SiNode> {
        if (json.isNullOrBlank()) return emptyList()
        return parseSiNodes(json)
    }

    private fun encodeSiNodes(nodes: List<SiNode>): String {
        val arr = JSONArray()
        for (node in nodes) {
            arr.put(
                JSONObject()
                    .put("ip", node.ip)
                    .put("domain", node.domain)
                    .put("region", node.region),
            )
        }
        return arr.toString()
    }
}
