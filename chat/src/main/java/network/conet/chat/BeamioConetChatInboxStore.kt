package network.conet.chat

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Inbound messages the app has not confirmed yet (no `ackInbound`), kept on
 * disk so a message received while the page is not running (call push, page
 * suspended or killed) reaches the page when it starts.
 *
 * Holds only the OpenPGP armor as received (still encrypted to the user PGP
 * key) plus its hash; it is decrypted again when handed over. Lives in
 * `noBackupFilesDir` (never in backups). Entries leave on ACK, after [TTL_MS],
 * or past [MAX_ENTRIES] (oldest first); the mailbox keeps its own copy until the
 * ACK either way.
 */
internal object BeamioConetChatInboxStore {
    private const val TAG = "BeamioConetChat"
    private const val FILE = "conet_chat_inbox_v1.json"
    private const val MAX_ENTRIES = 500
    private const val TTL_MS = 7L * 24 * 60 * 60 * 1000

    data class Entry(val armorHash: String, val armor: String, val viaDomain: String, val at: Long)

    private val lock = Any()

    private fun file(context: Context) = File(context.applicationContext.noBackupFilesDir, FILE)

    private fun readAll(context: Context): MutableList<Entry> {
        val f = file(context)
        if (!f.exists()) return mutableListOf()
        return try {
            val arr = JSONArray(f.readText())
            val now = System.currentTimeMillis()
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.optJSONObject(i) ?: return@mapNotNull null
                val e = Entry(o.optString("h"), o.optString("a"), o.optString("v"), o.optLong("t"))
                e.takeIf { it.armorHash.isNotEmpty() && it.armor.contains("BEGIN PGP MESSAGE") && now - it.at < TTL_MS }
            }.toMutableList()
        } catch (e: Exception) {
            Log.w(TAG, "inbox store unreadable; starting empty")
            mutableListOf()
        }
    }

    private fun writeAll(context: Context, entries: List<Entry>) {
        val arr = JSONArray()
        for (e in entries.takeLast(MAX_ENTRIES)) {
            arr.put(JSONObject().put("h", e.armorHash).put("a", e.armor).put("v", e.viaDomain).put("t", e.at))
        }
        val f = file(context)
        val tmp = File(f.parentFile, "$FILE.tmp")
        try {
            tmp.writeText(arr.toString())
            if (!tmp.renameTo(f)) {
                f.delete()
                tmp.renameTo(f)
            }
        } catch (e: Exception) {
            Log.w(TAG, "inbox store write failed")
        }
    }

    fun put(context: Context, armorHash: String, armor: String, viaDomain: String) {
        if (armorHash.isEmpty() || !armor.contains("BEGIN PGP MESSAGE")) return
        synchronized(lock) {
            val all = readAll(context)
            if (all.any { it.armorHash == armorHash }) return
            all.add(Entry(armorHash, armor, viaDomain, System.currentTimeMillis()))
            writeAll(context, all)
        }
    }

    fun remove(context: Context, armorHashes: Collection<String>) {
        if (armorHashes.isEmpty()) return
        synchronized(lock) {
            val all = readAll(context)
            if (all.removeAll { it.armorHash in armorHashes }) writeAll(context, all)
        }
    }

    fun list(context: Context): List<Entry> = synchronized(lock) { readAll(context) }

    /** True only when the inbox file is gone (spec 25.52PY.8 (4)). */
    fun clear(context: Context): Boolean = synchronized(lock) {
        val f = file(context)
        runCatching { f.delete() }
        !f.exists()
    }
}
