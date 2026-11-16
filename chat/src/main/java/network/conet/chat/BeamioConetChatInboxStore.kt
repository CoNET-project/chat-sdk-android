package network.conet.chat

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException

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
 *
 * An inbox file that exists but cannot be read or parsed is unknown, not empty:
 * reads throw [IOException], and no caller writes the file back in that state.
 * The write never deletes the previous file before replacing it.
 */
internal object BeamioConetChatInboxStore {
    private const val TAG = "BeamioConetChat"
    private const val FILE = "conet_chat_inbox_v1.json"
    private const val MAX_ENTRIES = 500
    private const val TTL_MS = 7L * 24 * 60 * 60 * 1000

    data class Entry(val armorHash: String, val armor: String, val viaDomain: String, val at: Long)

    private val lock = Any()

    private val renameFile: (File, File) -> Boolean = { from, to -> from.renameTo(to) }

    private fun file(context: Context) = File(context.applicationContext.noBackupFilesDir, FILE)

    /**
     * A missing file is an empty inbox. A file that exists but cannot be read or
     * parsed throws [IOException]: the inbox is unknown, so the caller must not
     * treat it as empty and must not write it back.
     */
    internal fun readEntries(f: File): MutableList<Entry> {
        if (!f.exists()) return mutableListOf()
        val arr = try {
            JSONArray(f.readText())
        } catch (e: Exception) {
            throw IOException("inbox store unreadable", e)
        }
        val now = System.currentTimeMillis()
        return (0 until arr.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            val e = Entry(o.optString("h"), o.optString("a"), o.optString("v"), o.optLong("t"))
            e.takeIf { it.armorHash.isNotEmpty() && it.armor.contains("BEGIN PGP MESSAGE") && now - it.at < TTL_MS }
        }.toMutableList()
    }

    /**
     * Replaces [f] with [entries] through a temporary file. The previous file is
     * never deleted first: when the replace fails the previous file and the
     * temporary file are kept and the failure is thrown.
     */
    internal fun writeEntries(f: File, entries: List<Entry>, replace: (File, File) -> Boolean = renameFile) {
        val arr = JSONArray()
        for (e in entries.takeLast(MAX_ENTRIES)) {
            arr.put(JSONObject().put("h", e.armorHash).put("a", e.armor).put("v", e.viaDomain).put("t", e.at))
        }
        val tmp = File(f.parentFile, f.name + ".tmp")
        tmp.writeText(arr.toString())
        if (!replace(tmp, f)) throw IOException("inbox store replace failed; previous file kept")
    }

    internal fun putAt(f: File, armorHash: String, armor: String, viaDomain: String, replace: (File, File) -> Boolean = renameFile) {
        try {
            val all = readEntries(f)
            if (all.any { it.armorHash == armorHash }) return
            all.add(Entry(armorHash, armor, viaDomain, System.currentTimeMillis()))
            writeEntries(f, all, replace)
        } catch (e: IOException) {
            // Unknown or unwritable: the file is left as it is; the mailbox still holds the message until ACK.
            Log.e(TAG, "inbox store not updated; file kept")
        }
    }

    internal fun removeAt(f: File, armorHashes: Collection<String>, replace: (File, File) -> Boolean = renameFile) {
        try {
            val all = readEntries(f)
            if (all.removeAll { it.armorHash in armorHashes }) writeEntries(f, all, replace)
        } catch (e: IOException) {
            Log.e(TAG, "inbox store not updated; file kept")
        }
    }

    fun put(context: Context, armorHash: String, armor: String, viaDomain: String) {
        if (armorHash.isEmpty() || !armor.contains("BEGIN PGP MESSAGE")) return
        synchronized(lock) { putAt(file(context), armorHash, armor, viaDomain) }
    }

    fun remove(context: Context, armorHashes: Collection<String>) {
        if (armorHashes.isEmpty()) return
        synchronized(lock) { removeAt(file(context), armorHashes) }
    }

    /** Throws [IOException] when the inbox is unknown; callers must not read that as empty. */
    fun list(context: Context): List<Entry> = synchronized(lock) { readEntries(file(context)) }

    /** True only when the inbox file is gone (spec 25.52PY.8 (4)). */
    fun clear(context: Context): Boolean = synchronized(lock) {
        val f = file(context)
        runCatching { f.delete() }
        !f.exists()
    }
}
