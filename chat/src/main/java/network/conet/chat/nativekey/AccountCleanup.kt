package network.conet.chat.nativekey

import network.conet.chat.ChatHistoryFileNames
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException

/**
 * The persisted journal of one `accountCleanupOld` (25.52Y.91 第 7 項): the idempotencyKey, the new account, and the names already removed. It is
 * written before the first removal and after each one, so an interrupted run resumes with the same idempotencyKey and removes only what is left.
 * Read failures are thrown as [IOException]: the caller then removes nothing.
 */
internal class CleanupJournal(private val files: VaultFiles) {
    class State(val idempotencyKey: String, val newAccountKey: String, val done: MutableSet<String>)

    /** Null when there is no journal. Throws [IOException] when a journal is present and cannot be read. */
    fun read(): State? {
        val raw = files.read(NAME) ?: return null
        return try {
            val o = JSONObject(String(raw, Charsets.UTF_8))
            val arr = o.getJSONArray("done")
            State(
                idempotencyKey = o.getString("idempotencyKey"),
                newAccountKey = o.getString("newAccountKey"),
                done = (0 until arr.length()).map { arr.getString(it) }.toMutableSet(),
            )
        } catch (e: Exception) {
            throw IOException("cleanup journal unreadable", e)
        }
    }

    fun write(idempotencyKey: String, newAccountKey: String, done: Set<String>) {
        val o = JSONObject()
            .put("v", 1)
            .put("idempotencyKey", idempotencyKey)
            .put("newAccountKey", newAccountKey)
            .put("done", JSONArray(done.sorted()))
        files.write(NAME, o.toString().toByteArray(Charsets.UTF_8))
    }

    /** Removes the journal once the cleanup is complete. True only when it is confirmed gone. */
    fun clear(): Boolean = eraseChecked(files, NAME)

    companion object {
        const val NAME = "account_cleanup_old.v1.journal"
    }
}

/**
 * The native confirmation of the cleanup (25.52Y.91 第 3 項): the user confirms on the native confirmation screen, and that screen records it here.
 * The page never records it and the payload never carries it. Single-use: [consume] removes it when the cleanup completes. An unreadable record
 * is not a confirmation.
 */
internal class CleanupConfirmation(private val files: VaultFiles) {
    /** Called by the native confirmation screen after the user confirms. */
    fun record(accountKey: String, atMs: Long) {
        val o = JSONObject().put("v", 1).put("accountKey", accountKey.lowercase()).put("atMs", atMs)
        files.write(NAME, o.toString().toByteArray(Charsets.UTF_8))
    }

    fun confirmedFor(accountKey: String): Boolean {
        return try {
            val raw = files.read(NAME) ?: return false
            JSONObject(String(raw, Charsets.UTF_8)).optString("accountKey") == accountKey.lowercase()
        } catch (_: Exception) {
            false
        }
    }

    fun consume(): Boolean = eraseChecked(files, NAME)

    companion object {
        const val NAME = "account_cleanup_confirm.v1"
    }
}

/** One store of the old account's data (25.52Y.85 第 3 项 (c)). An adapter's [scan] reports the new account's items too, as kept. */
internal interface CleanupAdapter {
    fun scan(newAccountKey: String): AccountCleanupOld.Scan

    /** True only when the item is confirmed gone. An item with no owner is never removed. */
    fun remove(item: AccountCleanupOld.Item): Boolean
}

/**
 * A store the cleanup cannot enumerate yet. Its scan is incomplete, so the cleanup cannot finish: `clear_incomplete`, and nothing is guessed.
 */
internal class UnenumeratedStore(private val label: String) : CleanupAdapter {
    override fun scan(newAccountKey: String): AccountCleanupOld.Scan = AccountCleanupOld.Scan(emptyList(), complete = false)

    override fun remove(item: AccountCleanupOld.Item): Boolean = false

    override fun toString(): String = "UnenumeratedStore($label)"
}

/**
 * The chat history files of the app's storage directory (see [ChatHistoryFileNames]). A name of the new account's family is kept; another name of
 * the same family belongs to another account and is removed; a name of any other form has no known owner and is never removed.
 */
internal class HistoryDirCleanup(private val dir: File) : CleanupAdapter {
    override fun scan(newAccountKey: String): AccountCleanupOld.Scan {
        if (!dir.exists()) return AccountCleanupOld.Scan(emptyList(), complete = true)
        val names = dir.list() ?: return AccountCleanupOld.Scan(emptyList(), complete = false)
        val newEoa = newAccountKey.substringBefore(':').lowercase()
        val newLocal = ChatHistoryFileNames.localName(newEoa)
        val kept = setOf(newLocal, ChatHistoryFileNames.pendingName(newEoa)) + ChatHistoryFileNames.LOCAL_SUFFIXES.map { newLocal.removeSuffix(".sqlite") + it }
        val items = names.map { name ->
            AccountCleanupOld.Item(name = "$PREFIX$name", accountKey = ownerOf(name, newAccountKey, kept))
        }
        return AccountCleanupOld.Scan(items, complete = true)
    }

    override fun remove(item: AccountCleanupOld.Item): Boolean {
        if (item.accountKey == null) return false
        val f = File(dir, item.name.removePrefix(PREFIX))
        if (!f.exists()) return true
        if (f.delete()) return true
        return !f.exists()
    }

    private fun ownerOf(name: String, newAccountKey: String, kept: Set<String>): String? = when {
        name in kept -> newAccountKey
        name.startsWith(ChatHistoryFileNames.LOCAL_PREFIX) &&
            ChatHistoryFileNames.LOCAL_SUFFIXES.any { name.endsWith(it) } ->
            "chat-local-v1:" + ChatHistoryFileNames.localDigestOf(name)
        name.startsWith(ChatHistoryFileNames.PENDING_PREFIX) && name.endsWith(".bin") ->
            "history-pending:" + ChatHistoryFileNames.pendingTagOf(name)
        else -> null
    }

    private companion object {
        const val PREFIX = "history:"
    }
}

/**
 * Runs `accountCleanupOld` after the bridge gate (25.52Y.91). The order is the refusal check, the preflight, the journal, the scan of every
 * adapter, then the removals with the journal written after each one. The result is `ok` only when every store was scanned and every removal
 * took effect; the journal and the confirmation are removed only then.
 */
internal class AccountCleanupRun(
    private val journal: CleanupJournal,
    private val confirmation: CleanupConfirmation,
    private val adapters: List<CleanupAdapter>,
) {
    fun run(
        payloadFields: Collection<String>,
        accountKey: String?,
        idempotencyKey: String?,
        gateNotReady: Boolean,
        newAccountKey: String?,
        newAccountReadable: Boolean,
    ): AccountCleanupOld.Outcome {
        AccountCleanupOld.refuseInput(payloadFields, accountKey, idempotencyKey)?.let { return refused(it) }
        val key = accountKey?.lowercase() ?: return refused(AccountCleanupOld.BAD_REQUEST)
        val idem = idempotencyKey ?: return refused(AccountCleanupOld.BAD_REQUEST)
        val newKey = newAccountKey?.lowercase()
        AccountCleanupOld.preflight(
            gateNotReady = gateNotReady,
            newAccountReadable = newAccountReadable && newKey != null,
            // The confirmation is the native new account's (25.52Y.91 第 4 項 (c)), not the payload's: a payload for another account is account_mismatch.
            nativeConfirmed = newKey != null && confirmation.confirmedFor(newKey),
            accountKeyMatch = newKey != null && key == newKey,
        )?.let { return refused(it) }
        if (newKey == null) return refused(AccountCleanupOld.NOT_AVAILABLE)

        val prior = try {
            journal.read()
        } catch (_: IOException) {
            // An unreadable journal: nothing is removed until it can be read (25.52Y.91 第 7 項).
            return AccountCleanupOld.Outcome(AccountCleanupOld.CLEAR_INCOMPLETE, emptyList(), emptyList(), cleanupPending = true)
        }
        val done: MutableSet<String> = if (prior != null && prior.idempotencyKey == idem && prior.newAccountKey == newKey) {
            prior.done
        } else {
            mutableSetOf()
        }

        val owner = HashMap<String, CleanupAdapter>()
        val items = mutableListOf<AccountCleanupOld.Item>()
        var complete = true
        for (adapter in adapters) {
            val scan = try {
                adapter.scan(newKey)
            } catch (_: Exception) {
                AccountCleanupOld.Scan(emptyList(), complete = false)
            }
            for (item in scan.items) owner[item.name] = adapter
            items += scan.items
            if (!scan.complete) complete = false
        }

        try {
            journal.write(idem, newKey, done)
        } catch (_: IOException) {
            return AccountCleanupOld.Outcome(AccountCleanupOld.CLEAR_INCOMPLETE, emptyList(), emptyList(), cleanupPending = true)
        }

        val outcome = AccountCleanupOld.execute(
            newAccountKey = newKey,
            items = items,
            done = done,
            remove = { item ->
                val adapter = owner[item.name]
                val gone = adapter != null && try {
                    adapter.remove(item)
                } catch (_: Exception) {
                    false
                }
                if (gone) {
                    done += item.name
                    // A journal write that fails after a removal is harmless: a later run finds the item gone and removes nothing.
                    try {
                        journal.write(idem, newKey, done)
                    } catch (_: IOException) {
                        Unit
                    }
                }
                gone
            },
            complete = complete,
        )
        if (outcome.code != AccountCleanupOld.OK) return outcome
        if (!journal.clear() || !confirmation.consume()) {
            return AccountCleanupOld.Outcome(AccountCleanupOld.CLEAR_INCOMPLETE, outcome.deleted, outcome.kept, cleanupPending = true)
        }
        return outcome
    }

    private fun refused(code: String) = AccountCleanupOld.Outcome(code, emptyList(), emptyList(), cleanupPending = false)
}
