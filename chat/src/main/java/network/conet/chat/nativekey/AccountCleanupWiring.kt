package network.conet.chat.nativekey

import network.conet.chat.passcode.PasscodeRecordStore
import org.json.JSONObject
import java.io.File

/**
 * The production adapters of `accountCleanupOld`, one per store. The old-account set is every account address this device identifies precisely (decision
 * all accounts but the new one), enumerated from: the vault owner, the PGP names, the page names, the passcode record names, the K item names, and
 * the legacy records' owners. It is not the vault's current owner alone, and it is not a replaced-account record. Name- and content-derived owners are restricted
 * to this set; an owner outside it is unattributed (kept, counted). The new account is never in the set. Owner, inbox and signal files are not in the
 * deletion set and are not counted.
 */
/** The active pointer as read once (see [AccountCleanupWiring.takeSnapshot]). */
internal class PointerSnapshot(val eoa: String?)

internal object AccountCleanupWiring {
    private val EOA = Regex("^0x[0-9a-f]{40}$")

    /**
     * The old-account set for one run, or null when any enumeration source cannot be read (v220 240.4(5): an unreadable source is not_ready and nothing is deleted;
     * a smaller set would silently keep less, so it is never returned). Sources: the vault owner, PGP, page, passcode and K names, and the legacy owners.
     */
    fun oldAccounts(
        filesDir: File,
        noBackupDir: File,
        kPgp: AccountPgpKBackend,
        legacyPgpOwner: () -> String?,
        walletCopyOwner: () -> String?,
        newEoa: String,
        /** Verifies a mnemonic record by its phrase. Default is unverified, so a residue is never attributed by its envelope alone. */
        mnemPhrase: (ByteArray) -> NativeWalletVault.PhraseItem = { NativeWalletVault.PhraseItem.Unreadable },
    ): Set<String>? {
        val nativeDir = File(filesDir, "native_wallet_v1")
        val found = HashSet<String>()
        fun add(owner: OwnerRead) {
            if (owner is OwnerRead.Known) found += owner.accountKey.substringBefore(':').lowercase()
        }
        fun listOrNull(dir: File): List<String>? = if (!dir.exists()) emptyList() else dir.list()?.toList()
        // The vault owner: an unreadable vault owner makes the set unknown.
        // Every exact vault file is read: an account's file in the vault is an account on this device too (EA-01). An unreadable one makes the set unknown.
        for (name in CleanupOwners.WALLET_NAMES) {
            val read = if (name == NativeWalletVault.MNEM) CleanupOwners.mnemOwner(nativeDir, name, mnemPhrase) else CleanupOwners.walletFileOwner(nativeDir, name)
            when (val o = read) {
                is OwnerRead.Known -> add(o)
                OwnerRead.Unowned -> Unit
                OwnerRead.Unreadable -> return null
            }
        }
        val nativeNames = listOrNull(nativeDir) ?: return null
        nativeNames.forEach { add(CleanupOwners.pgpOwner(it)) }
        val pageNames = listOrNull(File(noBackupDir, "page_record_v1")) ?: return null
        pageNames.forEach { add(CleanupOwners.pageOwner(it)) }
        // The per-account recovery backup flags (IdentityClear.backupFlagName) name their account too (EA-14, real source).
        pageNames.forEach { add(backupFlagOwner(it)) }
        val passNames = listOrNull(File(noBackupDir, PasscodeRecordStore.DIRECTORY)) ?: return null
        passNames.forEach { name ->
            val eoa = name.removeSuffix(PasscodeRecordStore.NEW_SUFFIX).lowercase()
            if (EOA.matches(eoa)) found += eoa
        }
        val kNames = try { kPgp.names() } catch (_: Exception) { return null }
        kNames.forEach { name ->
            if (name.startsWith(AccountPgpK.PREFIX)) {
                val parts = name.removePrefix(AccountPgpK.PREFIX).split("|")
                if (parts.size == 2) add(CleanupOwners.eoaOwner(parts[0], parts[1].ifEmpty { "default" }))
            }
        }
        try { legacyPgpOwner()?.let { if (EOA.matches(it.lowercase())) found += it.lowercase() } } catch (_: Exception) { return null }
        try { walletCopyOwner()?.let { if (EOA.matches(it.lowercase())) found += it.lowercase() } } catch (_: Exception) { return null }
        val new = newEoa.lowercase()
        return found.filter { EOA.matches(it) && it != new }.toSet()
    }

    /**
     * One read of the native active pointer (SNAP-01). Every comparison of one read-back uses this one snapshot; the pointer is never read
     * again between the derivation and the comparison. A re-read takes a new snapshot.
     */
    fun takeSnapshot(readPointer: () -> String?): PointerSnapshot = PointerSnapshot(readPointer()?.lowercase())

    /**
     * The read-back of the payload accountKey against one snapshot (v4 EA-12). The native derived address is taken from the same
     * snapshot's record. An unknown snapshot is UNREADABLE (not_ready); a readable one different from accountKey is MISMATCH (account_mismatch).
     */
    fun readBackVerdict(accountKey: String?, snap: PointerSnapshot): ReadBackCheck.Verdict =
        ReadBackCheck.verdict(accountKey, snap.eoa, snap.eoa)

    /** The per-account recovery backup flag prefix (IdentityClear.BACKUP_PREFIX). */
    internal const val BACKUP_FLAG_PREFIX = "recovery_backup_confirmed."
    private val BACKUP_FLAG = Regex("^recovery_backup_confirmed\\.([0-9a-f]{40})\\.v1$")

    /** The owner of one backup flag, by the address in its name; a name that carries no account is unowned (kept and counted). */
    fun backupFlagOwner(name: String): OwnerRead {
        val m = BACKUP_FLAG.matchEntire(name) ?: return OwnerRead.Unowned
        return CleanupOwners.eoaOwner("0x" + m.groupValues[1])
    }

    /**
     * SNAP-06 (production), three-valued (第 2 条): UNSENT when the library reads and has pending_publish > 0;
     * NONE when it reads and has none, or the file is absent; UNKNOWN for any failure to read (cannot open, corrupt, locked, not a database, bad schema).
     * An UNKNOWN library is never removed and never counted; it makes the run clear_incomplete with cleanupPending (retryable).
     */
    fun historyUnsentRead(file: File, openDb: (File) -> network.conet.chat.localread.SqlDb = { network.conet.chat.localread.AndroidSqlDb.open(it) }): UnsentRead {
        if (!file.exists()) return UnsentRead.NONE
        if (!file.isFile) return UnsentRead.UNKNOWN
        return try {
            val db = openDb(file)
            try {
                val n = (db.query("SELECT COUNT(*) FROM msg WHERE pending_publish > 0").firstOrNull()?.get(0) as? Number)?.toLong()
                when {
                    n == null -> UnsentRead.UNKNOWN
                    n > 0L -> UnsentRead.UNSENT
                    else -> UnsentRead.NONE
                }
            } finally {
                db.close()
            }
        } catch (_: Exception) {
            UnsentRead.UNKNOWN
        }
    }

    /** The adapters of one run, for the old-account set [oldAccounts] (already minus the new account). */
    fun adapters(
        filesDir: File,
        noBackupDir: File,
        kPgp: AccountPgpKBackend,
        oldAccounts: Set<String>,
        vaultMonitor: Any,
        activeAccount: () -> String?,
        hasUnsent: (File) -> UnsentRead = { UnsentRead.NONE },
        mnemPhrase: (ByteArray) -> NativeWalletVault.PhraseItem = { NativeWalletVault.PhraseItem.Unreadable },
    ): List<CleanupAdapter> {
        val nativeDir = File(filesDir, "native_wallet_v1")
        // EA-04 (vector 2026-11-21): the active account is never a removal candidate. Its items are kept whole and counted as unattributed (ok, no pending).
        val active = activeAccount()?.lowercase()?.substringBefore(':')
        val candidates = oldAccounts - setOfNotNull(active)
        val old = candidates.toList()
        return listOf(
            HistoryDirCleanup(File(filesDir, "conet-chat"), hasUnsent) { old },
            WalletVaultCleanup(nativeDir, vaultMonitor, activeAccount) { dir, name ->
                val read = if (name == NativeWalletVault.MNEM) CleanupOwners.mnemOwner(dir, name, mnemPhrase) else CleanupOwners.walletFileOwner(dir, name)
                restrictOwner(read, candidates)
            },
            FileDirCleanup(nativeDir, "pgp", { it.startsWith("pgp.v1.") }, { _, name -> restrictOwner(CleanupOwners.pgpOwner(name), candidates) }),
            FileDirCleanup(File(noBackupDir, "page_record_v1"), "page", { it.startsWith("page.v1.") }, { _, name ->
                restrictOwner(CleanupOwners.pageOwner(name), candidates)
            }),
            // The recovery backup flags (one per account, in page_record_v1): exact-owner removal for an old account; an unattributable one is kept and counted.
            FileDirCleanup(File(noBackupDir, "page_record_v1"), "backup", { it.startsWith(BACKUP_FLAG_PREFIX) }, { _, name ->
                restrictOwner(backupFlagOwner(name), candidates)
            }),
            PasscodeDirCleanup(File(noBackupDir, PasscodeRecordStore.DIRECTORY)) { old },
            KPgpCleanup(kPgp, candidates),
            // The legacy PGP record and the isolated wallet copy have a fixed name (not derived from an address): they are not in the deletion set (v210 230).
        )
    }
}

/**
 * The `accountCleanupOld` ack for [reqId] (25.52Y.91 第 6 項): `ok` with `result.cleanupPending` false; `clear_incomplete` with
 * `result.cleanupPending` true; every other refusal as `error`. `result.retainedUnattributed` counts the items kept without an owner (Y.103).
 * Only codes, flags and counts are sent: no names, no keys.
 */
internal fun accountCleanupAck(reqId: Any?, outcome: AccountCleanupOld.Outcome): JSONObject {
    val ok = outcome.code == AccountCleanupOld.OK
    val payload = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", ok)
    if (!ok) payload.put("error", outcome.code)
    payload.put(
        "result",
        JSONObject().put("cleanupPending", outcome.cleanupPending).put("keptUnattributed", outcome.retainedUnattributed),
    )
    return payload
}
