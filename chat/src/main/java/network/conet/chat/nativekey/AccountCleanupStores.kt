package network.conet.chat.nativekey

import network.conet.chat.passcode.PasscodeRecordStore
import network.conet.chat.passcode.PasscodeWriteState

import org.json.JSONObject
import java.io.File
import java.io.IOException

/**
 * The owner of a stored item, as read (Y.100, Y.103 2026-11-16). [Known]: the item names its accountKey. [Unowned]: it was read, and no accountKey
 * could be parsed from it; the item is kept and does not block ok. [Unreadable]: a read failed, so the owner is unknown and retryable; the scan
 * is incomplete and the result is clear_incomplete with nothing removed on that account.
 */
internal sealed class OwnerRead {
    data class Known(val accountKey: String) : OwnerRead()

    object Unowned : OwnerRead()

    object Unreadable : OwnerRead()
}

/** The owners of the stored items for `accountCleanupOld` (25.52Y.91). An accountKey is `eoa:workspace` (Y.77); the workspace is `default` (D5). */
internal object CleanupOwners {
    private const val DEFAULT_WORKSPACE = "default"
    private val EOA = Regex("^0x[0-9a-f]{40}$")
    private val PGP_NAME = Regex("""^pgp\.v1\.(?:(?:pending|old|done)\.)?([0-9a-f]{40})(?:\.[A-Za-z0-9_-]+)?$""")
    private val PGP_MIGRATION_NAME = Regex("""^pgp\.v1\.mig\.([0-9a-f]{40})\.([A-Za-z0-9_-]+)\.(?:n|m|last)$""")
    private val PGP_MIGRATION_NO_WORKSPACE = Regex("""^pgp\.v1\.mig\.([0-9a-f]{40})\.(?:n|m|last)$""")
    private val PAGE_NAME = Regex("""^page\.v1\.([0-9a-f]{40})\.([A-Za-z0-9_-]+)\.rec$""")
    /** Every name of the one vault: the marker is part of it, so an unreadable marker makes the owner unknown too (Y.103 blocker). */
    internal val WALLET_NAMES = listOf(NativeWalletVault.REC, NativeWalletVault.MARK, NativeWalletVault.INTENT, NativeWalletVault.COMMIT, NativeWalletVault.MNEM)

    /**
     * The owner of the mnemonic record: it names its account only when its phrase
     * verifies (the phrase derives the envelope's account). An envelope eoa alone is not proof of ownership, so a readable residue that does not verify is
     * Unowned (kept, counted). A transient read failure is Unreadable (the scan is incomplete, retryable).
     */
    fun mnemOwner(dir: File, name: String, phraseItemOf: (ByteArray) -> NativeWalletVault.PhraseItem): OwnerRead {
        val f = File(dir, name)
        if (!f.exists()) return OwnerRead.Unowned
        if (!f.isFile) return OwnerRead.Unreadable
        val raw = try {
            f.readBytes()
        } catch (_: IOException) {
            return OwnerRead.Unreadable
        }
        return try {
            when (val item = phraseItemOf(raw)) {
                is NativeWalletVault.PhraseItem.Valid -> eoaOwner(item.eoa)
                NativeWalletVault.PhraseItem.Invalid, NativeWalletVault.PhraseItem.Unreadable -> OwnerRead.Unowned
            }
        } catch (_: IOException) {
            OwnerRead.Unreadable
        }
    }

    /**
     * The owner of one exact vault file, read from that file's own envelope (EA-01: the key file and the mnemonic file can belong to different accounts).
     * A non-regular or unreadable file is [OwnerRead.Unreadable]; an absent file is [OwnerRead.Unowned]; a file naming no EOA is [OwnerRead.Unowned].
     */
    fun walletFileOwner(dir: File, name: String): OwnerRead {
        val f = File(dir, name)
        val attributes = try {
            java.nio.file.Files.readAttributes(f.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java)
        } catch (_: java.nio.file.NoSuchFileException) {
            return OwnerRead.Unowned
        } catch (_: Exception) {
            return OwnerRead.Unreadable
        }
        if (!attributes.isRegularFile) return OwnerRead.Unreadable
        val raw = try {
            f.readBytes()
        } catch (_: IOException) {
            return OwnerRead.Unreadable
        }
        val eoa = try {
            JSONObject(String(raw, Charsets.UTF_8)).optString("eoa", "")
        } catch (_: Exception) {
            "" // read, but not a JSON envelope: a parse failure, not a read failure
        }
        return eoaOwner(eoa)
    }

    /** An EOA string as an owner: a well-formed lower-case address is [OwnerRead.Known]; anything else was read but names no account. */
    fun eoaOwner(eoa: String?, workspace: String = DEFAULT_WORKSPACE): OwnerRead {
        val e = eoa?.trim()?.lowercase() ?: return OwnerRead.Unowned
        return if (EOA.matches(e)) OwnerRead.Known("$e:$workspace") else OwnerRead.Unowned
    }

    /** The owner of a `pgp.v1.*` file of the native vault directory, by the name's EOA; a migration file carries its workspace. */
    fun pgpOwner(name: String): OwnerRead {
        PGP_MIGRATION_NAME.find(name)?.let { m ->
            return eoaOwner("0x" + m.groupValues[1], m.groupValues[2])
        }
        // A migration row of the account without a named workspace is the account's own row (Y.105 第 4 条): its workspace is the default one (D5).
        PGP_MIGRATION_NO_WORKSPACE.find(name)?.let { m ->
            return eoaOwner("0x" + m.groupValues[1])
        }
        val m = PGP_NAME.find(name) ?: return OwnerRead.Unowned
        return eoaOwner("0x" + m.groupValues[1])
    }

    /** The owner of a `page.v1.<address>.<name>.rec` page copy (§25.52AD.2), by the address and the name it carries. */
    fun pageOwner(name: String): OwnerRead {
        val m = PAGE_NAME.matchEntire(name) ?: return OwnerRead.Unowned
        return eoaOwner("0x" + m.groupValues[1], m.groupValues[2])
    }

    /**
     * The owner of the native wallet vault (`wallet.v1.*`), one account per vault. A vault name present but not a regular file, or a file that
     * cannot be read, is [OwnerRead.Unreadable] at once: the owner is unknown, nothing is decided from the other files. The EOA is read from the
     * envelope's clear `eoa` field (no key is opened); a file that reads but names no EOA gives [OwnerRead.Unowned].
     */
    fun walletVaultOwner(dir: File): OwnerRead {
        // Absent is only NoSuchFileException from the stat; any other failure to stat (permission, I/O) is unreadable, never absent (Y.104 第 3 条).
        val present = mutableListOf<File>()
        for (name in WALLET_NAMES) {
            val f = File(dir, name)
            val attributes = try {
                java.nio.file.Files.readAttributes(f.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java)
            } catch (_: java.nio.file.NoSuchFileException) {
                continue
            } catch (_: Exception) {
                return OwnerRead.Unreadable
            }
            if (!attributes.isRegularFile) return OwnerRead.Unreadable
            present += f
        }
        val raws = mutableListOf<ByteArray>()
        for (f in present) {
            try {
                raws += f.readBytes()
            } catch (_: IOException) {
                return OwnerRead.Unreadable
            }
        }
        for (raw in raws) {
            val eoa = try {
                JSONObject(String(raw, Charsets.UTF_8)).optString("eoa", "")
            } catch (_: Exception) {
                "" // read, but not a JSON envelope: a parse failure, not a read failure
            }
            val owner = eoaOwner(eoa)
            if (owner is OwnerRead.Known) return owner
        }
        return OwnerRead.Unowned
    }
}

/**
 * A directory of single-file records (the native vault directory, the page copies). [accepts] selects the names this adapter owns; [ownerOf]
 * reads the owner of an accepted name. A directory that cannot be listed, and an item whose owner is unreadable, make the scan incomplete (the
 * result is clear_incomplete). An item that was read with no owner is kept and does not block ok. A name that is not accepted is never touched.
 */
internal class FileDirCleanup(
    private val dir: File,
    private val label: String,
    private val accepts: (String) -> Boolean,
    private val ownerOf: (File, String) -> OwnerRead,
) : CleanupAdapter {
    private val prefix = "$PREFIX$label:"

    override fun scan(newAccountKey: String): AccountCleanupOld.Scan {
        if (!dir.exists()) return AccountCleanupOld.Scan(emptyList(), complete = true)
        val names = dir.list() ?: return AccountCleanupOld.Scan(emptyList(), complete = false)
        val items = mutableListOf<AccountCleanupOld.Item>()
        var complete = true
        for (name in names.filter { accepts(it) }) {
            when (val owner = ownerOf(dir, name)) {
                is OwnerRead.Known -> items += AccountCleanupOld.Item(prefix + name, owner.accountKey)
                OwnerRead.Unowned -> items += AccountCleanupOld.Item(prefix + name, null)
                OwnerRead.Unreadable -> complete = false
            }
        }
        return AccountCleanupOld.Scan(items, complete)
    }

    override fun remove(item: AccountCleanupOld.Item): Boolean {
        if (item.accountKey == null || !item.name.startsWith(prefix)) return false
        val f = File(dir, item.name.removePrefix(prefix))
        if (!f.exists()) return true
        if (f.delete()) return true
        return !f.exists()
    }

    private companion object {
        const val PREFIX = "file:"
    }
}

/**
 * The K items of the account PGP store (`K.v1|<eoa>|<workspace>`, 25.52Y.91 第 c 項). Only the names are read; the key material is never read.
 * A store that cannot list its names is an incomplete scan.
 */
internal class KPgpCleanup(
    private val backend: AccountPgpKBackend,
    /** The old-account set: an owner outside it is kept as unattributed. Null means no restriction (tests only; production always passes a set). */
    private val oldAccounts: Set<String>? = null,
) : CleanupAdapter {
    override fun scan(newAccountKey: String): AccountCleanupOld.Scan {
        val names = try {
            backend.names()
        } catch (_: Exception) {
            return AccountCleanupOld.Scan(emptyList(), complete = false)
        }
        val items = names.filter { it.startsWith(AccountPgpK.PREFIX) }.map { name ->
            val parts = name.removePrefix(AccountPgpK.PREFIX).split("|")
            val owner = restrictOwner(if (parts.size == 2) CleanupOwners.eoaOwner(parts[0], parts[1].ifEmpty { "default" }) else OwnerRead.Unowned, oldAccounts)
            AccountCleanupOld.Item(name = "kpgp:$name", accountKey = (owner as? OwnerRead.Known)?.accountKey)
        }
        return AccountCleanupOld.Scan(items, complete = true)
    }

    override fun remove(item: AccountCleanupOld.Item): Boolean {
        if (item.accountKey == null || !item.name.startsWith("kpgp:")) return false
        val name = item.name.removePrefix("kpgp:")
        return try {
            backend.remove(name) && !backend.names().contains(name)
        } catch (_: Exception) {
            false
        }
    }
}

/**
 * The local inbox entries (`BeamioConetChatInboxStore`, Y.103 第 1 条). They carry no recipient, so no owner can be read: each entry is kept and
 * counted as retained unattributed. A store that cannot be read is an incomplete scan.
 */
internal class UnattributedInboxCleanup(private val count: () -> Int) : CleanupAdapter {
    override fun scan(newAccountKey: String): AccountCleanupOld.Scan = try {
        AccountCleanupOld.Scan((0 until count()).map { AccountCleanupOld.Item("inbox:$it", null) }, complete = true)
    } catch (_: Exception) {
        AccountCleanupOld.Scan(emptyList(), complete = false)
    }

    /** An inbox entry has no owner, so it is never removed. */
    override fun remove(item: AccountCleanupOld.Item): Boolean = false
}

/**
 * The native passcode records (`native_passcode_v1`, one file per account, named by the lower-case EOA; a write may leave `<eoa>.new`). The record is
 * bound to its account (the AAD names the EOA), so the owner is exact: a name equal to a known old account's EOA (or its `.new`) belongs to that account.
 * Any other name, and the new account's own names, are kept (unattributed or the new account). Single-item removal only; the directory is never cleared.
 * the record of a provably old account is removed after a successful recovery and a passing read-back, inside the silent cleanup.
 */
internal class PasscodeDirCleanup(
    private val dir: File,
    private val knownOldEoas: () -> Collection<String>,
) : CleanupAdapter {
    override fun scan(newAccountKey: String): AccountCleanupOld.Scan {
        if (!dir.exists()) return AccountCleanupOld.Scan(emptyList(), complete = true)
        val names = dir.list() ?: return AccountCleanupOld.Scan(emptyList(), complete = false)
        val newEoa = newAccountKey.substringBefore(':').lowercase()
        val oldOwner = HashMap<String, String>()
        for (raw in knownOldEoas()) {
            val e = raw.lowercase()
            if (e == newEoa || !EOA_RE.matches(e)) continue
            oldOwner[e] = "$e:default"
            oldOwner[e + PasscodeRecordStore.NEW_SUFFIX] = "$e:default"
        }
        val items = names.map { name ->
            val owner = when {
                name == newEoa || name == newEoa + PasscodeRecordStore.NEW_SUFFIX -> newAccountKey
                // A <eoa>.new of a known old account is attributed to it (v209 229.2). Whether it may be removed (older than this process, no write in progress)
                // is judged again at removal; a deferred one fails there, and the run answers clear_incomplete, never counted as unattributed.
                name.endsWith(PasscodeRecordStore.NEW_SUFFIX) -> oldOwner[name.removeSuffix(PasscodeRecordStore.NEW_SUFFIX)]
                else -> oldOwner[name]
            }
            AccountCleanupOld.Item(name = "$PREFIX$name", accountKey = owner)
        }
        return AccountCleanupOld.Scan(items, complete = true)
    }

    override fun remove(item: AccountCleanupOld.Item): Boolean {
        if (item.accountKey == null || !item.name.startsWith(PREFIX)) return false
        val name = item.name.removePrefix(PREFIX)
        val f = File(dir, name)
        if (!f.exists()) return true
        if (name.endsWith(PasscodeRecordStore.NEW_SUFFIX)) {
            // Re-judged at removal (v207 227): the stale-and-idle check and the delete run under the write-state lock. A write that started after the scan keeps the file,
            // and the item then fails (clear_incomplete, never reported as success).
            val account = name.removeSuffix(PasscodeRecordStore.NEW_SUFFIX)
            return PasscodeWriteState.whenStaleAndIdle(account, f) { f.delete() || !f.exists() } ?: false
        }
        if (f.delete()) return true
        return !f.exists()
    }

    private companion object {
        const val PREFIX = "passcode:"
        val EOA_RE = Regex("^0x[0-9a-f]{40}$")
    }
}

/**
 * The native wallet vault (`wallet.v1.*`). Only the five exact basenames are in the deletion set (rec, ok, mnem, intent, commit; on
 * wallet.v1.*). Any other `wallet.v1.*` name, such as an isolated copy `wallet.v1.*.isolated.<x>`, is retained as unattributed (counted in keptUnattributed):
 * its owner is not the vault's current owner, so it is never removed by the vault's owner. A removal takes the vault's own monitor, refuses while the old
 * account is the active one, and re-reads the owner under the monitor; a changed or unreadable owner keeps the file and the item fails (clear_incomplete).
 */
internal class WalletVaultCleanup(
    private val dir: File,
    private val vaultMonitor: Any,
    private val activeAccount: () -> String?,
    private val ownerOf: (File, String) -> OwnerRead,
) : CleanupAdapter {
    private val inner = FileDirCleanup(dir, "wallet", { it in DELETABLE }, ownerOf)

    override fun scan(newAccountKey: String): AccountCleanupOld.Scan {
        if (!dir.exists()) return AccountCleanupOld.Scan(emptyList(), complete = true)
        val names = dir.list() ?: return AccountCleanupOld.Scan(emptyList(), complete = false)
        val items = mutableListOf<AccountCleanupOld.Item>()
        var complete = true
        for (name in names.filter { it.startsWith(WALLET_PREFIX) }) {
            if (name !in DELETABLE) {
                // Not one of the five exact names (an isolated copy, for example): retained and unattributed, never in the deletion set.
                items += AccountCleanupOld.Item(name = "$ITEM_PREFIX$name", accountKey = null)
                continue
            }
            when (val owner = ownerOf(dir, name)) {
                is OwnerRead.Known -> {
                    // S-13: the active account equal to the candidate keeps the whole group (counted as kept, not failed); an unknown active
                    // account keeps it too (fail closed).
                    val active = activeAccount()?.lowercase()
                    val keep = active == null || active == owner.accountKey.substringBefore(':').lowercase()
                    items += AccountCleanupOld.Item(name = "$ITEM_PREFIX$name", accountKey = if (keep) null else owner.accountKey)
                }
                OwnerRead.Unowned -> items += AccountCleanupOld.Item(name = "$ITEM_PREFIX$name", accountKey = null)
                OwnerRead.Unreadable -> complete = false
            }
        }
        return AccountCleanupOld.Scan(items, complete)
    }

    override fun remove(item: AccountCleanupOld.Item): Boolean {
        val expected = item.accountKey ?: return false
        if (!item.name.startsWith(ITEM_PREFIX)) return false
        val name = item.name.removePrefix(ITEM_PREFIX)
        if (name !in DELETABLE) return false
        synchronized(vaultMonitor) {
            // Precondition: the environment's active account is read here; when it is the old account, the wallet group is kept. Unknown fails closed.
            val active = activeAccount()?.lowercase() ?: return false
            if (active == expected.substringBefore(':').lowercase()) return false
            val now = ownerOf(dir, name)
            if (now !is OwnerRead.Known || now.accountKey != expected) return false
            return inner.remove(AccountCleanupOld.Item(name = "file:wallet:$name", accountKey = expected))
        }
    }

    private companion object {
        const val WALLET_PREFIX = "wallet.v1."
        const val ITEM_PREFIX = "file:wallet:"
        val DELETABLE: Set<String> = setOf(
            NativeWalletVault.REC,
            NativeWalletVault.MARK,
            NativeWalletVault.MNEM,
            NativeWalletVault.INTENT,
            NativeWalletVault.COMMIT,
        )
    }
}

/** Restricts a name- or content-derived owner to the old-account set: an owner outside it is unattributed (kept, counted). Null set = unrestricted. */
internal fun restrictOwner(owner: OwnerRead, oldAccounts: Set<String>?): OwnerRead {
    if (oldAccounts == null || owner !is OwnerRead.Known) return owner
    return if (owner.accountKey.substringBefore(':').lowercase() in oldAccounts) owner else OwnerRead.Unowned
}
