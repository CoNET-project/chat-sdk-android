package network.conet.chat.nativekey

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
    private val PAGE_NAME = Regex("""^page\.v1\.([0-9a-f]{40})\.([A-Za-z0-9_-]+)\.rec$""")
    /** Every name of the one vault: the marker is part of it, so an unreadable marker makes the owner unknown too (Y.103 blocker). */
    private val WALLET_NAMES = listOf(NativeWalletVault.REC, NativeWalletVault.MARK, NativeWalletVault.INTENT, NativeWalletVault.COMMIT, NativeWalletVault.MNEM)

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
internal class KPgpCleanup(private val backend: AccountPgpKBackend) : CleanupAdapter {
    override fun scan(newAccountKey: String): AccountCleanupOld.Scan {
        val names = try {
            backend.names()
        } catch (_: Exception) {
            return AccountCleanupOld.Scan(emptyList(), complete = false)
        }
        val items = names.filter { it.startsWith(AccountPgpK.PREFIX) }.map { name ->
            val parts = name.removePrefix(AccountPgpK.PREFIX).split("|")
            val owner = if (parts.size == 2) CleanupOwners.eoaOwner(parts[0], parts[1].ifEmpty { "default" }) else OwnerRead.Unowned
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
 * A legacy single record (the legacy PGP record L, the legacy wallet copy): one item, owned by the EOA it names. [eoaOf] reads the EOA:
 * it throws when the store cannot be read (an incomplete scan); null or empty means there is no record; a value that names no account is
 * kept, unowned. [clearRecord] removes the record and returns true only when it is gone.
 */
internal class SingleRecordCleanup(
    private val label: String,
    private val eoaOf: () -> String?,
    private val clearRecord: () -> Boolean,
) : CleanupAdapter {
    override fun scan(newAccountKey: String): AccountCleanupOld.Scan {
        val eoa = try {
            eoaOf()
        } catch (_: Exception) {
            return AccountCleanupOld.Scan(emptyList(), complete = false)
        }
        if (eoa.isNullOrEmpty()) return AccountCleanupOld.Scan(emptyList(), complete = true)
        val owner = CleanupOwners.eoaOwner(eoa)
        return AccountCleanupOld.Scan(
            listOf(AccountCleanupOld.Item("record:$label", (owner as? OwnerRead.Known)?.accountKey)),
            complete = true,
        )
    }

    override fun remove(item: AccountCleanupOld.Item): Boolean {
        if (item.accountKey == null || item.name != "record:$label") return false
        return try {
            clearRecord()
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
