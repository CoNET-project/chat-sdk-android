package network.conet.chat.nativekey

import org.json.JSONObject
import java.io.File
import java.io.IOException

/**
 * The owners of the stored items for `accountCleanupOld` (25.52Y.91, Y.100 2026-11-16). An accountKey is `eoa:workspace` (Y.77); the workspace
 * of every store here is `default` (D5) unless the name carries another. An item whose owner cannot be read is kept by the run (no owner).
 */
internal object CleanupOwners {
    private const val DEFAULT_WORKSPACE = "default"
    /** `pgp.v1.[pending.|old.|done.]<eoa>[.<tag>]` and the migration files `pgp.v1.mig.<eoa>.<workspace>.<n|m|last>`. */
    private val PGP_NAME = Regex("""^pgp\.v1\.(?:(?:pending|old|done)\.)?([0-9a-f]{40})(?:\.[A-Za-z0-9_-]+)?$""")
    private val PGP_MIGRATION_NAME = Regex("""^pgp\.v1\.mig\.([0-9a-f]{40})\.([A-Za-z0-9_-]+)\.(?:n|m|last)$""")
    private val PAGE_NAME = Regex("""^page\.v1\.([0-9a-f]{40})\.([A-Za-z0-9_-]+)\.rec$""")

    /** The owner of a `pgp.v1.*` file of the native vault directory (per account, by the name's EOA; the migration files carry the workspace). */
    fun pgpOwner(name: String): String? {
        PGP_MIGRATION_NAME.find(name)?.let { m ->
            return "0x" + m.groupValues[1] + ":" + m.groupValues[2]
        }
        val m = PGP_NAME.find(name) ?: return null
        return "0x" + m.groupValues[1] + ":" + DEFAULT_WORKSPACE
    }

    /** The owner of a `page.v1.<address>.<name>.rec` page copy (§25.52AD.2): the address and the name it carries. */
    fun pageOwner(name: String): String? {
        val m = PAGE_NAME.matchEntire(name) ?: return null
        return "0x" + m.groupValues[1] + ":" + m.groupValues[2]
    }

    /**
     * The owner of the native wallet vault (`wallet.v1.*`): one vault holds one account. Its EOA is read from the envelope's clear `eoa` field
     * (no key is opened). Null when no envelope can be read: the files are then kept.
     */
    fun walletVaultOwner(dir: File): String? {
        for (name in listOf(NativeWalletVault.REC, NativeWalletVault.INTENT, NativeWalletVault.COMMIT, NativeWalletVault.MNEM)) {
            val raw = try {
                File(dir, name).takeIf { it.isFile }?.readBytes()
            } catch (_: IOException) {
                null
            } ?: continue
            val eoa = try {
                JSONObject(String(raw, Charsets.UTF_8)).optString("eoa", "")
            } catch (_: Exception) {
                ""
            }
            if (eoa.matches(Regex("^0x[0-9a-f]{40}$"))) return "$eoa:$DEFAULT_WORKSPACE"
        }
        return null
    }
}

/**
 * A directory of single-file records (the native vault directory, the page copies). [accepts] selects the names this adapter owns; [ownerOf]
 * gives the owner of an accepted name, given the directory (for an owner read from another file). A name that is not accepted belongs to no
 * adapter here and is never touched. An unreadable directory is an incomplete scan.
 */
internal class FileDirCleanup(
    private val dir: File,
    private val label: String,
    private val accepts: (String) -> Boolean,
    private val ownerOf: (File, String) -> String?,
) : CleanupAdapter {
    private val prefix = "$PREFIX$label:"

    override fun scan(newAccountKey: String): AccountCleanupOld.Scan {
        if (!dir.exists()) return AccountCleanupOld.Scan(emptyList(), complete = true)
        val names = dir.list() ?: return AccountCleanupOld.Scan(emptyList(), complete = false)
        val items = names.filter { accepts(it) }.map { name ->
            AccountCleanupOld.Item(name = prefix + name, accountKey = ownerOf(dir, name))
        }
        return AccountCleanupOld.Scan(items, complete = true)
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
 * The K items of the account PGP store (`K.v1|<eoa>|<workspace>`, 25.52Y.91 第 c 项). Only the names are listed; the key material is never read.
 * The store throws when unreadable: an incomplete scan.
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
            val owner = if (parts.size == 2 && parts[0].isNotEmpty() && parts[1].isNotEmpty()) "${parts[0]}:${parts[1]}" else null
            AccountCleanupOld.Item(name = "kpgp:$name", accountKey = owner?.lowercase())
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
 * A legacy single record (the legacy PGP record L, the legacy wallet copy): one item for the EOA it names, owned by `eoa:default`. [eoaOf]
 * reads the EOA (throws when unreadable: an incomplete scan); [clearRecord] removes the record and returns true only when it is gone.
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
        return AccountCleanupOld.Scan(listOf(AccountCleanupOld.Item("record:$label", "${eoa.lowercase()}:default")), complete = true)
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
