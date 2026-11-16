package network.conet.chat.nativekey

import org.json.JSONObject
import java.io.File

/**
 * The production adapters of `accountCleanupOld` (25.52Y.91, Y.100, Y.103 2026-11-16), one per store: the history directory, the native vault
 * (`wallet.v1.*`, by the vault's EOA), the native PGP files (`pgp.v1.*`, by the name's EOA), the page copies (`page.v1.*`, by the name), the K items
 * (`K.v1|eoa|workspace`), the legacy PGP record L and the legacy wallet copy (each by the EOA it names), and the inbox entries (no owner, retained).
 * Device flags are not account-keyed and are not touched.
 */
internal object AccountCleanupWiring {
    fun adapters(
        filesDir: File,
        noBackupDir: File,
        kPgp: AccountPgpKBackend,
        legacyPgpOwner: () -> String?,
        clearLegacyPgp: () -> Boolean,
        walletCopyOwner: () -> String?,
        clearWalletCopy: () -> Boolean,
        inboxCount: () -> Int,
    ): List<CleanupAdapter> {
        val nativeDir = File(filesDir, "native_wallet_v1")
        return listOf(
            HistoryDirCleanup(File(filesDir, "conet-chat")),
            FileDirCleanup(nativeDir, "wallet", { it.startsWith("wallet.v1.") }, { dir, _ -> CleanupOwners.walletVaultOwner(dir) }),
            FileDirCleanup(nativeDir, "pgp", { it.startsWith("pgp.v1.") }, { _, name -> CleanupOwners.pgpOwner(name) }),
            FileDirCleanup(File(noBackupDir, "page_record_v1"), "page", { it.startsWith("page.v1.") }, { _, name -> CleanupOwners.pageOwner(name) }),
            KPgpCleanup(kPgp),
            SingleRecordCleanup("legacy_pgp", legacyPgpOwner, clearLegacyPgp),
            SingleRecordCleanup("wallet_copy", walletCopyOwner, clearWalletCopy),
            UnattributedInboxCleanup(inboxCount),
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
        JSONObject().put("cleanupPending", outcome.cleanupPending).put("retainedUnattributed", outcome.retainedUnattributed),
    )
    return payload
}
