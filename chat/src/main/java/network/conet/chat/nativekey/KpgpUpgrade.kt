package network.conet.chat.nativekey

import android.content.Context

/**
 * The runtime upgrade of K_pgp for an account that has W but no K_pgp (§25.52Y.59 第 3 项, P-IMP-PGP scheme A). The source order is the native PGP
 * record L first (valid: K_pgp is written from it, and L is never deleted). The chain backup is verified by [ChainBackupRestore] before it is written; a backup that
 * does not verify is pgp_migration_retry, never a silent new key. A new key is generated only on the user's explicit click; this function does not generate it.
 */
internal object KpgpUpgrade {
    /** The native PGP record of the account: its private armor and its subkey keyId, as the vault reports them. */
    internal class LRecord(val privateArmor: String, val subkeyKeyId: String)

    /** The decision for [eoa], writing K_pgp from a valid L record. [record] null means no native record. */
    fun upgrade(
        k: AccountPgpK,
        eoa: String,
        record: LRecord?,
        userClick: Boolean,
        nowSec: Long,
        nativeConfirm: Boolean = false,
        chain: ChainBackupRestore.Result = ChainBackupRestore.Result.NoSource,
    ): KpgpPolicy.Expect {
        val existing = try {
            k.read(eoa, PgpMigrationPolicy.WORKSPACE) != null
        } catch (_: Exception) {
            // An unreadable K is not an absent one: the upgrade does not run (fail closed).
            return KpgpPolicy.Expect("pgp_migration_retry", emptyList(), emptyList(), "pgp_migration_retry", rollback = true)
        }
        if (existing) return KpgpPolicy.decide(KpgpPolicy.Input(kind = "upgrade", kPgpExists = true))
        val publicArmor = record?.let { NativePgpKeyGen.publicArmorOf(it.privateArmor) }
        val keyIdOfRecord = record?.let { r -> NativePgp.parseSecret(r.privateArmor)?.let { NativePgpBackup.subkeyKeyId(it) } }
        val lValid = record != null && publicArmor != null && keyIdOfRecord != null && keyIdOfRecord == record.subkeyKeyId
        // keyID consistency log (rc2.2-qa item 4): match, mismatch or unknown per check, and the on-chain public keyID. The local key and the
        // local keyID are never logged.
        val lCheck = when {
            record == null || keyIdOfRecord == null -> "unknown"
            keyIdOfRecord == record.subkeyKeyId -> "match"
            else -> "mismatch"
        }
        val chainKeyId = (chain as? ChainBackupRestore.Result.Verified)?.keyId
        val chainCheck = when {
            keyIdOfRecord == null || chainKeyId == null -> "unknown"
            keyIdOfRecord == chainKeyId -> "match"
            else -> "mismatch"
        }
        DiagTiming.log("kpgp.keyid", DiagTiming.now(), "L=$lCheck chain=$chainCheck chainKeyId=${chainKeyId ?: "none"}")
        var writeOk = false
        if (lValid && record != null && publicArmor != null && keyIdOfRecord != null) {
            val tW = DiagTiming.now()
            writeOk = k.writeIfAbsent(eoa, PgpMigrationPolicy.WORKSPACE, keyIdOfRecord, publicArmor, record.privateArmor, nowSec) ==
                AccountPgpKWrite.WRITTEN
            // origin log (25.52Y.84 request, project ruling): the label, the time and the code only. No key, no keyID.
            DiagTiming.log("kpgp.write:upgradeL", tW, if (writeOk) "ok" else "fail")
        }
        // The chain source is used only when L gives no valid key (§25.52Y.59 第 3 项 (b)). A verified backup is written; nothing is deleted.
        val chainVerified = chain as? ChainBackupRestore.Result.Verified
        if (!lValid && chainVerified != null) {
            val tC = DiagTiming.now()
            writeOk = k.writeIfAbsent(eoa, PgpMigrationPolicy.WORKSPACE, chainVerified.keyId, chainVerified.publicArmor, chainVerified.privateArmor, nowSec) ==
                AccountPgpKWrite.WRITTEN
            DiagTiming.log("kpgp.write:chainBackup", tC, if (writeOk) "ok" else "fail")
        }
        return KpgpPolicy.decide(
            KpgpPolicy.Input(
                kind = "upgrade",
                kPgpExists = false,
                writeOk = writeOk,
                readbackOk = writeOk,
                lPresent = record != null,
                lValid = lValid,
                chainBackupPresent = chain !is ChainBackupRestore.Result.NoSource,
                chainVerify = chainVerified != null,
                userClick = userClick,
                nativeConfirm = nativeConfirm,
            ),
        )
    }

    /** The device wrapper: reads the account's native PGP record from the vault and runs [upgrade] against the device K store. */
    fun fromDevice(app: Context, eoa: String, userClick: Boolean, nowSec: Long, nativeConfirm: Boolean = false): KpgpPolicy.Expect {
        val vault = NativeWallet.pgpFor(app, eoa)
        val record = try {
            val identity = vault.identity()
            val priv = vault.armorForMove()
            if (identity != null && priv != null) LRecord(priv, identity.subkeyKeyId) else null
        } catch (_: Exception) {
            null
        }
        val store = AccountPgpK.forDevice(app)
        // The chain is read only when K_pgp is absent (a read failure of K is handled inside upgrade, which then does not run).
        val kAbsent = try {
            store.read(eoa, PgpMigrationPolicy.WORKSPACE) == null
        } catch (_: Exception) {
            false
        }
        val chain = if (!kAbsent) ChainBackupRestore.Result.NoSource else chainFromDevice(app, eoa)
        return upgrade(store, eoa, record, userClick, nowSec, nativeConfirm, chain)
    }

    /** The chain source for [eoa]: the public record and backup, verified with the account's wallet key. Read-only. */
    private fun chainFromDevice(app: Context, eoa: String): ChainBackupRestore.Result {
        val chain = AddressPgpChain.read(eoa) { ep -> AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs) }
        val vault = NativeWallet.vault(app)
        val password: () -> String? = {
            val key = vault.unlock()
            try {
                key?.let { "0x" + it.joinToString("") { b -> "%02x".format(b) } }
            } finally {
                key?.fill(0)
            }
        }
        return ChainBackupRestore.restore(eoa, chain, password, NativeMigrationCrypto())
    }
}
