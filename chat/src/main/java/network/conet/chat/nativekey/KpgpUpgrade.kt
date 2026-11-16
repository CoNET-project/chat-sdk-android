package network.conet.chat.nativekey

import android.content.Context

/**
 * The runtime upgrade of K_pgp for an account that has W but no K_pgp (§25.52Y.59 第 3 项, P-IMP-PGP scheme A). The source order is the native PGP
 * record L first (valid: K_pgp is written from it, and L is never deleted). The chain backup restore is not connected yet: without a verified source the
 * result is pgp_migration_retry, never a silent new key. A new key is generated only on the user's explicit click; this function does not generate it.
 */
internal object KpgpUpgrade {
    /** The native PGP record of the account: its private armor and its subkey keyId, as the vault reports them. */
    internal class LRecord(val privateArmor: String, val subkeyKeyId: String)

    /** The decision for [eoa], writing K_pgp from a valid L record. [record] null means no native record. */
    fun upgrade(k: AccountPgpK, eoa: String, record: LRecord?, userClick: Boolean, nowSec: Long): KpgpPolicy.Expect {
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
        var writeOk = false
        if (lValid && record != null && publicArmor != null && keyIdOfRecord != null) {
            writeOk = k.writeIfAbsent(eoa, PgpMigrationPolicy.WORKSPACE, keyIdOfRecord, publicArmor, record.privateArmor, nowSec) ==
                AccountPgpKWrite.WRITTEN
        }
        return KpgpPolicy.decide(
            KpgpPolicy.Input(
                kind = "upgrade",
                kPgpExists = false,
                writeOk = writeOk,
                readbackOk = writeOk,
                lPresent = record != null,
                lValid = lValid,
                chainBackupPresent = false,
                userClick = userClick,
            ),
        )
    }

    /** The device wrapper: reads the account's native PGP record from the vault and runs [upgrade] against the device K store. */
    fun fromDevice(app: Context, eoa: String, userClick: Boolean, nowSec: Long): KpgpPolicy.Expect {
        val vault = NativeWallet.pgpFor(app, eoa)
        val record = try {
            val identity = vault.identity()
            val priv = vault.armorForMove()
            if (identity != null && priv != null) LRecord(priv, identity.subkeyKeyId) else null
        } catch (_: Exception) {
            null
        }
        return upgrade(AccountPgpK.forDevice(app), eoa, record, userClick, nowSec)
    }
}
