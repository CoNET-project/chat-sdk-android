package network.conet.chat.nativekey

import java.security.SecureRandom

/**
 * The chain-backup source of the K_pgp upgrade (§25.52Y.59 第 3 项 (b), P-IMP-PGP scheme A). Read-only: it reads the public record and the
 * backup of the account, decrypts the backup with the account's wallet key, and checks the result against the chain before anything is written.
 *
 * Checks, in order: the chain is readable; a record with a backup exists; the wallet key is available; the backup decrypts (AES-256-GCM, the
 * PWA's legacy form); the armor is a private key; its master fingerprint and first subkey keyId equal the chain record (the original identity);
 * the challenge signature verifies, and a one-bit change to the challenge does not. The challenge step needs the OpenPGP approval
 * ([MigrationCrypto.approved]); without it the result is [Result.Unverified], so nothing is written (verify_unavailable, §25.52.10).
 *
 * Every failure is [Result.Unverified] or [Result.NoSource], never a key. A chain or backup read that fails is not "no backup": it is Unverified.
 */
internal object ChainBackupRestore {
    sealed class Result {
        /** The chain holds no record, or no backup. Nothing to restore from. */
        object NoSource : Result()

        /** A backup exists but cannot be verified (chain unreadable, locked, decrypt or identity mismatch, challenge not passed). */
        object Unverified : Result()

        /** The backup is verified. [privateArmor] is returned to the caller for the K_pgp write only. */
        class Verified(val privateArmor: String, val publicArmor: String, val keyId: String) : Result()
    }

    fun restore(
        eoa: String,
        chain: PgpRestoreChain,
        passwordString: () -> String?,
        crypto: MigrationCrypto,
        random: SecureRandom = SecureRandom(),
    ): Result {
        if (!chain.chainReadable()) return Result.Unverified
        val identity = chain.identity()
        val backup = chain.backupText()
        if (backup.isEmpty()) return Result.NoSource
        if (identity == null) return Result.Unverified
        val pw = passwordString() ?: return Result.Unverified
        val armorBytes = NativePgpBackup.decryptArmor(pw, backup) ?: return Result.Unverified
        val armor = String(armorBytes, Charsets.UTF_8)
        val fp = crypto.secretFingerprint(armor) ?: return Result.Unverified
        if (fp.uppercase() != identity.fingerprint.uppercase()) return Result.Unverified
        val keyId = crypto.keyId(armor) ?: return Result.Unverified
        if (keyId.uppercase() != identity.subkeyKeyId.uppercase()) return Result.Unverified
        val publicArmor = NativePgpKeyGen.publicArmorOf(armor) ?: return Result.Unverified
        if (!challengeVerifies(eoa.lowercase(), armor, keyId, crypto, random)) return Result.Unverified
        return Result.Verified(armor, publicArmor, keyId.uppercase())
    }

    /** The challenge (§25.52.8): a random nonce, signed with the restored key, verified with it, and a one-bit change must fail. */
    private fun challengeVerifies(eoa: String, armor: String, keyId: String, crypto: MigrationCrypto, random: SecureRandom): Boolean {
        if (!crypto.approved()) return false
        val nonce = ByteArray(PgpMigrationPolicy.NONCE_BYTES).also { random.nextBytes(it) }
        val message = "$eoa|$keyId|${nonce.joinToString("") { "%02x".format(it) }}".toByteArray(Charsets.UTF_8)
        val signature = crypto.sign(armor, PgpMigrationPolicy.CHALLENGE_LABEL, message) ?: return false
        val good = crypto.verify(armor, PgpMigrationPolicy.CHALLENGE_LABEL, message, signature)
        val tampered = message.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val tamperedVerifies = crypto.verify(armor, PgpMigrationPolicy.CHALLENGE_LABEL, tampered, signature)
        return good && !tamperedVerifies
    }
}
