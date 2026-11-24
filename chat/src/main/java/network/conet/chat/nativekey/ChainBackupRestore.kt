package network.conet.chat.nativekey

/**
 * The chain-backup candidate of the recovery . Read-only: it takes the backup the account stored on the chain and opens it
 * with the account's wallet key, in any of the six key-string forms a legacy backup may have been sealed with. It is only a candidate: whether the key
 * is the registered one is decided by [RecoveryChallengeGate] (a fresh challenge signed by the candidate and verified with the registered public key),
 * and nothing is written before that.
 *
 * Every failure is a reason, never a key. A chain or backup read that fails is [Candidate.Unreadable], not "no backup".
 */
internal object ChainBackupRestore {
    sealed class Candidate {
        /** The chain holds no backup for the account. */
        object NoBackup : Candidate()

        /** The chain cannot be read, or the wallet key is not available. */
        object Unreadable : Candidate()

        /** A backup exists but this account's key does not open it, or it does not hold a private key block. */
        object Undecryptable : Candidate()

        /** The decrypted private key block. It stays inside the native layer. */
        class Present(val armor: String) : Candidate()
    }

    fun candidate(chain: PgpRestoreChain, passwordForms: () -> List<String>?): Candidate {
        if (!chain.chainReadable() || !chain.backupReadable()) return Candidate.Unreadable
        val backup = chain.backupText()
        if (backup.isEmpty()) return Candidate.NoBackup
        val forms = passwordForms() ?: return Candidate.Unreadable
        val bytes = NativePgpBackup.decryptArmorAny(forms, backup) ?: return Candidate.Undecryptable
        return try {
            val armor = String(bytes, Charsets.UTF_8)
            if (armor.contains("BEGIN PGP PRIVATE KEY")) Candidate.Present(armor) else Candidate.Undecryptable
        } finally {
            bytes.fill(0)
        }
    }
}
