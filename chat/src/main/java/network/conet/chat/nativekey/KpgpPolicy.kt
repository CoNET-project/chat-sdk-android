package network.conet.chat.nativekey

/**
 * The decision for the account PGP item K_pgp (§25.52Y.59, PM ruling): creation with W in one transaction, and the upgrade of an account that has W
 * but no K_pgp. Pure: the caller performs the writes, deletes and reads it asks for. The vector group `kpgpCases` (KP-01 to KP-13) checks it.
 *
 * Upgrade order: an existing K_pgp is kept; then the native PGP record L (valid: K_pgp is written from it, L is never deleted); then the chain backup
 * (verified: written); otherwise a failure is pgp_migration_retry, never a silent new key. A new key is generated only on the user's explicit click.
 */
internal object KpgpPolicy {
    data class Input(
        val kind: String,
        val kPgpExists: Boolean = false,
        val generateOk: Boolean = true,
        val writeOk: Boolean = true,
        val readbackOk: Boolean = true,
        val lPresent: Boolean = false,
        val lValid: Boolean = false,
        val chainBackupPresent: Boolean = false,
        val chainVerify: Boolean = false,
        val userClick: Boolean = false,
    )

    data class Expect(
        val action: String,
        val writes: List<String>,
        val deletes: List<String>,
        val page: String,
        val rollback: Boolean = false,
        val registryReplace: Boolean = false,
    )

    private val K = "K_pgp"
    private val W = "W"

    fun decide(i: Input): Expect = when (i.kind) {
        "create" -> create(i)
        "upgrade" -> upgrade(i)
        else -> throw IllegalArgumentException("unknown kind ${i.kind}")
    }

    private fun create(i: Input): Expect {
        if (i.kPgpExists) return Expect("not_available", emptyList(), emptyList(), "none")
        if (!i.generateOk) return Expect("write_failed", emptyList(), emptyList(), "none", rollback = true)
        if (i.writeOk && i.readbackOk) return Expect("created", listOf(K, W), emptyList(), "first_screen_done")
        // A failed write or read-back removes both K_pgp and W: no half account.
        return Expect("write_failed", listOf(K, W), listOf(K, W), "none", rollback = true)
    }

    private fun upgrade(i: Input): Expect {
        if (i.kPgpExists) return Expect("keep_existing", emptyList(), emptyList(), "home")
        if (i.lPresent && i.lValid) return writeFrom(i, "upgraded_from_L")
        if (i.chainBackupPresent) {
            return if (i.chainVerify) writeFrom(i, "upgraded_from_chain")
            else Expect("pgp_migration_retry", emptyList(), emptyList(), "pgp_migration_retry", rollback = true)
        }
        if (i.userClick) return Expect("generated_on_user_click", listOf(K), emptyList(), "home", registryReplace = true)
        return Expect("pgp_migration_retry", emptyList(), emptyList(), "pgp_migration_retry")
    }

    /** Writes K_pgp from a verified source. A failed write or read-back never deletes the source, and leaves the retry page. */
    private fun writeFrom(i: Input, action: String): Expect {
        if (i.writeOk && i.readbackOk) return Expect(action, listOf(K), emptyList(), "home")
        return Expect("pgp_migration_retry", emptyList(), emptyList(), "pgp_migration_retry", rollback = true)
    }
}
