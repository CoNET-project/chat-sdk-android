package network.conet.chat.nativekey

/**
 * Test adapters of [PgpRestoreMachine] for one account, shared by the JVM tests and the device fixture (P-IMP-PGP option A,
 * spec r3l §25.30). The chain is one fixed record here: the real chain read adapter is not implemented yet, and the fields
 * are public so a test can simulate the chain changing under the device. The wallet is the account's own vault. No test
 * path generates a key through these adapters.
 */

/** One on-chain record. The machine changes it only through [write], which advances the version by one. */
internal class StaticChain(var storedIdentity: PgpIdentity?, var storedBackup: String) : PgpRestoreChain {
    var version: Long = if (storedIdentity == null) 0L else 1L

    override fun chainReadable(): Boolean = true
    override fun backupReadable(): Boolean = true
    override fun version(): Long = version
    override fun identity(): PgpIdentity? = storedIdentity
    override fun backupText(): String = storedBackup

    override fun write(identity: PgpIdentity, backupText: String) {
        storedIdentity = identity
        storedBackup = backupText
        version++
    }
}

/** The account's wallet: ready while the vault holds the account, and the backup password is derived from its key once. */
internal class VaultWallet(private val wallet: NativeWalletVault) : PgpRestoreWallet {
    override fun ready(): Boolean = wallet.state() is NativeWalletVault.State.Ready

    override fun passwordString(): String? {
        val key = wallet.unlock() ?: return null
        return try {
            NativePgpBackup.passwordString(key)
        } finally {
            key.fill(0)
        }
    }
}

/** For a fixture that restores and never generates: a generation request is a bug in that fixture. */
internal object NoNewKeys : PgpRestoreKeys {
    override fun newKey(deviceId: String): PgpNewKey = error("this fixture never generates a key")
}

/** A machine with one device "A" over [files] and [wrap], for [account], restoring from [chain]. */
internal fun restoreMachineForOneDevice(
    chain: PgpRestoreChain,
    wallet: NativeWalletVault,
    wrap: KeyWrap,
    files: VaultFiles,
    account: String,
): PgpRestoreMachine = PgpRestoreMachine(
    chain,
    VaultWallet(wallet),
    NoNewKeys,
    { error("this fixture writes no new backup") },
    mapOf("A" to PgpRestoreDevice("A", account, wrap, files)),
)
