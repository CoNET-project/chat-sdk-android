package network.conet.chat.nativekey

import java.security.SecureRandom

/**
 * Reads the on-chain identity of an account: the encrypted PGP backup and the registered public-key fingerprint (P-IMP-PGP
 * option A, approved 2026-11-13). The implementation is the host's, read-only, and never writes. A failed read is
 * [Read.Unavailable]: it is never treated as "missing" (§42 rule).
 */
internal interface PgpIdentitySource {
    sealed class Read {
        /** The on-chain state. A null field means the record is absent on chain. */
        class Found(val backupBase64: String?, val registeredFingerprint: String?) : Read()

        /** The read failed (network, RPC, parsing). Nothing may be decided from this. */
        object Unavailable : Read()
    }

    fun read(eoa: String): Read
}

/**
 * Restore, generation and registration guards for the PGP identity of an account (§42).
 *
 * Three failure classes on restore, each returning its own code and changing nothing: `pgp_backup_missing`, `pgp_backup_
 * undecryptable` and `pgp_fingerprint_mismatch`. The native code never generates a key, never registers, never overwrites
 * the on-chain public key or the backup, and never replaces an active record of another key. A new key is generated only
 * by [generate] with the user's confirmation, and only when the chain holds no identity for the account. Before registration,
 * [registrationGuard] refuses any registration that would replace an identity on chain.
 */
internal object NativePgpRecovery {
    enum class Code(val wire: String) {
        OK("ok"),
        NO_KEY("no_key"),
        LOCKED("locked"),
        BAD_EOA("bad_eoa"),
        CANCELLED("cancelled"),
        SOURCE_UNAVAILABLE("pgp_source_unavailable"),
        BACKUP_MISSING("pgp_backup_missing"),
        BACKUP_UNDECRYPTABLE("pgp_backup_undecryptable"),
        BACKUP_INVALID("pgp_backup_invalid"),
        FINGERPRINT_MISMATCH("pgp_fingerprint_mismatch"),
        IDENTITY_EXISTS("pgp_identity_exists"),
        OVERWRITE_REFUSED("pgp_overwrite_refused"),
        NO_PENDING("pgp_no_pending"),
        ALREADY_EXISTS("already_exists"),
        PGP_LOCKED("pgp_locked"),
        WRITE_FAILED("write_failed"),
        READBACK_FAILED("readback_failed"),
    }

    /** [fingerprint] and [publicArmor] are public; the private key never leaves the native layer. */
    class Result(val code: Code, val fingerprint: String? = null, val publicArmor: String? = null)

    private const val USER_ID = "beamio-chat-v1"

    /** The wallet must hold the account of [pgp]. */
    private fun walletCheck(wallet: NativeWalletVault, account: String): Code? =
        when (val st = wallet.state()) {
            is NativeWalletVault.State.NoKey -> Code.NO_KEY
            is NativeWalletVault.State.Locked -> Code.LOCKED
            is NativeWalletVault.State.Ready -> if (st.eoa.lowercase() == account) null else Code.BAD_EOA
        }

    /**
     * Restores the account's original PGP key from the on-chain backup (P-IMP-PGP option A). Enables the identity only when the
     * decrypted key's fingerprint equals the registered one. Idempotent when that same key is already active.
     */
    fun restore(wallet: NativeWalletVault, pgp: NativePgpVault, source: PgpIdentitySource): Result {
        val account = pgp.account
        walletCheck(wallet, account)?.let { return Result(it) }
        val read = source.read(account)
        if (read !is PgpIdentitySource.Read.Found) return Result(Code.SOURCE_UNAVAILABLE)
        val backup = read.backupBase64
        val registered = read.registeredFingerprint
        when (val st = pgp.state()) {
            // A key is already active: it is the identity when it matches the registered one. Nothing is written.
            is NativePgpVault.State.Ready ->
                return when {
                    registered == null -> Result(Code.BACKUP_MISSING)
                    st.fingerprint.equals(registered, ignoreCase = true) -> Result(Code.OK, st.fingerprint)
                    else -> Result(Code.ALREADY_EXISTS)
                }
            is NativePgpVault.State.Locked -> return Result(Code.PGP_LOCKED)
            is NativePgpVault.State.NoKey -> Unit
        }
        if (backup == null || registered == null) return Result(Code.BACKUP_MISSING)
        val key = wallet.unlock() ?: return Result(Code.LOCKED)
        val password = try {
            NativePgpBackup.passwordString(key)
        } finally {
            key.fill(0)
        }
        val armorBytes = NativePgpBackup.decryptArmor(password, backup) ?: return Result(Code.BACKUP_UNDECRYPTABLE)
        val armor = String(armorBytes, Charsets.UTF_8)
        armorBytes.fill(0)
        val secret = NativePgp.parseSecret(armor) ?: return Result(Code.BACKUP_INVALID)
        if (!secret.fingerprint.equals(registered, ignoreCase = true)) return Result(Code.FINGERPRINT_MISMATCH)
        return when (pgp.put(account, armor, "")) {
            NativePgpVault.Put.OK -> Result(Code.OK, secret.fingerprint)
            NativePgpVault.Put.BAD_EOA -> Result(Code.BAD_EOA)
            NativePgpVault.Put.BAD_KEY -> Result(Code.BACKUP_INVALID)
            NativePgpVault.Put.STORE_FAILED -> Result(Code.WRITE_FAILED)
            NativePgpVault.Put.READBACK_FAILED -> Result(Code.READBACK_FAILED)
        }
    }

    /**
     * Generates a new key into the pending slot. Only with [userConfirmed] (the user's click on the generate entry), and only
     * when the chain holds no identity for the account and no active record exists. A pending key that already exists is
     * returned as it is. The pending key is not the active identity until [activate].
     */
    fun generate(
        wallet: NativeWalletVault,
        pgp: NativePgpVault,
        pending: NativePgpVault,
        source: PgpIdentitySource,
        userConfirmed: Boolean,
        random: SecureRandom = SecureRandom(),
    ): Result {
        val account = pgp.account
        if (!userConfirmed) return Result(Code.CANCELLED)
        walletCheck(wallet, account)?.let { return Result(it) }
        if (pending.account != account || !pending.isPendingSlot() || pgp.isPendingSlot()) return Result(Code.BAD_EOA)
        when (val st = pgp.state()) {
            is NativePgpVault.State.Ready -> return Result(Code.ALREADY_EXISTS, st.fingerprint)
            is NativePgpVault.State.Locked -> return Result(Code.PGP_LOCKED)
            is NativePgpVault.State.NoKey -> Unit
        }
        val read = source.read(account)
        if (read !is PgpIdentitySource.Read.Found) return Result(Code.SOURCE_UNAVAILABLE)
        if (read.backupBase64 != null || read.registeredFingerprint != null) return Result(Code.IDENTITY_EXISTS)
        when (val st = pending.state()) {
            is NativePgpVault.State.Ready -> {
                val armor = pending.pendingArmorForActivation() ?: return Result(Code.PGP_LOCKED)
                return Result(Code.OK, st.fingerprint, NativePgpKeyGen.publicArmorOf(armor))
            }
            is NativePgpVault.State.Locked -> return Result(Code.PGP_LOCKED)
            is NativePgpVault.State.NoKey -> Unit
        }
        val generated = NativePgpKeyGen.generate(USER_ID, random)
        return when (pending.put(account, generated.privateArmor, "")) {
            NativePgpVault.Put.OK -> Result(Code.OK, generated.fingerprint, generated.publicArmor)
            NativePgpVault.Put.BAD_EOA -> Result(Code.BAD_EOA)
            NativePgpVault.Put.BAD_KEY -> Result(Code.BACKUP_INVALID)
            NativePgpVault.Put.STORE_FAILED -> Result(Code.WRITE_FAILED)
            NativePgpVault.Put.READBACK_FAILED -> Result(Code.READBACK_FAILED)
        }
    }

    /**
     * Run immediately before registering [pendingFingerprint] on chain. Refuses any registration that would replace an identity
     * on chain: a different registered key, or a backup without a registered key. A read failure refuses too.
     */
    fun registrationGuard(source: PgpIdentitySource, account: String, pendingFingerprint: String): Code {
        val read = source.read(account)
        if (read !is PgpIdentitySource.Read.Found) return Code.SOURCE_UNAVAILABLE
        val registered = read.registeredFingerprint
        return when {
            registered != null && registered.equals(pendingFingerprint, ignoreCase = true) -> Code.OK
            registered != null -> Code.OVERWRITE_REFUSED
            read.backupBase64 != null -> Code.OVERWRITE_REFUSED
            else -> Code.OK
        }
    }

    /**
     * After a confirmed registration, makes the pending key the active identity. It needs the on-chain fingerprint read after
     * registering to equal the pending one. It refuses to replace an active record of another key.
     */
    fun activate(
        wallet: NativeWalletVault,
        pgp: NativePgpVault,
        pending: NativePgpVault,
        registeredFingerprint: String,
    ): Result {
        val account = pgp.account
        walletCheck(wallet, account)?.let { return Result(it) }
        val pendingState = pending.state()
        if (pendingState !is NativePgpVault.State.Ready) return Result(Code.NO_PENDING)
        if (!pendingState.fingerprint.equals(registeredFingerprint, ignoreCase = true)) return Result(Code.FINGERPRINT_MISMATCH)
        when (val st = pgp.state()) {
            is NativePgpVault.State.Ready ->
                return if (st.fingerprint.equals(pendingState.fingerprint, ignoreCase = true)) {
                    pending.forget()
                    Result(Code.OK, st.fingerprint)
                } else {
                    Result(Code.ALREADY_EXISTS)
                }
            is NativePgpVault.State.Locked -> return Result(Code.PGP_LOCKED)
            is NativePgpVault.State.NoKey -> Unit
        }
        val armor = pending.pendingArmorForActivation() ?: return Result(Code.PGP_LOCKED)
        return when (pgp.put(account, armor, "")) {
            NativePgpVault.Put.OK -> {
                pending.forget()
                Result(Code.OK, pendingState.fingerprint)
            }
            NativePgpVault.Put.BAD_EOA -> Result(Code.BAD_EOA)
            NativePgpVault.Put.BAD_KEY -> Result(Code.BACKUP_INVALID)
            NativePgpVault.Put.STORE_FAILED -> Result(Code.WRITE_FAILED)
            NativePgpVault.Put.READBACK_FAILED -> Result(Code.READBACK_FAILED)
        }
    }
}
