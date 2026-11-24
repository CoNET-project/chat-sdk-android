package network.conet.chat.nativekey

import network.conet.chat.BeamioChatPgpStore
import java.security.SecureRandom

/**
 * The automatic recovery of the account's own chat key, for an account whose native PGP vault is empty. Order, with nothing written
 * before the key has passed [RecoveryChallengeGate]:
 *
 *  1. The ACTIVE slot of the native PGP vault must be strictly empty ([NativePgpVault.State.NoKey]). A locked slot is left alone (retry); a ready
 *     one is the caller's own path.
 *  2. The registered public key of the account is read ([PgpRestoreChain.registeredKey], both endpoints at one block). Unreadable or absent: stop.
 *  3. Candidates, in this order: the key an older build left in the SDK store, then the chain backup. Each goes through the gate; the first that
 *     verifies is used. A candidate that does not verify is dropped without a trace on disk.
 *  4. The verified key is written to the ACTIVE slot (the empty slot only, with the vault's read-back and rollback), then mirrored to K_pgp. A failed
 *     mirror keeps the vault key (it is verified) and reports a retry; the next run finds it through the vault and completes the mirror.
 *
 * Any refusal is the existing `pgp_migration_retry`; the reason code goes to the SDK log only. Nothing is registered, generated or written to the chain,
 * and no old file is changed or removed.
 */
internal object AutoRecovery {
    /** The result and the reason code (for the SDK log only; it never reaches the page). */
    class Outcome(val expect: KpgpPolicy.Expect, val logCode: String)

    /** `registration_unavailable`, with the sub-reason of the chain read when it has one (the SDK log only, never the bridge). */
    private fun unavailableCode(chain: PgpRestoreChain): String =
        RecoveryChallengeGate.Failure.REGISTRATION_UNAVAILABLE.wire + (chain.registeredKeyFailure()?.let { ":$it" } ?: "")

    private fun retry(code: String) = Outcome(KpgpPolicy.decide(KpgpPolicy.Input(kind = "upgrade")), code)

    fun recover(
        eoa: String,
        activeVault: NativePgpVault,
        k: AccountPgpK,
        chain: PgpRestoreChain,
        legacy: BeamioChatPgpStore.LegacyCopy?,
        passwordForms: () -> List<String>?,
        nowSec: Long,
        random: SecureRandom = SecureRandom(),
        signer: RecoveryChallengeGate.ChallengeSigner? = null,
        /** The lock of the account's key now (the passcode): checked again right before the vault write, after the chain read and the gate. */
        lock: () -> LockState = { LockState.UNLOCKED },
    ): Outcome {
        when (activeVault.state()) {
            is NativePgpVault.State.NoKey -> Unit
            is NativePgpVault.State.Locked -> return retry("vault_locked")
            is NativePgpVault.State.Ready -> return retry("vault_ready")
        }
        val registered = chain.registeredKey()
        when (registered) {
            is RegisteredKeyRead.Unknown -> return retry(unavailableCode(chain))
            is RegisteredKeyRead.Absent -> return retry(RecoveryChallengeGate.Failure.REGISTRATION_MISSING.wire)
            is RegisteredKeyRead.Present -> Unit
        }
        var lastReason = "no_candidate"
        var verified: VerifiedRecoveryKey? = null
        fun tryGate(origin: RecoveryChallengeGate.Origin, armor: String): Boolean {
            val allowed = setOf(RegisteredPgpKey.Source.AGREED)
            val r = RecoveryChallengeGate.verify(eoa, RecoveryChallengeGate.Purpose.AUTO_RECOVERY, origin, armor, registered, allowed, random, signer)
            return when (r) {
                is RecoveryChallengeGate.Result.Verified -> {
                    verified = r.key
                    true
                }
                is RecoveryChallengeGate.Result.Refused -> {
                    lastReason = "${origin.wire}:${r.reason.wire}"
                    false
                }
            }
        }
        val local = try {
            LegacyArmorRestore.candidate(eoa, legacy)
        } catch (_: Exception) {
            LegacyArmorRestore.Candidate.None
        }
        if (local is LegacyArmorRestore.Candidate.Present) tryGate(RecoveryChallengeGate.Origin.LEGACY_STORE, local.armor)
        if (verified == null) {
            when (val c = ChainBackupRestore.candidate(chain, passwordForms)) {
                is ChainBackupRestore.Candidate.Present -> tryGate(RecoveryChallengeGate.Origin.CHAIN_BACKUP, c.armor)
                is ChainBackupRestore.Candidate.NoBackup -> if (lastReason == "no_candidate") lastReason = "backup_missing"
                is ChainBackupRestore.Candidate.Unreadable -> lastReason = "backup_unreadable"
                is ChainBackupRestore.Candidate.Undecryptable -> lastReason = "backup_undecryptable"
            }
        }
        val key = verified ?: return retry(lastReason)
        // The chain read and the gate took time: a lock since then writes nothing (passcode_not_provided, or not_ready when it cannot be told).
        when (lock()) {
            LockState.UNLOCKED -> Unit
            LockState.LOCKED -> return retry("passcode_not_provided")
            LockState.UNKNOWN -> return retry("not_ready")
        }
        return when (val put = VerifiedPgpActivation.write(activeVault, key)) {
            NativePgpVault.Put.OK -> mirror(k, eoa, key, nowSec)
            NativePgpVault.Put.EXISTS -> retry("vault_exists")
            // The put's own code is the sub-reason (log only).
            else -> retry("vault_write_failed:${put.code}")
        }
    }

    /**
     * The mirror of a key the vault already holds (a Ready slot) into K_pgp, when K_pgp is missing. The vault key is held to the
     * same gate as a recovered one: it must sign a fresh challenge that the registered public key verifies (both endpoints, one block) before K_pgp is
     * written from it. A refusal writes nothing (the vault key is untouched either way) and is the existing retry state; K_pgp that already exists is
     * never reached (the caller keeps it without reading the chain).
     */
    fun mirrorVault(
        eoa: String,
        record: KpgpUpgrade.LRecord,
        k: AccountPgpK,
        chain: PgpRestoreChain,
        nowSec: Long,
        random: SecureRandom = SecureRandom(),
        signer: RecoveryChallengeGate.ChallengeSigner? = null,
        lock: () -> LockState = { LockState.UNLOCKED },
    ): Outcome {
        val registered = chain.registeredKey()
        when (registered) {
            is RegisteredKeyRead.Unknown -> return retry(unavailableCode(chain))
            is RegisteredKeyRead.Absent -> return retry(RecoveryChallengeGate.Failure.REGISTRATION_MISSING.wire)
            is RegisteredKeyRead.Present -> Unit
        }
        val gate = RecoveryChallengeGate.verify(
            eoa, RecoveryChallengeGate.Purpose.AUTO_RECOVERY, RecoveryChallengeGate.Origin.VAULT_RECORD, record.privateArmor,
            registered, setOf(RegisteredPgpKey.Source.AGREED), random, signer,
        )
        if (gate is RecoveryChallengeGate.Result.Refused) return retry("vault_record:${gate.reason.wire}")
        when (lock()) {
            LockState.UNLOCKED -> Unit
            LockState.LOCKED -> return retry("passcode_not_provided")
            LockState.UNKNOWN -> return retry("not_ready")
        }
        // K gets the registered public armor, the same bytes the recovery path writes (the fingerprint matches by the gate, the bytes then do too).
        val verified = (gate as RecoveryChallengeGate.Result.Verified).key
        val expect = KpgpUpgrade.upgrade(k, eoa, record, userClick = false, nowSec = nowSec, registeredPublicArmor = verified.publicArmor)
        return Outcome(expect, if (expect.action == "pgp_migration_retry") "k_mirror_failed" else "mirrored:vault_record")
    }

    private fun mirror(k: AccountPgpK, eoa: String, key: VerifiedRecoveryKey, nowSec: Long): Outcome {
        val written = try {
            k.writeIfAbsent(eoa, PgpMigrationPolicy.WORKSPACE, key.subkeyKeyId, key.publicArmor, key.privateArmor, nowSec)
        } catch (_: Exception) {
            null
        }
        val ok = written == AccountPgpKWrite.WRITTEN
        val fromLegacy = key.origin == RecoveryChallengeGate.Origin.LEGACY_STORE
        val expect = KpgpPolicy.decide(
            KpgpPolicy.Input(
                kind = "upgrade",
                kPgpExists = false,
                writeOk = ok,
                readbackOk = ok,
                lPresent = fromLegacy,
                lValid = fromLegacy,
                chainBackupPresent = !fromLegacy,
                chainVerify = !fromLegacy,
            ),
        )
        return Outcome(expect, if (ok) "recovered:${key.origin.wire}" else "k_mirror_failed")
    }
}
