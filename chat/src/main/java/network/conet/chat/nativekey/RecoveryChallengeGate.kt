package network.conet.chat.nativekey

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import java.io.ByteArrayInputStream
import java.security.SecureRandom

/**
 * The gate every recovered private key passes before anything of it is written. A key that a recovery found (the account's own key
 * an older build left in the SDK store, or the chain backup) is accepted only when it signs a fresh challenge and the signature verifies against the
 * public key the CoNET registry holds for the account, a key that was read independently of the candidate.
 *
 *  1. The registered key must be readable ([RegisteredKeyRead.Present]), for this account, from the CoNET L1 chain and the AddressPGP contract, and read
 *     at an allowed source level (both endpoints for the automatic recovery; the primary endpoint for the page). Unreadable or absent: refused.
 *  2. The candidate's master fingerprint and first subkey key id equal the registered ones.
 *  3. A new 32-byte random nonce (local, never kept, never taken from a caller), the account, the registered identity, the chain, the contract, the
 *     block, the purpose and the source go into one fixed message. The candidate signs it (type 0x01, SHA-256, empty passphrase), under its own domain
 *     label.
 *  4. The signature is verified with the registered public ring only (never the ring that comes with the candidate): its issuing key must be in that
 *     ring, a subkey needs a valid binding signature from the registered master key, and nothing used may be revoked. A one-bit change of the message
 *     must not verify.
 *
 * Nothing here writes, logs, or returns the challenge, the signature or a key; the only output is the verified key (for the activation write) or a
 * reason code. This gate does not call `crypto.approved()` and does not read `OPENPGP_APPROVED`: the use of the Android OpenPGP functions
 * on this path is labelled [OWNER_APPROVAL], and a source scan keeps the verified key's users to the files that may hold it.
 */
internal object RecoveryChallengeGate {
    /** The label of the use of the existing Android OpenPGP implementation on this recovery path only (the global flag stays false). */
    const val OWNER_APPROVAL = "auto-recovery"

    /** Domain label of the signature: its own, not the migration one. */
    const val LABEL = "beamio.pgp.recover.challenge.v1\n"

    private const val MESSAGE_HEAD = "beamio-chat-recovery/v1"
    private const val NONCE_BYTES = 32

    enum class Purpose(val wire: String) { AUTO_RECOVERY("auto_recovery"), PAGE_RESTORE("page_restore") }

    /** Where the candidate came from. */
    enum class Origin(val wire: String) { LEGACY_STORE("legacy_store"), CHAIN_BACKUP("chain_backup"), VAULT_RECORD("vault_record") }

    enum class Failure(val wire: String) {
        REGISTRATION_UNAVAILABLE("registration_unavailable"),
        REGISTRATION_MISSING("registration_missing"),
        ACCOUNT_MISMATCH("account_mismatch"),
        IDENTITY_MISMATCH("identity_mismatch"),
        SIGN_FAILED("sign_failed"),
        VERIFY_FAILED("verify_failed"),
    }

    sealed class Result {
        class Verified(val key: VerifiedRecoveryKey) : Result()
        class Refused(val reason: Failure) : Result()
    }

    /** The signer of the challenge. Production signs with the candidate's own private key; a test may replace it (never with a value for the nonce). */
    internal fun interface ChallengeSigner {
        fun sign(secret: NativePgp.Secret, label: String, message: ByteArray): NativePgp.Outcome
    }

    /** The check of a signature against the registered ring. Production uses [verifies]; a test may replace it to prove the negative control works. */
    internal fun interface SignatureCheck {
        fun check(ring: PGPPublicKeyRing, message: ByteArray, armoredSignature: String): Boolean
    }

    private val DEFAULT_CHECK = SignatureCheck { ring, message, signature -> verifies(ring, message, signature) }

    private val DEFAULT_SIGNER = ChallengeSigner { secret, label, message ->
        NativePgp.signDocument(secret, "", label, message, NativePgp.SIG_CANONICAL_TEXT)
    }

    /**
     * Runs the gate for [candidateArmor] (the private key found by a recovery) of [account]. [registered] is the registry read; [allowed] the source
     * levels this caller accepts. The challenge nonce is made here, once per call.
     */
    fun verify(
        account: String,
        purpose: Purpose,
        origin: Origin,
        candidateArmor: String,
        registered: RegisteredKeyRead,
        allowed: Set<RegisteredPgpKey.Source>,
        random: SecureRandom = SecureRandom(),
        signer: ChallengeSigner? = null,
        check: SignatureCheck? = null,
    ): Result {
        val reg = when (registered) {
            is RegisteredKeyRead.Unknown -> return Result.Refused(Failure.REGISTRATION_UNAVAILABLE)
            is RegisteredKeyRead.Absent -> return Result.Refused(Failure.REGISTRATION_MISSING)
            is RegisteredKeyRead.Present -> registered.key
        }
        if (reg.chainId != AddressPgpChain.CONET_CHAIN_ID || reg.source !in allowed ||
            !reg.contract.equals(AddressPgpConfig.default.contract, ignoreCase = true)
        ) {
            return Result.Refused(Failure.REGISTRATION_UNAVAILABLE)
        }
        if (!PgpMigrationPolicy.EOA_RE.matches(account.lowercase()) || !reg.account.equals(account, ignoreCase = true)) {
            return Result.Refused(Failure.ACCOUNT_MISMATCH)
        }
        val secret = NativePgp.parseSecret(candidateArmor) ?: return Result.Refused(Failure.IDENTITY_MISMATCH)
        val subkey = NativePgpBackup.subkeyKeyId(secret) ?: return Result.Refused(Failure.IDENTITY_MISMATCH)
        if (!secret.fingerprint.equals(reg.fingerprint, ignoreCase = true) || !subkey.equals(reg.subkeyKeyId, ignoreCase = true)) {
            return Result.Refused(Failure.IDENTITY_MISMATCH)
        }
        val registeredRing = ringOf(reg.publicArmor) ?: return Result.Refused(Failure.REGISTRATION_UNAVAILABLE)
        val message = challengeMessage(account.lowercase(), purpose, origin, reg, nonceHex(random))
        val signature = (signer ?: DEFAULT_SIGNER).sign(secret, LABEL, message)
        if (!signature.ok || signature.value == null) return Result.Refused(Failure.SIGN_FAILED)
        val checker = check ?: DEFAULT_CHECK
        if (!checker.check(registeredRing, message, signature.value)) return Result.Refused(Failure.VERIFY_FAILED)
        // The negative control: the same signature must not verify a message that differs by one bit.
        val flipped = message.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        if (checker.check(registeredRing, flipped, signature.value)) return Result.Refused(Failure.VERIFY_FAILED)
        return Result.Verified(
            VerifiedRecoveryKey(candidateArmor, reg.publicArmor, reg.fingerprint, reg.subkeyKeyId, account.lowercase(), origin, reg.source, reg.block),
        )
    }

    private fun nonceHex(random: SecureRandom): String {
        val nonce = ByteArray(NONCE_BYTES).also { random.nextBytes(it) }
        return nonce.joinToString("") { "%02x".format(it) }
    }

    /** The one fixed message: one `name=value` per line, in this order, `\n` only. */
    internal fun challengeMessage(account: String, purpose: Purpose, origin: Origin, reg: RegisteredPgpKey, nonceHex: String): ByteArray =
        listOf(
            MESSAGE_HEAD,
            "purpose=${purpose.wire}",
            "source=${origin.wire}",
            "chain=${reg.chainId}",
            "contract=${reg.contract.lowercase()}",
            "account=$account",
            "fingerprint=${reg.fingerprint.uppercase()}",
            "subkey=${reg.subkeyKeyId.uppercase()}",
            "block=${reg.block ?: "unknown"}",
            "nonce=$nonceHex",
        ).joinToString("\n").toByteArray(Charsets.UTF_8)

    private fun ringOf(armor: String): PGPPublicKeyRing? = try {
        PGPPublicKeyRing(PGPUtil.getDecoderStream(ByteArrayInputStream(armor.toByteArray(Charsets.UTF_8))), BcKeyFingerprintCalculator())
    } catch (_: Exception) {
        null
    }

    /** Verifies [armoredSignature] over `LABEL || message` with the registered ring only. */
    private fun verifies(ring: PGPPublicKeyRing, message: ByteArray, armoredSignature: String): Boolean = try {
        val input = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredSignature.toByteArray(Charsets.UTF_8)))
        val list = PGPObjectFactory(input, BcKeyFingerprintCalculator()).nextObject() as? PGPSignatureList
        if (list == null || list.size() != 1) {
            false
        } else {
            val sig: PGPSignature = list.get(0)
            val signer = ring.getPublicKey(sig.keyID)
            if (sig.signatureType != NativePgp.SIG_CANONICAL_TEXT || sig.hashAlgorithm != HashAlgorithmTags.SHA256 || signer == null) {
                false
            } else if (!usable(ring, signer)) {
                false
            } else {
                sig.init(BcPGPContentVerifierBuilderProvider(), signer)
                sig.update(LABEL.toByteArray(Charsets.UTF_8))
                sig.update(message)
                sig.verify()
            }
        }
    } catch (_: Exception) {
        false
    }

    /**
     * The signing key is usable when neither it nor the master is revoked and, for a subkey, a binding signature of the registered master key over it
     * verifies and allows signing.
     */
    private fun usable(ring: PGPPublicKeyRing, signer: PGPPublicKey): Boolean {
        val master = ring.publicKey
        if (master.hasRevocation() || signer.hasRevocation()) return false
        if (signer.keyID == master.keyID) return true
        val bindings = signer.getSignaturesOfType(PGPSignature.SUBKEY_BINDING).asSequence().toList()
        return bindings.any { binding ->
            try {
                binding.init(BcPGPContentVerifierBuilderProvider(), master)
                val flags = binding.hashedSubPackets?.keyFlags ?: 0
                binding.verifyCertification(master, signer) && (flags and KeyFlags.SIGN_DATA) != 0
            } catch (_: Exception) {
                false
            }
        }
    }
}

/** How the page restore uses the gate: the source levels it accepts (the page reads the primary endpoint alone, so SINGLE is allowed too). */
internal class PageRecoveryGate(
    val allowed: Set<RegisteredPgpKey.Source> = setOf(RegisteredPgpKey.Source.SINGLE, RegisteredPgpKey.Source.AGREED),
    val random: SecureRandom = SecureRandom(),
    val signer: RecoveryChallengeGate.ChallengeSigner? = null,
)

/**
 * A recovered private key that passed [RecoveryChallengeGate]. It is built only by the gate (a guard test keeps every other file from constructing
 * it) and is the only thing [VerifiedPgpActivation] accepts. The armor stays inside the native layer.
 */
internal class VerifiedRecoveryKey internal constructor(
    val privateArmor: String,
    /** The registered public armor (the one that verified the signature). */
    val publicArmor: String,
    val fingerprint: String,
    val subkeyKeyId: String,
    val account: String,
    val origin: RecoveryChallengeGate.Origin,
    val source: RegisteredPgpKey.Source,
    val block: Long?,
)

/** The one write of a verified recovered key into the native PGP vault: the empty slot only, with the vault's own read-back and rollback. */
internal object VerifiedPgpActivation {
    fun write(vault: NativePgpVault, key: VerifiedRecoveryKey): NativePgpVault.Put =
        vault.put(key.account, key.privateArmor, "", overwrite = false)
}
