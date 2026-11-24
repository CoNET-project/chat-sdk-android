package network.conet.chat.nativekey

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

/**
 * The recovery gate with real OpenPGP keys: a recovered key is accepted only when it signs a fresh challenge that the registered
 * public key verifies. The refusals (registration unreadable or absent, another account, another identity, a signature that is missing, made by
 * another key, a replayed one, or made by a signing subkey the registered ring does not hold) all give a reason and no key.
 */
class RecoveryChallengeGateTest {
    private val random = SecureRandom()
    private val account = "0x" + "ab".repeat(20)
    private val own = RecKeys.generate(account, random)
    private val other = RecKeys.generate(account, random)
    private val allowedAuto = setOf(RegisteredPgpKey.Source.AGREED)

    private fun verify(
        candidate: RecPgp = own,
        registered: RegisteredKeyRead = registeredOf(own, account),
        allowed: Set<RegisteredPgpKey.Source> = allowedAuto,
        purpose: RecoveryChallengeGate.Purpose = RecoveryChallengeGate.Purpose.AUTO_RECOVERY,
        origin: RecoveryChallengeGate.Origin = RecoveryChallengeGate.Origin.LEGACY_STORE,
        who: String = account,
        signer: RecoveryChallengeGate.ChallengeSigner? = null,
    ) = RecoveryChallengeGate.verify(who, purpose, origin, candidate.privateArmor, registered, allowed, random, signer)

    private fun refusal(r: RecoveryChallengeGate.Result): RecoveryChallengeGate.Failure =
        (r as RecoveryChallengeGate.Result.Refused).reason

    // ---- accepted --------------------------------------------------------------------------------------------------------------------

    @Test
    fun theRegisteredKeyThatSignsTheChallengeIsVerified() {
        for (origin in RecoveryChallengeGate.Origin.values()) {
            val r = verify(origin = origin)
            assertTrue("$origin", r is RecoveryChallengeGate.Result.Verified)
            val key = (r as RecoveryChallengeGate.Result.Verified).key
            assertEquals(own.privateArmor, key.privateArmor)
            assertEquals("the verified key carries the REGISTERED public armor", own.publicArmor, key.publicArmor)
            assertEquals(origin, key.origin)
            assertEquals(account, key.account)
        }
    }

    @Test
    fun theGateDoesNotNeedTheGlobalApprovalFlag() {
        assertFalse(PgpMigrationPolicy.OPENPGP_APPROVED)
        assertTrue(verify() is RecoveryChallengeGate.Result.Verified)
    }

    // ---- the registration -------------------------------------------------------------------------------------------------------------

    @Test
    fun anUnreadableRegistrationIsUnavailableAndAnAbsentOneIsMissing() {
        assertEquals(RecoveryChallengeGate.Failure.REGISTRATION_UNAVAILABLE, refusal(verify(registered = RegisteredKeyRead.Unknown)))
        assertEquals(RecoveryChallengeGate.Failure.REGISTRATION_MISSING, refusal(verify(registered = RegisteredKeyRead.Absent)))
    }

    @Test
    fun aRegistrationFromTheWrongChainContractOrSourceLevelIsUnavailable() {
        assertEquals(RecoveryChallengeGate.Failure.REGISTRATION_UNAVAILABLE, refusal(verify(registered = registeredOf(own, account, chainId = 1L))))
        assertEquals(
            RecoveryChallengeGate.Failure.REGISTRATION_UNAVAILABLE,
            refusal(verify(registered = registeredOf(own, account, contract = "0x" + "11".repeat(20)))),
        )
        // The automatic recovery needs both endpoints; one endpoint is enough for the page only.
        val single = registeredOf(own, account, source = RegisteredPgpKey.Source.SINGLE)
        assertEquals(RecoveryChallengeGate.Failure.REGISTRATION_UNAVAILABLE, refusal(verify(registered = single)))
        assertTrue(verify(registered = single, allowed = setOf(RegisteredPgpKey.Source.SINGLE, RegisteredPgpKey.Source.AGREED), purpose = RecoveryChallengeGate.Purpose.PAGE_RESTORE) is RecoveryChallengeGate.Result.Verified)
    }

    @Test
    fun aRegistrationOfAnotherAccountIsAMismatch() {
        val foreign = "0x" + "cd".repeat(20)
        assertEquals(RecoveryChallengeGate.Failure.ACCOUNT_MISMATCH, refusal(verify(registered = registeredOf(own, foreign))))
        assertEquals(RecoveryChallengeGate.Failure.ACCOUNT_MISMATCH, refusal(verify(who = "not-an-account")))
    }

    // ---- the identity ----------------------------------------------------------------------------------------------------------------

    @Test
    fun aKeyThatIsNotTheRegisteredIdentityIsAMismatch() {
        assertEquals(RecoveryChallengeGate.Failure.IDENTITY_MISMATCH, refusal(verify(candidate = other)))
        assertEquals(RecoveryChallengeGate.Failure.IDENTITY_MISMATCH, refusal(RecoveryChallengeGate.verify(account, RecoveryChallengeGate.Purpose.AUTO_RECOVERY, RecoveryChallengeGate.Origin.CHAIN_BACKUP, "not a key", registeredOf(own, account), allowedAuto, random)))
    }

    @Test
    fun theSameMasterWithAnotherSubkeyIsAMismatch() {
        val registered = registeredOf(own, account, subkey = other.identity.subkeyKeyId)
        assertEquals(RecoveryChallengeGate.Failure.IDENTITY_MISMATCH, refusal(verify(registered = registered)))
    }

    // ---- the signature ---------------------------------------------------------------------------------------------------------------

    @Test
    fun aSignerThatFailsIsSignFailed() {
        val r = verify(signer = RecoveryChallengeGate.ChallengeSigner { _, _, _ -> NativePgp.Outcome.fail("sign_failed") })
        assertEquals(RecoveryChallengeGate.Failure.SIGN_FAILED, refusal(r))
    }

    @Test
    fun aSignatureMadeByAnotherKeyDoesNotVerify() {
        val otherSecret = NativePgp.parseSecret(other.privateArmor)!!
        val r = verify(signer = RecoveryChallengeGate.ChallengeSigner { _, label, message ->
            NativePgp.signDocument(otherSecret, "", label, message, NativePgp.SIG_CANONICAL_TEXT)
        })
        assertEquals(RecoveryChallengeGate.Failure.VERIFY_FAILED, refusal(r))
    }

    @Test
    fun aGarbageSignatureOrAnotherTypeOrAnotherLabelDoesNotVerify() {
        assertEquals(RecoveryChallengeGate.Failure.VERIFY_FAILED, refusal(verify(signer = RecoveryChallengeGate.ChallengeSigner { _, _, _ -> NativePgp.Outcome.ok("not a signature") })))
        val secret = NativePgp.parseSecret(own.privateArmor)!!
        val binary = verify(signer = RecoveryChallengeGate.ChallengeSigner { s, label, message -> NativePgp.signDocument(s, "", label, message, NativePgp.SIG_BINARY_DOCUMENT) })
        assertEquals("only the canonical-text type is accepted", RecoveryChallengeGate.Failure.VERIFY_FAILED, refusal(binary))
        val wrongLabel = verify(signer = RecoveryChallengeGate.ChallengeSigner { s, _, message ->
            NativePgp.signDocument(s, "", PgpMigrationPolicy.CHALLENGE_LABEL, message, NativePgp.SIG_CANONICAL_TEXT)
        })
        assertEquals("the migration label is not this domain", RecoveryChallengeGate.Failure.VERIFY_FAILED, refusal(wrongLabel))
        assertTrue(secret.fingerprint.isNotEmpty())
    }

    @Test
    fun anOldChallengeCannotBeReused() {
        val messages = ArrayList<String>()
        var recorded: String? = null
        val first = verify(signer = RecoveryChallengeGate.ChallengeSigner { s, label, message ->
            messages += String(message)
            NativePgp.signDocument(s, "", label, message, NativePgp.SIG_CANONICAL_TEXT).also { recorded = it.value }
        })
        assertTrue(first is RecoveryChallengeGate.Result.Verified)
        // The second run is handed the signature of the first run's challenge.
        val replay = verify(signer = RecoveryChallengeGate.ChallengeSigner { _, _, message ->
            messages += String(message)
            NativePgp.Outcome.ok(recorded!!)
        })
        assertEquals(RecoveryChallengeGate.Failure.VERIFY_FAILED, refusal(replay))
        assertEquals(2, messages.size)
        assertNotEquals("each run makes its own nonce", messages[0], messages[1])
    }

    // ---- the challenge ---------------------------------------------------------------------------------------------------------------

    @Test
    fun theChallengeIsTheFixedMessageWithAFreshNonceBoundToTheAccountAndThePurpose() {
        val seen = ArrayList<String>()
        for (i in 0 until 3) {
            verify(
                purpose = RecoveryChallengeGate.Purpose.AUTO_RECOVERY,
                origin = RecoveryChallengeGate.Origin.CHAIN_BACKUP,
                signer = RecoveryChallengeGate.ChallengeSigner { s, label, message ->
                    assertEquals(RecoveryChallengeGate.LABEL, label)
                    seen += String(message)
                    NativePgp.signDocument(s, "", label, message, NativePgp.SIG_CANONICAL_TEXT)
                },
            )
        }
        assertEquals(3, seen.toSet().size)
        val lines = seen[0].split("\n")
        assertEquals("beamio-chat-recovery/v1", lines[0])
        assertEquals("purpose=auto_recovery", lines[1])
        assertEquals("source=chain_backup", lines[2])
        assertEquals("chain=224422", lines[3])
        assertEquals("contract=" + AddressPgpConfig.default.contract.lowercase(), lines[4])
        assertEquals("account=$account", lines[5])
        assertEquals("fingerprint=${own.identity.fingerprint}", lines[6])
        assertEquals("subkey=${own.identity.subkeyKeyId}", lines[7])
        assertEquals("block=100", lines[8])
        assertTrue(Regex("^nonce=[0-9a-f]{64}$").matches(lines[9]))
        assertEquals(10, lines.size)
    }

    @Test
    fun thePurposeAndTheSourceAreInsideTheSignedMessage() {
        val seen = ArrayList<String>()
        val signer = RecoveryChallengeGate.ChallengeSigner { s, label, message ->
            seen += String(message)
            NativePgp.signDocument(s, "", label, message, NativePgp.SIG_CANONICAL_TEXT)
        }
        verify(purpose = RecoveryChallengeGate.Purpose.PAGE_RESTORE, origin = RecoveryChallengeGate.Origin.LEGACY_STORE, signer = signer, allowed = setOf(RegisteredPgpKey.Source.AGREED))
        assertTrue(seen[0].contains("purpose=page_restore"))
        assertTrue(seen[0].contains("source=legacy_store"))
    }

    // ---- the registered ring is the only verifier ------------------------------------------------------------------------------------

    /** A key whose master only certifies and whose signing key is a subkey (first subkey), plus an encryption subkey. */
    private class SubkeySigner(val secretRing: PGPSecretKeyRing, val publicRing: PGPPublicKeyRing, val signingKeyId: Long, val privateArmor: String)

    @Suppress("DEPRECATION")
    private fun keyWithSigningSubkey(): SubkeySigner {
        val date = Date()
        val e1 = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(random)) }.generateKeyPair()
        val e2 = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(random)) }.generateKeyPair()
        val x = X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(random)) }.generateKeyPair()
        val master = BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, e1, date)
        val sign = BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, e2, date)
        val enc = BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, x, date)
        val masterHashed = PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.CERTIFY_OTHER) }.generate()
        val signHashed = PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.SIGN_DATA) }.generate()
        val encHashed = PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.ENCRYPT_COMMS) }.generate()
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, master, account, BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            masterHashed, null, BcPGPContentSignerBuilder(master.publicKey.algorithm, HashAlgorithmTags.SHA256), null,
        )
        gen.addSubKey(sign, signHashed, null)
        gen.addSubKey(enc, encHashed, null)
        val secret = gen.generateSecretKeyRing()
        val out = ByteArrayOutputStream()
        ArmoredOutputStream.builder().clearHeaders().build(out).use { secret.encode(it) }
        return SubkeySigner(secret, gen.generatePublicKeyRing(), sign.keyID, out.toString(Charsets.UTF_8.name()))
    }

    private fun armorOf(ring: PGPPublicKeyRing): String {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream.builder().clearHeaders().build(out).use { ring.encode(it) }
        return out.toString(Charsets.UTF_8.name())
    }

    private fun signWithSubkey(k: SubkeySigner) = RecoveryChallengeGate.ChallengeSigner { _, label, message ->
        val sk = k.secretRing.getSecretKey(k.signingKeyId)
        val priv = sk.extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)))
        val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256))
        gen.init(NativePgp.SIG_CANONICAL_TEXT, priv)
        gen.update(label.toByteArray(Charsets.UTF_8))
        gen.update(message)
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { gen.generate().encode(it) }
        NativePgp.Outcome.ok(String(out.toByteArray(), Charsets.US_ASCII))
    }

    private fun identityOf(k: SubkeySigner): PgpIdentity {
        val secret = NativePgp.parseSecret(k.privateArmor)!!
        return PgpIdentity(secret.fingerprint.uppercase(), NativePgpBackup.subkeyKeyId(secret)!!)
    }

    @Test
    fun aSigningSubkeyThatTheRegisteredRingHoldsAndBindsIsAccepted() {
        val k = keyWithSigningSubkey()
        val id = identityOf(k)
        val registered = RegisteredKeyRead.Present(
            RegisteredPgpKey(account, id.fingerprint, id.subkeyKeyId, armorOf(k.publicRing), 7L, RegisteredPgpKey.Source.AGREED, AddressPgpChain.CONET_CHAIN_ID, AddressPgpConfig.default.contract.lowercase()),
        )
        val r = RecoveryChallengeGate.verify(
            account, RecoveryChallengeGate.Purpose.AUTO_RECOVERY, RecoveryChallengeGate.Origin.CHAIN_BACKUP, k.privateArmor, registered, allowedAuto, random, signWithSubkey(k),
        )
        assertTrue(r is RecoveryChallengeGate.Result.Verified)
    }

    @Test
    fun aRegisteredRingWithoutTheSigningSubkeyDoesNotVerifyTheSignature() {
        val k = keyWithSigningSubkey()
        val id = identityOf(k)
        val stripped = PGPPublicKeyRing.removePublicKey(k.publicRing, k.publicRing.getPublicKey(k.signingKeyId))
        val registered = RegisteredKeyRead.Present(
            RegisteredPgpKey(account, id.fingerprint, id.subkeyKeyId, armorOf(stripped), 7L, RegisteredPgpKey.Source.AGREED, AddressPgpChain.CONET_CHAIN_ID, AddressPgpConfig.default.contract.lowercase()),
        )
        val r = RecoveryChallengeGate.verify(
            account, RecoveryChallengeGate.Purpose.AUTO_RECOVERY, RecoveryChallengeGate.Origin.CHAIN_BACKUP, k.privateArmor, registered, allowedAuto, random, signWithSubkey(k),
        )
        assertEquals("the verifying key must be in the registered ring, not in the candidate's", RecoveryChallengeGate.Failure.VERIFY_FAILED, refusal(r))
    }

    @Test
    fun theCandidatesOwnRingIsNeverUsedToVerify() {
        // The registered armor is another key's public ring with the candidate's identity written next to it: the signature cannot verify with it.
        val registered = registeredOf(own, account, publicArmor = other.publicArmor)
        assertEquals(RecoveryChallengeGate.Failure.VERIFY_FAILED, refusal(verify(registered = registered)))
    }

    @Test
    fun aRegisteredArmorThatDoesNotParseIsUnavailable() {
        val registered = registeredOf(own, account, publicArmor = "not an armor")
        assertEquals(RecoveryChallengeGate.Failure.REGISTRATION_UNAVAILABLE, refusal(verify(registered = registered)))
    }

    @Test
    fun theGateOutputCarriesNoChallengeOrSignature() {
        val r = verify() as RecoveryChallengeGate.Result.Verified
        val names = r.key.javaClass.declaredFields.map { it.name }.toSet()
        assertFalse(names.any { it.contains("nonce", true) || it.contains("signature", true) || it.contains("challenge", true) })
        assertTrue(PGPUtil::class.java.name.isNotEmpty())
    }

    // ---- the one-bit negative control really runs -------------------------------------------------------------------------------------

    @Test
    fun aVerifierThatAcceptsAnythingIsCaughtByTheOneBitControl() {
        val acceptAll = RecoveryChallengeGate.SignatureCheck { _, _, _ -> true }
        val r = RecoveryChallengeGate.verify(
            account, RecoveryChallengeGate.Purpose.AUTO_RECOVERY, RecoveryChallengeGate.Origin.LEGACY_STORE, own.privateArmor,
            registeredOf(own, account), allowedAuto, random, null, acceptAll,
        )
        assertEquals("a broken verifier must not open the gate", RecoveryChallengeGate.Failure.VERIFY_FAILED, refusal(r))
    }

    @Test
    fun aVerifierThatRejectsEverythingGivesVerifyFailedAndTheRealOneAccepts() {
        val rejectAll = RecoveryChallengeGate.SignatureCheck { _, _, _ -> false }
        val r = RecoveryChallengeGate.verify(
            account, RecoveryChallengeGate.Purpose.AUTO_RECOVERY, RecoveryChallengeGate.Origin.LEGACY_STORE, own.privateArmor,
            registeredOf(own, account), allowedAuto, random, null, rejectAll,
        )
        assertEquals(RecoveryChallengeGate.Failure.VERIFY_FAILED, refusal(r))
        assertTrue(verify() is RecoveryChallengeGate.Result.Verified)
    }

    @Test
    fun theControlChecksTheSameSignatureOnAMessageThatDiffersByOneBit() {
        val seen = ArrayList<ByteArray>()
        var signatureSeen: String? = null
        val spy = RecoveryChallengeGate.SignatureCheck { ring, message, signature ->
            seen += message
            if (signatureSeen == null) signatureSeen = signature else assertEquals("the control uses the same signature", signatureSeen, signature)
            false
        }
        RecoveryChallengeGate.verify(
            account, RecoveryChallengeGate.Purpose.AUTO_RECOVERY, RecoveryChallengeGate.Origin.LEGACY_STORE, own.privateArmor,
            registeredOf(own, account), allowedAuto, random, null, spy,
        )
        // The first check fails and ends the run; to see the control, let the first one pass and the second answer.
        val seen2 = ArrayList<ByteArray>()
        var calls = 0
        val passFirst = RecoveryChallengeGate.SignatureCheck { _, message, _ ->
            seen2 += message
            calls++ == 0
        }
        val ok = RecoveryChallengeGate.verify(
            account, RecoveryChallengeGate.Purpose.AUTO_RECOVERY, RecoveryChallengeGate.Origin.LEGACY_STORE, own.privateArmor,
            registeredOf(own, account), allowedAuto, random, null, passFirst,
        )
        assertTrue("the second answer (false) lets it through", ok is RecoveryChallengeGate.Result.Verified)
        assertEquals(2, seen2.size)
        var diffBits = 0
        for (i in seen2[0].indices) diffBits += Integer.bitCount((seen2[0][i].toInt() xor seen2[1][i].toInt()) and 0xFF)
        assertEquals("exactly one bit differs", 1, diffBits)
        assertEquals(1, seen.size)
    }
}
