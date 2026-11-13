package network.conet.chat.nativekey

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

/**
 * A new OpenPGP key of the same shape the PWA generates (openpgp.js `generateKey`, type curve25519): a primary EdDSA
 * (legacy) signing key and an ECDH (curve25519) encryption subkey, no passphrase, one user ID. Generated natively with the
 * BouncyCastle lightweight API. The private armor stays in native code; callers get the public armor and the fingerprint.
 */
internal object NativePgpKeyGen {
    class Generated(val privateArmor: String, val publicArmor: String, val fingerprint: String)

    @Suppress("DEPRECATION")
    fun generate(userId: String, random: SecureRandom, createdAt: Date = Date()): Generated {
        val ed = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(random)) }.generateKeyPair()
        val x = X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(random)) }.generateKeyPair()
        val master = BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, ed, createdAt)
        val sub = BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, x, createdAt)
        val masterHashed = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
        }.generate()
        val subHashed = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
        }.generate()
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            master,
            userId,
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            masterHashed,
            null,
            BcPGPContentSignerBuilder(master.publicKey.algorithm, HashAlgorithmTags.SHA256),
            null,
        )
        gen.addSubKey(sub, subHashed, null)
        val secret = gen.generateSecretKeyRing()
        val public = gen.generatePublicKeyRing()
        val privOut = ByteArrayOutputStream()
        ArmoredOutputStream.builder().clearHeaders().build(privOut).use { secret.encode(it) }
        val pubOut = ByteArrayOutputStream()
        ArmoredOutputStream.builder().clearHeaders().build(pubOut).use { public.encode(it) }
        val priv = privOut.toString(Charsets.UTF_8.name())
        val fp = NativePgp.parseSecret(priv)?.fingerprint ?: error("generated key does not parse")
        return Generated(priv, pubOut.toString(Charsets.UTF_8.name()), fp)
    }

    /** The public armor of a private armor (native-only input). `null` if it does not parse. */
    fun publicArmorOf(privateArmor: String): String? {
        val ring = NativePgp.parseSecret(privateArmor)?.ring ?: return null
        val publics = ring.secretKeys.asSequence().map { it.publicKey }.toList()
        val out = ByteArrayOutputStream()
        ArmoredOutputStream.builder().clearHeaders().build(out).use { PGPPublicKeyRing(publics).encode(it) }
        return out.toString(Charsets.UTF_8.name())
    }
}
