package network.conet.chat.nativekey

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.security.SecureRandom
import java.util.Date

/**
 * Inbound decryption from the shipped PGP store (2026-11-22): the shipped armor decides when it exists, read only; the native PGP vault
 * is not written. Synthetic keys only (no passphrase, the shape the migration read). Positive and negative examples, plus source guards.
 */
class LegacyPgpReaderTest {

    private val random = SecureRandom()
    private val shipped = NativePgpKeyGen.generate("synthetic-legacy <legacy@synthetic.invalid>", random)
    private val other = NativePgpKeyGen.generate("synthetic-other <other@synthetic.invalid>", random)

    /** Positive: a message to the shipped key decrypts with the shipped armor (empty passphrase), and the literal is the text. */
    @Test
    fun aMessageToTheShippedKeyDecryptsWithTheShippedArmor() {
        val armored = encryptTo(shipped.publicArmor, "synthetic inbound text")
        val out = LegacyPgpReader.decryptWith(shipped.privateArmor, armored)
        assertTrue(out.ok)
        assertEquals("synthetic inbound text", out.value)
    }

    /** Negative: a message to another key is not decrypted by the shipped armor (not a recipient). */
    @Test
    fun aMessageToAnotherKeyIsRefused() {
        val armored = encryptTo(other.publicArmor, "synthetic other text")
        assertFalse(LegacyPgpReader.decryptWith(shipped.privateArmor, armored).ok)
    }

    /** Negative: a shipped armor that does not parse is refused (bad_pgp_key), never decrypted. */
    @Test
    fun aBrokenShippedArmorIsRefused() {
        val armored = encryptTo(shipped.publicArmor, "synthetic")
        assertEquals("bad_pgp_key", LegacyPgpReader.decryptWith("not an armor", armored).code)
    }

    private val reader = File("src/main/java/network/conet/chat/nativekey/LegacyPgpReader.kt").readText(Charsets.UTF_8)
    private val wallet = File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText(Charsets.UTF_8)
    private val listen = File("src/main/java/network/conet/chat/BeamioConetChatListenSession.kt").readText(Charsets.UTF_8)

    /** Negative: the reader writes, imports and removes nothing (the shipped store is never rewritten). */
    @Test
    fun theReaderNeverWritesOrRemoves() {
        assertFalse(reader.contains(".put("))
        assertFalse(reader.contains(".clear("))
        assertFalse(reader.contains(".save("))
        assertFalse(reader.contains("commit("))
    }

    /** Negative: the migration creates no native PGP vault record (no put into pgpVault). */
    @Test
    fun theMigrationCreatesNoVaultRecord() {
        val body = wallet.substringAfter("private fun migrateLegacyPgpOutcome(app: Context): MigrationGate.Outcome").substringBefore("\n    /**")
        assertFalse(body.contains("pgpVault.put("))
        assertTrue(body.contains("MigrationGate.Outcome.RESOLVED_NOTHING"))
    }

    /** Positive: the listen decrypt and the wallet's inbound functions read the shipped armor first. */
    @Test
    fun theInboundDecryptPrefersTheShippedArmor() {
        assertTrue(listen.contains("NativeWallet.decryptInbound(app, armored)"))
        val fn = wallet.substringAfter("internal fun decryptInbound(context: Context, armored: String): NativePgp.Outcome").substringBefore("\n    }")
        assertTrue(fn.contains("LegacyPgpReader.shippedArmor(app)"))
        assertTrue(fn.indexOf("LegacyPgpReader.decryptWith") < fn.indexOf("pgp(app).decryptInbound"))
    }

    /** bcpg encryption to a public armor (the app's route encryption shape: UTF-8 literal, zlib, AES-256). */
    private fun encryptTo(publicArmor: String, text: String): String {
        val ring = PGPPublicKeyRing(PGPUtil.getDecoderStream(publicArmor.toByteArray(Charsets.UTF_8).inputStream()), BcKeyFingerprintCalculator())
        val key: PGPPublicKey = ring.publicKeys.asSequence().toList().first { !it.isMasterKey && it.isEncryptionKey }
        val literal = text.toByteArray(Charsets.UTF_8)
        val compressedOut = ByteArrayOutputStream()
        val compressor = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZLIB)
        val cOut: OutputStream = compressor.open(compressedOut)
        val lOut: OutputStream = PGPLiteralDataGenerator().open(cOut, PGPLiteralData.UTF8, "", literal.size.toLong(), Date())
        lOut.write(literal)
        lOut.close()
        compressor.close()
        val armoredOut = ByteArrayOutputStream()
        val armorOut = ArmoredOutputStream.builder().clearHeaders().build(armoredOut)
        val encryptor = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true).setSecureRandom(random),
        )
        encryptor.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(key).setSecureRandom(random))
        val eOut: OutputStream = encryptor.open(armorOut, compressedOut.size().toLong())
        eOut.write(compressedOut.toByteArray())
        eOut.close()
        armorOut.close()
        return armoredOut.toString(Charsets.UTF_8.name())
    }
}
