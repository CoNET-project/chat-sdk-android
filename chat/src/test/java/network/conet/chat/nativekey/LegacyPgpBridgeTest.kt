package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpDecryptInbound
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
import org.json.JSONObject
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
 * The `pgpDecryptInbound` bridge with only the shipped PGP armor (2026-11-22): the shipped armor answers without the vault's NoKey gate, the
 * same checks apply as the vault path, and nothing is written. Synthetic keys and account only.
 */
class LegacyPgpBridgeTest {

    private val random = SecureRandom()
    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val shipped = NativePgpKeyGen.generate("synthetic-bridge <bridge@synthetic.invalid>", random)
    private val other = NativePgpKeyGen.generate("synthetic-bridge-other <other@synthetic.invalid>", random)

    private fun body(armored: String, account: String = "$eoa:ws") = JSONObject().put("accountKey", account).put("armoredMessage", armored)

    /** Positive: a message to the shipped key answers ok with the plaintext, with no vault and no NoKey gate. */
    @Test
    fun aMessageToTheShippedKeyAnswersOkWithoutTheVault() {
        val armored = encryptTo(shipped.publicArmor, "synthetic bridge text")
        val a = LegacyPgpReader.inboundAnswer(shipped.privateArmor, eoa, body(armored))
        assertTrue(a.ok)
        assertEquals("synthetic bridge text", a.result!!.getString("plaintext"))
    }

    /** Negative: a message to another key is refused (recipient_mismatch) before any decrypt. */
    @Test
    fun aMessageToAnotherKeyIsRefusedAsRecipientMismatch() {
        val armored = encryptTo(other.publicArmor, "synthetic other")
        assertEquals("recipient_mismatch", LegacyPgpReader.inboundAnswer(shipped.privateArmor, eoa, body(armored)).error)
    }

    /** Negative: an account other than the shipped owner is refused (account_mismatch). */
    @Test
    fun anotherAccountIsRefused() {
        val armored = encryptTo(shipped.publicArmor, "synthetic")
        val wrong = "0x0cf9000000000000000000000000000000002022"
        assertEquals("account_mismatch", LegacyPgpReader.inboundAnswer(shipped.privateArmor, eoa, body(armored, "$wrong:ws")).error)
    }

    /** Negative: a payload that is not an OpenPGP message is refused (not_openpgp_message). */
    @Test
    fun aNonOpenPgpPayloadIsRefused() {
        assertEquals("not_openpgp_message", LegacyPgpReader.inboundAnswer(shipped.privateArmor, eoa, body("not a message")).error)
    }

    /** Source guard: the bridge reads the shipped armor before the vault's NoKey gate, and that gate still runs for the vault path. */
    @Test
    fun theBridgeReadsTheShippedArmorBeforeTheVaultGate() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        val fn = module.substringAfter("private fun handlePgpDecryptInbound(body: JSONObject) {").substringBefore("\n    }\n")
        assertTrue(fn.indexOf("LegacyPgpReader.shippedArmor(ctx)") in 0 until fn.indexOf("NoKeyGate.gateOf"))
        assertTrue(fn.contains("LegacyPgpReader.inboundAnswer(shipped, legacyEoa, body)"))
        val shippedBlock = fn.substringBefore("NoKeyGate.gateOf")
        assertFalse("the shipped path writes no store", shippedBlock.contains("pgpVault.put(") || shippedBlock.contains("clear(") || shippedBlock.contains("save("))
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
