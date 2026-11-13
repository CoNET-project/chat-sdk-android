package network.conet.chat.nativekey

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
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
 * Per-account PGP records and the generated key's shape, on the JVM (P-IMP-PGP option A, §42): two accounts keep their own
 * records and never overwrite each other, a vault refuses another account's record, a generated key has the expected curve
 * shape, and a key the restore machine generates decrypts and signs once it is committed. Synthetic material only (the
 * spec's test vectors).
 */
class NativePgpAccountTest {
    private val vectors = JSONObject(
        String(File(System.getenv("PGP_BACKUP_VECTORS") ?: "../spec/pgp-backup-compat-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val p1 = vectors.getJSONArray("positives").getJSONObject(0)
    private val p2 = vectors.getJSONArray("positives").getJSONObject(1)
    private val account = p1.getString("eoa").lowercase()
    private val account2 = p2.getString("eoa").lowercase()
    private val fp1 = p1.getJSONObject("expect").getString("primaryFingerprint").lowercase()
    private val fp2 = p2.getJSONObject("expect").getString("primaryFingerprint").lowercase()

    private val acceptance = JSONObject(
        String(File(System.getenv("PGP_RESTORE_VECTORS") ?: "../spec/pgp-restore-acceptance-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )

    @Test
    fun aGeneratedKeyHasTheCurve25519Shape() {
        val g = NativePgpKeyGen.generate("beamio-chat-v1", SecureRandom())
        val ring = NativePgp.parseSecret(g.privateArmor)!!.ring
        val keys = ring.secretKeys.asSequence().toList()
        assertEquals(2, keys.size)
        assertEquals(PublicKeyAlgorithmTags.EDDSA_LEGACY, keys[0].publicKey.algorithm)
        assertEquals(PublicKeyAlgorithmTags.ECDH, keys[1].publicKey.algorithm)
    }

    @Test
    fun accountsKeepTheirOwnRecordsAndNeverOverwriteEachOther() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val a = NativePgpVault(wrap, files, account)
        val b = NativePgpVault(wrap, files, account2)
        assertEquals(NativePgpVault.Put.OK, a.put(account, p1.getJSONObject("pgp").getString("privateArmor"), ""))
        assertEquals(NativePgpVault.Put.OK, b.put(account2, p2.getJSONObject("pgp").getString("privateArmor"), ""))
        assertTrue(a.state() is NativePgpVault.State.Ready && (a.state() as NativePgpVault.State.Ready).fingerprint == fp1)
        assertTrue(b.state() is NativePgpVault.State.Ready && (b.state() as NativePgpVault.State.Ready).fingerprint == fp2)
        assertFalse(NativePgpVault.recName(account) == NativePgpVault.recName(account2))
        b.forget()
        assertTrue("A survives B's removal", a.state() is NativePgpVault.State.Ready)
        assertTrue(b.state() is NativePgpVault.State.NoKey)
    }

    @Test
    fun aVaultCannotWriteAnotherAccountsRecord() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val a = NativePgpVault(wrap, files, account)
        assertEquals(NativePgpVault.Put.BAD_EOA, a.put(account2, p2.getJSONObject("pgp").getString("privateArmor"), ""))
        assertTrue(files.map.isEmpty())
    }

    /**
     * The machine generates a key for a device whose chain identity has no backup (the restore fails as `backup_missing`),
     * the user confirms, the key is committed under the chain's version, and then it decrypts and signs on that device.
     */
    @Test
    fun aKeyTheMachineGeneratesDecryptsAndSignsOnceCommitted() {
        val h = PgpRestoreHarness(acceptance, p1.getString("passwordString"), { NativeTestWrap() }, { NativeTestFiles() })
        val w = h.World()
        w.setChain("P4", "B_EMPTY")
        assertEquals("failed:backup_missing", w.machine.restore("A").result)
        assertEquals("ok", w.machine.tapEntry("A").result)
        assertEquals("ok", w.machine.keygen("A", "idem-1", true).result)
        assertEquals("ok", w.machine.commit("A").result)
        assertEquals(1, w.machine.counters.keygen)

        val dev = w.devices.getValue("A")
        val st = dev.active.state()
        assertTrue("active: $st", st is NativePgpVault.State.Ready && st.fingerprint.equals(h.identity("P3").fingerprint, ignoreCase = true))

        val pub = NativePgpKeyGen.publicArmorOf(acceptance.getJSONObject("syntheticKeys").getJSONObject("P3").getString("privateArmor"))!!
        val msg = "generated key message"
        val out = dev.active.decryptInbound(encryptTo(pub, msg))
        assertEquals("ok", out.code)
        assertEquals(msg, out.value)
        val signed = dev.active.sign("syntheticvector", NativePgp.SIG_BINARY_DOCUMENT, msg.toByteArray(Charsets.UTF_8), setOf("syntheticvector"))
        assertEquals("ok", signed.code)
        assertTrue(dev.active.verifySignature("syntheticvector", msg.toByteArray(Charsets.UTF_8), signed.value!!))
    }

    /** bcpg encryption to a public armor (the same shape as the app's route encryption; UTF-8 literal, zlib, AES-256). */
    private fun encryptTo(publicArmor: String, text: String): String {
        val ring = PGPPublicKeyRing(PGPUtil.getDecoderStream(publicArmor.toByteArray(Charsets.UTF_8).inputStream()), BcKeyFingerprintCalculator())
        val key: PGPPublicKey = ring.publicKeys.asSequence().toList().first { !it.isMasterKey && it.isEncryptionKey }
        val literal = text.toByteArray(Charsets.UTF_8)
        val random = SecureRandom()
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
