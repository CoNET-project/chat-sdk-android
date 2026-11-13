package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.security.SecureRandom
import java.util.Date
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * §42 (P-IMP-PGP option A, approved): restore from the on-chain backup, the three failure classes, the user-confirmed
 * generation, the registration guard and the activation. Synthetic material only: the public test mnemonics and PGP keys of
 * `pgp-backup-compat-vectors.v1.json`. Every refusal is checked for "nothing changed": no record, no pending key, no wallet
 * change.
 */
class NativePgpRecoveryTest {
    private val vectors = JSONObject(
        String(File(System.getenv("PGP_BACKUP_VECTORS") ?: "../spec/pgp-backup-compat-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val p1 = vectors.getJSONArray("positives").getJSONObject(0)
    private val p2 = vectors.getJSONArray("positives").getJSONObject(1)
    private val account = p1.getString("eoa").lowercase()
    private val account2 = p2.getString("eoa").lowercase()
    private val fp1 = p1.getJSONObject("expect").getString("primaryFingerprint").lowercase()
    private val fp2 = p2.getJSONObject("expect").getString("primaryFingerprint").lowercase()
    private val backup1 = p1.getJSONObject("backup").getString("base64")
    private val test1 = p1.getJSONObject("testMessage")
    private val mnemonic1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private class Chain(backup: String?, registered: String?) : PgpIdentitySource {
        val found = PgpIdentitySource.Read.Found(backup, registered)
        override fun read(eoa: String): PgpIdentitySource.Read = found
    }

    private object Unavailable : PgpIdentitySource {
        override fun read(eoa: String): PgpIdentitySource.Read = PgpIdentitySource.Read.Unavailable
    }

    /** The wallet holds the account (imported from the public test mnemonic); the PGP records are empty. */
    private class World(val wrap: NativeTestWrap, val files: NativeTestFiles, val account: String) {
        val wallet = NativeWalletVault(wrap, files)
        val pgp = NativePgpVault(wrap, files, account)
        val pending = NativePgpVault(wrap, files, account, NativePgpVault.Slot.PENDING)
    }

    private fun world(): World {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val w = World(wrap, files, account)
        val key = MnemonicDerivation.deriveKey(mnemonic1)!!
        assertEquals(NativeWalletVault.Import.OK, w.wallet.importKey(account, key))
        key.fill(0)
        return w
    }

    private fun snapshot(files: NativeTestFiles): Map<String, String> =
        files.map.mapValues { (_, v) -> ConetChatCryptoUtil.toHex(v) }

    private fun pgpKeys(files: NativeTestFiles): Set<String> = files.map.keys.filter { it.startsWith("pgp.") }.toSet()

    /** Test-side encryption of a non-key text under the account's password string (for the "decrypts but is not a key" case). */
    private fun blobOf(passwordString: String, plain: ByteArray): String {
        val key = java.security.MessageDigest.getInstance("SHA-256").digest(passwordString.toByteArray(Charsets.UTF_8))
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return java.util.Base64.getEncoder().encodeToString(iv + c.doFinal(plain))
    }

    private fun passwordOfAccount1(): String {
        val key = MnemonicDerivation.deriveKey(mnemonic1)!!
        return try {
            NativePgpBackup.passwordString(key)
        } finally {
            key.fill(0)
        }
    }

    // ---------- restore: the three failure classes, and the rest of the refusals ----------

    @Test
    fun theBackupRestoresTheOriginalIdentityWhenTheFingerprintMatches() {
        val w = world()
        val r = NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1))
        assertEquals(NativePgpRecovery.Code.OK, r.code)
        assertEquals(fp1, r.fingerprint)
        val st = w.pgp.state()
        assertTrue("active: $st", st is NativePgpVault.State.Ready && st.fingerprint == fp1)
        assertEquals("ok", w.pgp.decryptInbound(test1.getString("armored")).code)
    }

    @Test
    fun missingBackupIsTheMissingClassAndNothingChanges() {
        val w = world()
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.BACKUP_MISSING, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(null, fp1)).code)
        assertEquals(before, snapshot(w.files))
        assertTrue(w.pgp.state() is NativePgpVault.State.NoKey)
    }

    @Test
    fun noRegisteredKeyIsAlsoTheMissingClass() {
        // The document maps "no registered key" into the missing class: there is no identity on chain to confirm against.
        val w = world()
        assertEquals(NativePgpRecovery.Code.BACKUP_MISSING, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, null)).code)
        assertTrue(pgpKeys(w.files).isEmpty())
    }

    @Test
    fun undecryptableBackupIsTheSecondClassAndNothingChanges() {
        val w = world()
        val before = snapshot(w.files)
        val tampered = backup1.substring(0, 20) + (if (backup1[20] == 'A') "B" else "A") + backup1.substring(21)
        assertEquals(NativePgpRecovery.Code.BACKUP_UNDECRYPTABLE, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(tampered, fp1)).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun aBackupThatDecryptsToNonKeyTextIsInvalidAndNothingChanges() {
        val w = world()
        val before = snapshot(w.files)
        val blob = blobOf(passwordOfAccount1(), "not an armored key".toByteArray(Charsets.UTF_8))
        assertEquals(NativePgpRecovery.Code.BACKUP_INVALID, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(blob, fp1)).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun aDecryptedKeyWithAnotherFingerprintIsTheThirdClassAndNothingChanges() {
        val w = world()
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.FINGERPRINT_MISMATCH, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp2)).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun anUnavailableSourceIsNeverMissingAndNothingChanges() {
        val w = world()
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.SOURCE_UNAVAILABLE, NativePgpRecovery.restore(w.wallet, w.pgp, Unavailable).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun aDifferentActiveKeyIsNotOverwrittenByARestore() {
        val w = world()
        // The account already holds P-2's key (a different identity).
        assertEquals(NativePgpVault.Put.OK, w.pgp.put(account, p2.getJSONObject("pgp").getString("privateArmor"), ""))
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.ALREADY_EXISTS, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1)).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun anActiveKeyMatchingTheChainIsOkEvenWithoutABackupOnChain() {
        val w = world()
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1)).code)
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(null, fp1)).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun anActiveKeyWithNoRegisteredIdentityOnChainIsNotConfirmed() {
        val w = world()
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1)).code)
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.BACKUP_MISSING, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, null)).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun restoringTheSameActiveKeyAgainIsIdempotent() {
        val w = world()
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1)).code)
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1)).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun theWalletRecordIsUnaffectedByRestoreRefusalsAndSuccess() {
        val w = world()
        val walletBefore = w.files.map[NativeWalletVault.REC]!!.copyOf()
        NativePgpRecovery.restore(w.wallet, w.pgp, Chain(null, fp1))
        NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp2))
        assertTrue(walletBefore.contentEquals(w.files.map[NativeWalletVault.REC]!!))
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1)).code)
        assertTrue(walletBefore.contentEquals(w.files.map[NativeWalletVault.REC]!!))
    }

    @Test
    fun aRestoredIdentitySurvivesAColdStart() {
        val w = world()
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1)).code)
        val fresh = NativePgpVault(w.wrap, w.files, account)
        assertTrue(fresh.state() is NativePgpVault.State.Ready)
        assertEquals("ok", fresh.decryptInbound(test1.getString("armored")).code)
    }

    @Test
    fun aCrashAfterTheRecordWriteLeavesNoKeyAndTheRetryCompletes() {
        val w = world()
        w.files.crashAfterWrite = NativePgpVault.recName(account)
        try {
            NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1))
            error("no crash")
        } catch (_: NativeTestCrash) {
        }
        w.files.crashAfterWrite = null
        assertEquals("unconfirmed record is not a key", "no_pgp_key", w.pgp.decryptInbound(test1.getString("armored")).code)
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1)).code)
        assertEquals("ok", w.pgp.decryptInbound(test1.getString("armored")).code)
    }

    @Test
    fun aFailedMarkerWriteRollsBackAndTheRetryCompletes() {
        val w = world()
        w.files.failWrite = NativePgpVault.markName(account)
        assertEquals(NativePgpRecovery.Code.WRITE_FAILED, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1)).code)
        assertTrue(w.pgp.state() is NativePgpVault.State.NoKey)
        w.files.failWrite = null
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.restore(w.wallet, w.pgp, Chain(backup1, fp1)).code)
    }

    @Test
    fun noWalletKeyMeansNoRestoreAndNoChange() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val wallet = NativeWalletVault(wrap, files)
        val pgp = NativePgpVault(wrap, files, account)
        assertEquals(NativePgpRecovery.Code.NO_KEY, NativePgpRecovery.restore(wallet, pgp, Chain(backup1, fp1)).code)
        assertTrue(files.map.isEmpty())
    }

    // ---------- generation: user-confirmed, only with no identity on chain ----------

    @Test
    fun generationNeedsTheUserConfirmation() {
        val w = world()
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.CANCELLED, NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, null), false).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun generationIsRefusedWhenTheChainHoldsAnIdentity() {
        val w = world()
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.IDENTITY_EXISTS, NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(backup1, fp1), true).code)
        assertEquals(NativePgpRecovery.Code.IDENTITY_EXISTS, NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, fp1), true).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun generationIsRefusedWhenTheSourceIsUnavailable() {
        val w = world()
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.SOURCE_UNAVAILABLE, NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Unavailable, true).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun generationIsRefusedWhenAnActiveRecordExists() {
        val w = world()
        assertEquals(NativePgpVault.Put.OK, w.pgp.put(account, p1.getJSONObject("pgp").getString("privateArmor"), ""))
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.ALREADY_EXISTS, NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, null), true).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun aConfirmedGenerationWritesOnlyThePendingSlotAndReturnsPublicMaterial() {
        val w = world()
        val activeBefore = snapshot(w.files)
        val r = NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, null), true, SecureRandom())
        assertEquals(NativePgpRecovery.Code.OK, r.code)
        assertNotNull(r.fingerprint)
        assertEquals(40, r.fingerprint!!.length)
        assertTrue(r.publicArmor!!.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        assertFalse("the returned material is public", r.publicArmor!!.contains("PRIVATE KEY"))
        assertTrue("pending: ${w.pending.state()}", w.pending.state() is NativePgpVault.State.Ready)
        assertTrue("active untouched", w.pgp.state() is NativePgpVault.State.NoKey)
        assertTrue(activeBefore.keys.all { it in snapshot(w.files).keys })
        assertEquals(setOf(NativePgpVault.recName(account, NativePgpVault.Slot.PENDING), NativePgpVault.markName(account, NativePgpVault.Slot.PENDING)), pgpKeys(w.files))
    }

    @Test
    fun aSecondConfirmedGenerationReturnsTheSamePendingKey() {
        val w = world()
        val first = NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, null), true)
        val second = NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, null), true)
        assertEquals(first.fingerprint, second.fingerprint)
        assertEquals(first.publicArmor, second.publicArmor)
    }

    @Test
    fun aGeneratedKeyHasTheCurve25519Shape() {
        val g = NativePgpKeyGen.generate("beamio-chat-v1", SecureRandom())
        val ring = NativePgp.parseSecret(g.privateArmor)!!.ring
        val keys = ring.secretKeys.asSequence().toList()
        assertEquals(2, keys.size)
        assertEquals(PublicKeyAlgorithmTags.EDDSA_LEGACY, keys[0].publicKey.algorithm)
        assertEquals(PublicKeyAlgorithmTags.ECDH, keys[1].publicKey.algorithm)
    }

    // ---------- registration guard: no overwrite of an identity on chain ----------

    @Test
    fun theRegistrationGuardRefusesAnyOverwrite() {
        val w = world()
        val gen = NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, null), true)
        val pendingFp = gen.fingerprint!!
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.registrationGuard(Chain(null, null), account, pendingFp))
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.registrationGuard(Chain(null, pendingFp), account, pendingFp))
        assertEquals(NativePgpRecovery.Code.OVERWRITE_REFUSED, NativePgpRecovery.registrationGuard(Chain(null, fp1), account, pendingFp))
        assertEquals(NativePgpRecovery.Code.OVERWRITE_REFUSED, NativePgpRecovery.registrationGuard(Chain(backup1, null), account, pendingFp))
        assertEquals(NativePgpRecovery.Code.SOURCE_UNAVAILABLE, NativePgpRecovery.registrationGuard(Unavailable, account, pendingFp))
    }

    // ---------- activation after a confirmed registration ----------

    @Test
    fun aConfirmedRegistrationActivatesThePendingKey() {
        val w = world()
        val pendingFp = NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, null), true).fingerprint!!
        val r = NativePgpRecovery.activate(w.wallet, w.pgp, w.pending, pendingFp)
        assertEquals(NativePgpRecovery.Code.OK, r.code)
        val st = w.pgp.state()
        assertTrue("active: $st", st is NativePgpVault.State.Ready && st.fingerprint.equals(pendingFp, ignoreCase = true))
        assertTrue("pending is gone", w.pending.state() is NativePgpVault.State.NoKey)
    }

    @Test
    fun activationRefusesAFingerprintThatIsNotThePendingOne() {
        val w = world()
        NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, null), true)
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.FINGERPRINT_MISMATCH, NativePgpRecovery.activate(w.wallet, w.pgp, w.pending, fp1).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun activationWithoutAPendingKeyDoesNothing() {
        val w = world()
        assertEquals(NativePgpRecovery.Code.NO_PENDING, NativePgpRecovery.activate(w.wallet, w.pgp, w.pending, fp1).code)
        assertTrue(pgpKeys(w.files).isEmpty())
    }

    @Test
    fun activationNeverReplacesAnActiveKeyOfAnotherIdentity() {
        val w = world()
        val pendingFp = NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, null), true).fingerprint!!
        assertEquals(NativePgpVault.Put.OK, w.pgp.put(account, p1.getJSONObject("pgp").getString("privateArmor"), ""))
        val before = snapshot(w.files)
        assertEquals(NativePgpRecovery.Code.ALREADY_EXISTS, NativePgpRecovery.activate(w.wallet, w.pgp, w.pending, pendingFp).code)
        assertEquals(before, snapshot(w.files))
    }

    @Test
    fun aGeneratedAndActivatedKeyDecryptsAndSigns() {
        val w = world()
        val pendingFp = NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, null), true).fingerprint!!
        val pub = NativePgpRecovery.generate(w.wallet, w.pgp, w.pending, Chain(null, null), true).publicArmor!!
        assertEquals(NativePgpRecovery.Code.OK, NativePgpRecovery.activate(w.wallet, w.pgp, w.pending, pendingFp).code)
        val msg = "generated key message"
        val cipher = encryptTo(pub, msg)
        val out = w.pgp.decryptInbound(cipher)
        assertEquals("ok", out.code)
        assertEquals(msg, out.value)
        val signed = w.pgp.sign("syntheticvector", NativePgp.SIG_BINARY_DOCUMENT, msg.toByteArray(Charsets.UTF_8), setOf("syntheticvector"))
        assertEquals("ok", signed.code)
        assertTrue(w.pgp.verifySignature("syntheticvector", msg.toByteArray(Charsets.UTF_8), signed.value!!))
    }

    // ---------- per-account records ----------

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
