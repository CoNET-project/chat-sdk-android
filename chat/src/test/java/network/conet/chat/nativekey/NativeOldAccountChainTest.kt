package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The synthetic old-account migration chain, on the JVM (the same steps as `NativeOldAccountChainDeviceTest`, which runs on
 * a device with the Keystore):
 *   native import → address and PGP identity match → read back → sign and decrypt → cold start → interrupted, then retried.
 * Synthetic material only: the public test mnemonic of P-1 and the P-1 backup from `pgp-backup-compat-vectors.v1.json`.
 */
class NativeOldAccountChainTest {
    private val vectors = JSONObject(
        String(File(System.getenv("PGP_BACKUP_VECTORS") ?: "../spec/pgp-backup-compat-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val p1 = vectors.getJSONArray("positives").getJSONObject(0)
    private val eoa = p1.getString("eoa")
    private val fingerprint = p1.getJSONObject("expect").getString("primaryFingerprint")
    private val backup = p1.getJSONObject("backup").getString("base64")
    private val test = p1.getJSONObject("testMessage")
    private val mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val signPurpose = "syntheticvector"

    @Test
    fun theChainRunsEndToEndAndSurvivesARestartAndAnInterruptedRetry() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val wallet = NativeWalletVault(wrap, files)
        val pgp = NativePgpVault(wrap, files, eoa.lowercase())

        // 1. Native import from the mnemonic; the derived address must be the account's address.
        val imported = NativeImport.submitMnemonic(mnemonic, eoa, wallet)
        assertEquals("import", NativeImport.Code.OK, imported.code)
        assertEquals(eoa.lowercase(), imported.eoa!!.lowercase())

        // 2. Read back: the vault holds the account, and its key gives the PWA's password string.
        assertEquals(eoa.lowercase(), (wallet.state() as NativeWalletVault.State.Ready).eoa.lowercase())
        assertTrue("PGP not yet restored", pgp.state() is NativePgpVault.State.NoKey)

        // 3. Restore the PGP key from the backup; the identity must be the expected primary fingerprint.
        val restored = NativePgpBackup.restore(wallet, pgp, backup, fingerprint)
        assertEquals("restore", NativePgpBackup.Code.OK, restored.code)
        assertEquals(fingerprint.lowercase(), restored.fingerprint)

        // 4. Read back the PGP record.
        val state = pgp.state()
        assertTrue("PGP record read back: $state", state is NativePgpVault.State.Ready)
        assertEquals(fingerprint.lowercase(), (state as NativePgpVault.State.Ready).fingerprint)

        // 5. Sign (the purpose registry is empty by design, so the test passes its own synthetic purpose) and decrypt.
        val message = "chain message".toByteArray(Charsets.UTF_8)
        val signed = pgp.sign(signPurpose, NativePgp.SIG_BINARY_DOCUMENT, message, setOf(signPurpose))
        assertEquals("sign", "ok", signed.code)
        assertTrue(pgp.verifySignature(signPurpose, message, signed.value!!))
        val decrypted = pgp.decryptInbound(test.getString("armored"))
        assertEquals("decrypt", "ok", decrypted.code)
        assertEquals(test.getString("plaintext"), decrypted.value)

        // 6. Cold start: new vault objects on the same records and the same wrapping key.
        val wallet2 = NativeWalletVault(wrap, files)
        val pgp2 = NativePgpVault(wrap, files, eoa.lowercase())
        assertTrue("wallet after restart", wallet2.state() is NativeWalletVault.State.Ready)
        assertTrue("PGP after restart", pgp2.state() is NativePgpVault.State.Ready)
        assertEquals("decrypt after restart", "ok", pgp2.decryptInbound(test.getString("armored")).code)

        // 7. Refusals leave the record as it is: a different expected identity, and a tampered backup.
        assertEquals(NativePgpBackup.Code.IDENTITY_MISMATCH, NativePgpBackup.restore(wallet2, pgp2, backup, "0".repeat(40)).code)
        val tampered = backup.substring(0, 20) + (if (backup[20] == 'A') "B" else "A") + backup.substring(21)
        assertEquals(NativePgpBackup.Code.DECRYPT_FAILED, NativePgpBackup.restore(wallet2, pgp2, tampered, fingerprint).code)
        assertEquals("record unchanged", fingerprint.lowercase(), (pgp2.state() as NativePgpVault.State.Ready).fingerprint)

        // 8. Interrupted, then retried: the process dies after the record is written and before the marker (a crash, not an
        // ordinary error, so the vault does not roll back). A record without its marker is not confirmed: the next state read
        // removes it, so the account has no PGP key until the restore is run again.
        pgp2.forget()
        files.crashAfterWrite = NativePgpVault.recName(eoa.lowercase())
        try {
            NativePgpBackup.restore(wallet2, pgp2, backup, fingerprint)
            error("the simulated crash did not happen")
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        assertTrue("the half-written record is on disk", files.map.containsKey(NativePgpVault.recName(eoa.lowercase())))
        assertEquals("unconfirmed record is not a key", "no_pgp_key", pgp2.decryptInbound(test.getString("armored")).code)
        assertFalse("and it is removed", files.map.containsKey(NativePgpVault.recName(eoa.lowercase())))

        // 9. Retry: the same restore completes, and the key works.
        val retry = NativePgpBackup.restore(wallet2, pgp2, backup, fingerprint)
        assertEquals("retry", NativePgpBackup.Code.OK, retry.code)
        assertEquals("decrypt after retry", "ok", pgp2.decryptInbound(test.getString("armored")).code)
    }

    @Test
    fun aFailedWriteRollsBackAndTheRetryWorks() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val wallet = NativeWalletVault(wrap, files)
        val pgp = NativePgpVault(wrap, files, eoa.lowercase())
        assertEquals(NativeImport.Code.OK, NativeImport.submitMnemonic(mnemonic, eoa, wallet).code)

        files.failWrite = NativePgpVault.markName(eoa.lowercase())
        assertEquals(NativePgpBackup.Code.WRITE_FAILED, NativePgpBackup.restore(wallet, pgp, backup, fingerprint).code)
        assertTrue("nothing is left behind", pgp.state() is NativePgpVault.State.NoKey)

        files.failWrite = null
        assertEquals(NativePgpBackup.Code.OK, NativePgpBackup.restore(wallet, pgp, backup, fingerprint).code)
        assertEquals("ok", pgp.decryptInbound(test.getString("armored")).code)
    }
}
