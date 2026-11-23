package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The synthetic old-account migration chain on the JVM, through [PgpRestoreMachine] (the same steps as the device fixture
 * `PgpRestoreAcceptanceDeviceTest`, which runs on a device with the Keystore):
 *   native import → address match → read back → restore from the on-chain backup → sign and decrypt → cold start →
 *   refusals leave the record → interrupted write, then retry; and a failed local write, then retry.
 * Synthetic material only: the public test mnemonic of P-1 and the P-1 backup from `pgp-backup-compat-vectors.v1.json`.
 */
class NativeOldAccountChainTest {
    private val vectors = JSONObject(
        String(File(System.getenv("PGP_BACKUP_VECTORS") ?: "../spec/pgp-backup-compat-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val p1 = vectors.getJSONArray("positives").getJSONObject(0)
    private val eoa = p1.getString("eoa")
    private val account = eoa.lowercase()
    private val expect = p1.getJSONObject("expect")
    private val fingerprint = expect.getString("primaryFingerprint").uppercase()
    private val subkeyKeyId = expect.getString("subkeyKeyID")
    private val backup = p1.getJSONObject("backup").getString("base64")
    private val test = p1.getJSONObject("testMessage")
    private val mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val signPurpose = "syntheticvector"

    private fun onChain(): PgpIdentity = PgpIdentity(fingerprint, subkeyKeyId)

    @Test
    fun theChainRunsEndToEndAndSurvivesARestartAndAnInterruptedRetry() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val wallet = NativeWalletVault(wrap, files)
        val chain = StaticChain(onChain(), backup)
        val m = restoreMachineForOneDevice(chain, wallet, wrap, files, account)
        val dev = m.devices.getValue("A")

        // 1. Native import from the mnemonic; the derived address must be the account's address.
        val imported = NativeImport.importRecoveryPhrase(mnemonic, eoa, wallet)
        assertEquals("import", NativeImport.Code.OK, imported.code)
        assertEquals(account, imported.eoa!!.lowercase())

        // 2. Read back: the wallet holds the account, and no PGP key is restored yet.
        assertEquals(account, (wallet.state() as NativeWalletVault.State.Ready).eoa.lowercase())
        assertTrue("PGP not yet restored", dev.active.state() is NativePgpVault.State.NoKey)

        // 3. Restore from the on-chain backup: the identity matches the chain, and the armor is written and read back.
        assertEquals("restore", "ok", m.restore("A").result)
        val state = dev.active.state()
        assertTrue("PGP record read back: $state", state is NativePgpVault.State.Ready)
        assertEquals(fingerprint.lowercase(), (state as NativePgpVault.State.Ready).fingerprint)

        // 4. Sign (the purpose registry is empty by design, so the test passes its own synthetic purpose) and decrypt.
        val message = "chain message".toByteArray(Charsets.UTF_8)
        val signed = dev.active.sign(signPurpose, NativePgp.SIG_BINARY_DOCUMENT, message, setOf(signPurpose))
        assertEquals("sign", "ok", signed.code)
        assertTrue(dev.active.verifySignature(signPurpose, message, signed.value!!))
        val decrypted = dev.active.decryptInbound(test.getString("armored"))
        assertEquals("decrypt", "ok", decrypted.code)
        assertEquals(test.getString("plaintext"), decrypted.value)

        // 5. Cold start: new vault objects on the same records and the same wrapping key.
        val wallet2 = NativeWalletVault(wrap, files)
        val pgp2 = NativePgpVault(wrap, files, account)
        assertTrue("wallet after restart", wallet2.state() is NativeWalletVault.State.Ready)
        assertTrue("PGP after restart", pgp2.state() is NativePgpVault.State.Ready)
        assertEquals("decrypt after restart", "ok", pgp2.decryptInbound(test.getString("armored")).code)

        // 6. Refusals leave the record as it is: a different on-chain identity, then a tampered on-chain backup.
        chain.storedIdentity = PgpIdentity("0".repeat(40), subkeyKeyId)
        assertEquals("identity mismatch", "failed:fingerprint_mismatch", m.restore("A").result)
        chain.storedIdentity = onChain()
        val tampered = backup.substring(0, 20) + (if (backup[20] == 'A') "B" else "A") + backup.substring(21)
        chain.storedBackup = tampered
        assertEquals("tampered backup", "failed:decrypt_failed", m.restore("A").result)
        chain.storedBackup = backup
        assertEquals(
            "record unchanged",
            fingerprint.lowercase(),
            (dev.active.state() as NativePgpVault.State.Ready).fingerprint,
        )

        // 7. Interrupted, then retried: the process dies after the record is written and before the marker (a crash, not an
        // ordinary error, so the vault does not roll back). A record without its marker is not confirmed: the next state read
        // removes it, so the account has no PGP key until the restore runs again.
        dev.active.forget()
        files.crashAfterWrite = NativePgpVault.recName(account)
        try {
            m.restore("A")
            error("the simulated crash did not happen")
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        assertTrue("the half-written record is on disk", files.map.containsKey(NativePgpVault.recName(account)))
        // Rewritten 2026-11-16 (a read never deletes user data). The unconfirmed record stays and reads as an unknown state
        // (pgp_locked, retry), not as no key: a read must not remove what a write left. The retry below is the write path that completes it.
        assertEquals("unconfirmed record is unknown, not a key", "pgp_locked", dev.active.decryptInbound(test.getString("armored")).code)
        assertTrue("and it is kept", files.map.containsKey(NativePgpVault.recName(account)))

        // 8. Retry (rewritten 2026-11-16, : keep the user's data): the locked record is an unknown state, so the automatic restore does
        // not overwrite it. The retry answers pgp_locked and leaves the record as it is; a user-initiated recovery is the way out (Y.83).
        val before = files.map[NativePgpVault.recName(account)]!!.copyOf()
        assertEquals("retry is refused, not overwritten", "undetermined", m.restore("A").result)
        assertEquals("the record is unchanged", true, before.contentEquals(files.map[NativePgpVault.recName(account)]!!))
        assertEquals("decrypt still locked", "pgp_locked", dev.active.decryptInbound(test.getString("armored")).code)
    }

    @Test
    fun aFailedLocalWriteLeavesNothingBehindAndTheRetryWorks() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val wallet = NativeWalletVault(wrap, files)
        val m = restoreMachineForOneDevice(StaticChain(onChain(), backup), wallet, wrap, files, account)
        val dev = m.devices.getValue("A")
        assertEquals(NativeImport.Code.OK, NativeImport.importRecoveryPhrase(mnemonic, eoa, wallet).code)

        files.failWrite = NativePgpVault.markName(account)
        assertEquals("a failed local write is undetermined, not ok", "undetermined", m.restore("A").result)
        assertTrue("nothing is left behind", dev.active.state() is NativePgpVault.State.NoKey)

        files.failWrite = null
        assertEquals("retry", "ok", m.restore("A").result)
        assertEquals("decrypt after retry", "ok", dev.active.decryptInbound(test.getString("armored")).code)
    }
}
