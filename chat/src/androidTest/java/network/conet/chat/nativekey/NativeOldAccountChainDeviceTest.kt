package network.conet.chat.nativekey

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Device fixture for the synthetic old-account chain (P-IMP-PGP option A; `pgp-backup-compat-vectors.v1.json`, P-1):
 *   native import → address and PGP identity match → read back → sign and decrypt → cold start → interrupted, then retried.
 *
 * Synthetic material only, from the spec's test assets: the public BIP-39 test mnemonic of P-1 (account
 * 0x9858effd…) and the P-1 backup blob. Nothing is a real wallet and nothing goes to the network. The data lives in this
 * test package's own files directory (the instrumentation target), not in any app's data.
 *
 * The Keystore is the real `AndroidKeyWrap`. "Cold start" builds new vault objects over the same files and a new wrap
 * object for the same Keystore alias; a real process kill is a device-run step for the operator (`adb shell am force-stop`
 * between two runs) and is not done by this test.
 *
 * Build and run (the operator picks the device; this file does not choose one):
 *   ./gradlew :chat:assembleDebugAndroidTest --offline
 *   adb -s <serial> install -r chat/build/outputs/apk/androidTest/debug/chat-debug-androidTest.apk
 *   adb -s <serial> shell am instrument -w -e class network.conet.chat.nativekey.NativeOldAccountChainDeviceTest network.conet.chat.test/androidx.test.runner.AndroidJUnitRunner
 */
@RunWith(AndroidJUnit4::class)
class NativeOldAccountChainDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val assets = InstrumentationRegistry.getInstrumentation().context.assets

    private val vectors: JSONObject by lazy {
        JSONObject(assets.open("pgp-backup-compat-vectors.v1.json").bufferedReader(Charsets.UTF_8).use { it.readText() })
    }
    private val p1: JSONObject by lazy { vectors.getJSONArray("positives").getJSONObject(0) }
    private val eoa: String by lazy { p1.getString("eoa") }
    private val fingerprint: String by lazy { p1.getJSONObject("expect").getString("primaryFingerprint") }
    private val backup: String by lazy { p1.getJSONObject("backup").getString("base64") }
    private val testMessage: JSONObject by lazy { p1.getJSONObject("testMessage") }
    private val mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    /** The same directory the app's `NativeWallet` uses, under this test package's files directory. */
    private val dir: File get() = File(context.filesDir, "native_wallet_v1")

    /** A VaultFiles wrapper that throws a crash-like Error once, right after a write to [crashAfter] (no rollback). */
    private class CrashAfterWrite(private val inner: VaultFiles, private val crashAfter: String) : VaultFiles {
        var armed = true
        override fun read(name: String): ByteArray? = inner.read(name)
        override fun write(name: String, bytes: ByteArray) {
            inner.write(name, bytes)
            if (armed && name == crashAfter) {
                armed = false
                throw SimulatedCrash()
            }
        }
        override fun delete(name: String) = inner.delete(name)
    }

    private class SimulatedCrash : Error("simulated crash after the record write")

    private fun vaults(files: VaultFiles = AndroidVaultFiles(dir)): Pair<NativeWalletVault, NativePgpVault> {
        val wrap = AndroidKeyWrap()
        return NativeWalletVault(wrap, files) to NativePgpVault(wrap, files, eoa.lowercase())
    }

    @Before
    fun startWithoutAnyRecord() = wipe()

    @After
    fun leaveNoRecord() = wipe()

    private fun wipe() {
        val (wallet, pgp) = vaults()
        pgp.forget()
        wallet.forget()
    }

    @Test
    fun theOldAccountChainRunsOnTheKeystoreAndSurvivesAColdStartAndARetry() {
        val (wallet, pgp) = vaults()

        // 1. Native import from the mnemonic. The derived address must be the account's address.
        val imported = NativeImport.submitMnemonic(mnemonic, eoa, wallet)
        assertEquals("import", NativeImport.Code.OK, imported.code)
        assertEquals(eoa.lowercase(), imported.eoa!!.lowercase())

        // 2. Read back.
        assertEquals(eoa.lowercase(), (wallet.state() as NativeWalletVault.State.Ready).eoa.lowercase())
        assertTrue("PGP not yet restored", pgp.state() is NativePgpVault.State.NoKey)

        // 3. Restore the PGP key from the backup. The identity must be the expected primary fingerprint.
        val restored = NativePgpBackup.restore(wallet, pgp, backup, fingerprint)
        assertEquals("restore", NativePgpBackup.Code.OK, restored.code)
        assertEquals(fingerprint.lowercase(), restored.fingerprint)

        // 4. Read back the PGP record.
        val state = pgp.state()
        assertTrue("PGP record read back: $state", state is NativePgpVault.State.Ready)
        assertEquals(fingerprint.lowercase(), (state as NativePgpVault.State.Ready).fingerprint)

        // 5. Sign with the test's own synthetic purpose (the production registry is empty) and decrypt the test message.
        val purpose = "syntheticvector"
        val message = "device chain message".toByteArray(Charsets.UTF_8)
        val signed = pgp.sign(purpose, NativePgp.SIG_BINARY_DOCUMENT, message, setOf(purpose))
        assertEquals("sign", "ok", signed.code)
        assertTrue(pgp.verifySignature(purpose, message, signed.value!!))
        val decrypted = pgp.decryptInbound(testMessage.getString("armored"))
        assertEquals("decrypt", "ok", decrypted.code)
        assertEquals(testMessage.getString("plaintext"), decrypted.value)

        // 6. Cold start: new objects over the same files, a new wrap object for the same Keystore alias.
        val (wallet2, pgp2) = vaults()
        assertTrue("wallet after restart", wallet2.state() is NativeWalletVault.State.Ready)
        assertTrue("PGP after restart", pgp2.state() is NativePgpVault.State.Ready)
        assertEquals("decrypt after restart", "ok", pgp2.decryptInbound(testMessage.getString("armored")).code)

        // 7. Refusals leave the record as it is: a different expected identity, and a tampered backup.
        assertEquals(NativePgpBackup.Code.IDENTITY_MISMATCH, NativePgpBackup.restore(wallet2, pgp2, backup, "0".repeat(40)).code)
        val tampered = backup.substring(0, 20) + (if (backup[20] == 'A') "B" else "A") + backup.substring(21)
        assertEquals(NativePgpBackup.Code.DECRYPT_FAILED, NativePgpBackup.restore(wallet2, pgp2, tampered, fingerprint).code)
        assertEquals(fingerprint.lowercase(), (pgp2.state() as NativePgpVault.State.Ready).fingerprint)

        // 8. Interrupted, then retried: the process dies after the record is written and before the marker.
        pgp2.forget()
        val crashing = CrashAfterWrite(AndroidVaultFiles(dir), NativePgpVault.recName(eoa.lowercase()))
        val (wallet3, pgp3) = vaults(crashing)
        try {
            NativePgpBackup.restore(wallet3, pgp3, backup, fingerprint)
            error("the simulated crash did not happen")
        } catch (_: SimulatedCrash) {
        }
        // Without its marker the record is not confirmed: the next state read removes it, and the account has no key.
        assertEquals("unconfirmed record is not a key", "no_pgp_key", pgp2.decryptInbound(testMessage.getString("armored")).code)

        // 9. Retry: the same restore completes, and the key works after another cold start.
        val (wallet4, pgp4) = vaults()
        assertEquals("retry", NativePgpBackup.Code.OK, NativePgpBackup.restore(wallet4, pgp4, backup, fingerprint).code)
        val (wallet5, pgp5) = vaults()
        assertFalse("wallet still present", wallet5.state() is NativeWalletVault.State.NoKey)
        assertEquals("decrypt after retry and restart", "ok", pgp5.decryptInbound(testMessage.getString("armored")).code)
    }
}
