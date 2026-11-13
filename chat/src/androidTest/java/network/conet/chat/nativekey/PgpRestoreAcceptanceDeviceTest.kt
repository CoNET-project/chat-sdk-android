package network.conet.chat.nativekey

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Device fixture for P-IMP-PGP option A (spec r3l §25.30.8), synthetic material only:
 *   1. the 34 acceptance cases of `pgp-restore-acceptance-vectors.v1.json`, each step result and the final state, run against
 *      [PgpRestoreMachine] with the real Keystore ([AndroidKeyWrap]) and the app's files under this test package's own files
 *      directory (the instrumentation target, not any app's data);
 *   2. the old-account chain on the Keystore: native import, restore from the backup, decrypt, cold start.
 * Each case starts with no record and leaves none. Nothing goes to the network.
 *
 * The Keystore is the real `AndroidKeyWrap`. "Cold start" builds new vault objects over the same files and a new wrap object
 * for the same Keystore alias; a real process kill is a device-run step for the operator and is not done by this test.
 *
 * Build and run (the operator picks the device; this file does not choose one):
 *   ./gradlew :chat:assembleDebugAndroidTest --offline
 *   adb -s <serial> install -r chat/build/outputs/apk/androidTest/debug/chat-debug-androidTest.apk
 *   adb -s <serial> shell am instrument -w -e class network.conet.chat.nativekey.PgpRestoreAcceptanceDeviceTest network.conet.chat.test/androidx.test.runner.AndroidJUnitRunner
 */
@RunWith(AndroidJUnit4::class)
class PgpRestoreAcceptanceDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val assets = InstrumentationRegistry.getInstrumentation().context.assets

    private val doc: JSONObject by lazy {
        JSONObject(assets.open("pgp-restore-acceptance-vectors.v1.json").bufferedReader(Charsets.UTF_8).use { it.readText() })
    }
    private val compat: JSONObject by lazy {
        JSONObject(assets.open("pgp-backup-compat-vectors.v1.json").bufferedReader(Charsets.UTF_8).use { it.readText() })
    }
    private val p1: JSONObject by lazy { compat.getJSONArray("positives").getJSONObject(0) }
    private val password: String by lazy { p1.getString("passwordString") }
    private val mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    /** All device files of this fixture live under here. */
    private val root: File get() = File(context.filesDir, "pgp_restore_acceptance")

    @Before
    fun startWithoutAnyRecord() {
        root.deleteRecursively()
    }

    @After
    fun leaveNoRecord() {
        root.deleteRecursively()
    }

    @Test
    fun theThirtyFourAcceptanceCasesMatchTheVectorsOnTheKeystore() {
        val cases = doc.getJSONArray("cases")
        val failures = mutableListOf<String>()
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            File(root, id).deleteRecursively()
            val h = PgpRestoreHarness(doc, password, { AndroidKeyWrap() }, { dev -> AndroidVaultFiles(File(root, "$id/$dev")) })
            val (steps, final) = h.run(c.getJSONObject("input").getJSONArray("steps"))
            val expected = c.getJSONObject("expect")
            val expSteps = expected.getJSONArray("stepResults")
            if (expSteps.length() != steps.length()) {
                failures += "$id: step count ${steps.length()} != ${expSteps.length()}"
            } else {
                for (j in 0 until expSteps.length()) {
                    if (!PgpRestoreHarness.jsonEq(expSteps.getJSONObject(j), steps.getJSONObject(j))) {
                        failures += "$id step $j: expected ${expSteps.getJSONObject(j)} got ${steps.getJSONObject(j)}"
                    }
                }
            }
            if (!PgpRestoreHarness.jsonEq(expected.getJSONObject("final"), final)) {
                failures += "$id final: expected ${expected.getJSONObject("final")} got $final"
            }
            File(root, id).deleteRecursively()
        }
        assertTrue("device acceptance mismatches:\n" + failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun theOldAccountChainRunsOnTheKeystoreAndSurvivesAColdStart() {
        val eoa = p1.getString("eoa")
        val account = eoa.lowercase()
        val expect = p1.getJSONObject("expect")
        val dir = File(root, "old_account_chain")
        val files = AndroidVaultFiles(dir)
        val wrap = AndroidKeyWrap()
        val wallet = NativeWalletVault(wrap, files)

        // 1. Native import from the mnemonic; the derived address must be the account's address.
        val imported = NativeImport.submitMnemonic(mnemonic, eoa, wallet)
        assertEquals("import", NativeImport.Code.OK, imported.code)
        assertEquals(account, imported.eoa!!.lowercase())

        // 2. Restore from the on-chain backup (the fixed chain of the vector: P-1's identity and backup).
        val chain = StaticChain(
            PgpIdentity(expect.getString("primaryFingerprint").uppercase(), expect.getString("subkeyKeyID")),
            p1.getJSONObject("backup").getString("base64"),
        )
        val m = restoreMachineForOneDevice(chain, wallet, wrap, files, account)
        assertEquals("restore", "ok", m.restore("A").result)

        // 3. The key works.
        val test = p1.getJSONObject("testMessage")
        assertEquals("decrypt", "ok", m.devices.getValue("A").active.decryptInbound(test.getString("armored")).code)

        // 4. Cold start: new vault objects over the same files and a new wrap object for the same Keystore alias.
        val pgp2 = NativePgpVault(AndroidKeyWrap(), AndroidVaultFiles(dir), account)
        assertTrue("PGP after restart", pgp2.state() is NativePgpVault.State.Ready)
        assertEquals("decrypt after restart", "ok", pgp2.decryptInbound(test.getString("armored")).code)
    }

    /** Two accounts on one device keep separate PGP records on the Keystore and never overwrite each other (§42). */
    @Test
    fun theRecordsOfTwoAccountsStayApartOnTheKeystore() {
        val account1 = p1.getString("eoa").lowercase()
        val account2 = compat.getJSONArray("positives").getJSONObject(1).getString("eoa").lowercase()
        val key1 = p1.getJSONObject("pgp").getString("privateArmor")
        val key2 = compat.getJSONArray("positives").getJSONObject(1).getJSONObject("pgp").getString("privateArmor")
        val files = AndroidVaultFiles(File(root, "two_accounts"))
        val a = NativePgpVault(AndroidKeyWrap(), files, account1)
        val b = NativePgpVault(AndroidKeyWrap(), files, account2)
        assertEquals(NativePgpVault.Put.OK, a.put(account1, key1, ""))
        assertEquals(NativePgpVault.Put.OK, b.put(account2, key2, ""))
        assertEquals(NativePgpVault.Put.BAD_EOA, a.put(account2, key2, ""))
        b.forget()
        assertTrue("A survives B's removal", NativePgpVault(AndroidKeyWrap(), files, account1).state() is NativePgpVault.State.Ready)
        assertTrue("B is gone", NativePgpVault(AndroidKeyWrap(), files, account2).state() is NativePgpVault.State.NoKey)
    }
}
