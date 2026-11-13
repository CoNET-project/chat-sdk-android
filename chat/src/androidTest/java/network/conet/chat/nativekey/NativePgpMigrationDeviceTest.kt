package network.conet.chat.nativekey

import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import network.conet.chat.BeamioChatPgpStore
import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Device fixture for the legacy PGP migration, positive path (spec 25.22.2; R7 independent review item 2b).
 *
 * Only synthetic material from `spec/` is used, read from the test assets: the spec's test wallet key (SHA-256 of
 * "chat-local-test-private-key-v1", account 0x39581c72…, `gossip-sign-vectors.v1.json`) and the `ecc-nopass` PGP vector
 * key (`pgp-native-vectors.v1.json`, no passphrase). Nothing here is a real wallet and nothing goes to the network. The
 * PWA is not involved: the pre-upgrade store is written by this file (see `seedLegacyPgp`), the way the old save wrote it,
 * so the production store has no test-only write path. The test does not log key material.
 *
 * Build and run (the operator picks the device; this file does not choose one):
 *   ./gradlew :chat:assembleDebugAndroidTest --offline
 *   adb -s <serial> install -r chat/build/outputs/apk/androidTest/debug/chat-debug-androidTest.apk
 *   adb -s <serial> shell am instrument -w -e class network.conet.chat.nativekey.NativePgpMigrationDeviceTest network.conet.chat.test/androidx.test.runner.AndroidJUnitRunner
 */
@RunWith(AndroidJUnit4::class)
class NativePgpMigrationDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val assets = InstrumentationRegistry.getInstrumentation().context.assets

    private fun vector(name: String): JSONObject =
        JSONObject(assets.open(name).bufferedReader(Charsets.UTF_8).use { it.readText() })

    private companion object {
        // Mirrors BeamioChatPgpStore's private constants. Keep in step with that file.
        const val LEGACY_PREFS = "beamio_chat_pgp_v1"
        const val LEGACY_KEY_PRIVATE = "userPgpPrivateArmor"
        const val LEGACY_KEY_EOA = "recipientEoa"
    }

    private val wallet by lazy { vector("gossip-sign-vectors.v1.json") }
    private val pgp by lazy { vector("pgp-native-vectors.v1.json") }
    private val nopassKey by lazy { pgp.getJSONObject("keys").getJSONObject("ecc-nopass") }

    private fun decryptCase(id: String): JSONObject {
        val cases = pgp.getJSONArray("decrypt")
        return (0 until cases.length()).map { cases.getJSONObject(it) }.first { it.getString("id") == id }
    }

    @Before
    fun startWithoutAnyRecord() = removeEverything()

    @After
    fun leaveNoRecord() = removeEverything()

    private fun removeEverything() {
        NativeWallet.pgp(context).forget()
        NativeWallet.vault(context).forget()
        BeamioChatPgpStore.clearLegacyPrivateArmor(context)
        BeamioChatPgpStore.clear(context)
    }

    /**
     * Writes the pre-upgrade store the way the old save did: the same encrypted preferences file, the same key names
     * (`BeamioChatPgpStore`: PREFS, KEY_PRIVATE, KEY_EOA) and the same schemes. Test-side only.
     */
    private fun seedLegacyPgp(privateArmor: String, eoa: String) {
        val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        val prefs = EncryptedSharedPreferences.create(
            context,
            LEGACY_PREFS,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        assertTrue("legacy seed", prefs.edit().putString(LEGACY_KEY_PRIVATE, privateArmor).putString(LEGACY_KEY_EOA, eoa).commit())
    }

    /** Creates the native wallet record from the synthetic key. Returns its account. */
    private fun createSyntheticWalletRecord(): String {
        val eoa = wallet.getString("eoa")
        val key = ConetChatCryptoUtil.hexToBytes(wallet.getString("privateKeyHex"))!!
        assertEquals(NativeWalletVault.Import.OK, NativeWallet.vault(context).importKey(eoa, key))
        return eoa
    }

    /** Positive path: the same account's legacy key is adopted by the vault, the old copy is removed, and the key works. */
    @Test
    fun aLegacyPgpKeyOfTheSameAccountMovesIntoTheVaultAndTheOldCopyIsCleared() {
        val eoa = createSyntheticWalletRecord()
        seedLegacyPgp(nopassKey.getString("privateArmored"), eoa)
        assertTrue(BeamioChatPgpStore.legacyPrivateArmor(context).contains("BEGIN PGP PRIVATE KEY"))
        assertTrue("before: no PGP record", NativeWallet.pgp(context).state() is NativePgpVault.State.NoKey)

        assertTrue("migration must adopt the key", NativeWallet.migrateLegacyPgp(context))

        val state = NativeWallet.pgp(context).state()
        assertTrue("after: vault holds the key, state=$state", state is NativePgpVault.State.Ready)
        val fingerprint = (state as NativePgpVault.State.Ready).fingerprint
        assertTrue("fingerprint", fingerprint.equals(nopassKey.getString("fingerprint"), ignoreCase = true))
        assertEquals("the old copy is removed", "", BeamioChatPgpStore.legacyPrivateArmor(context))

        // The migrated key decrypts a message made for it (vector D-2, no passphrase).
        val d2 = decryptCase("D-2")
        val out = NativeWallet.pgp(context).decryptInbound(d2.getString("armor"))
        assertEquals("decrypt code", "ok", out.code)
        assertEquals("decrypt text", d2.getJSONObject("expect").getString("text"), out.value)

        // Nothing is left to move: a second call changes nothing.
        assertFalse(NativeWallet.migrateLegacyPgp(context))
    }

    /** Account check (spec 25.22.2): a legacy key recorded for another account is not moved, and the old copy stays. */
    @Test
    fun aLegacyPgpKeyOfAnotherAccountIsNotMovedAndTheOldCopyStays() {
        createSyntheticWalletRecord()
        val otherAccount = "0x2222222222222222222222222222222222222222"
        seedLegacyPgp(nopassKey.getString("privateArmored"), otherAccount)

        assertFalse(NativeWallet.migrateLegacyPgp(context))

        assertTrue("no PGP record", NativeWallet.pgp(context).state() is NativePgpVault.State.NoKey)
        assertTrue("old copy kept", BeamioChatPgpStore.legacyPrivateArmor(context).contains("BEGIN PGP PRIVATE KEY"))
    }
}
