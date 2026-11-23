package network.conet.chat

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import network.conet.chat.nativekey.ClearFlagFiles
import network.conet.chat.nativekey.MnemonicDerivation
import network.conet.chat.nativekey.NativeSessionState
import network.conet.chat.nativekey.NativeWallet
import network.conet.chat.nativekey.NativeWalletVault
import network.conet.chat.nativekey.VaultSnapshotRefresh
import network.conet.chat.nativekey.WalletAddress
import network.conet.chat.nativekey.pageRecordFiles
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * PY.14 4(c) (owner 2026-11-15, follow-up): a key-only account (a readable key record, no phrase) is refused for
 * the identity clear with unregister_refused and reason key_only when clear_pending is not set. Continuation (2026-11-22, aligned): with
 * clear_pending set, the precheck is skipped and the command reaches the redo path; here the backup of the held wallet is not confirmed, so the
 * existing check (1b) refuses with backup_unconfirmed and nothing is removed. Nothing is removed, shown or exported on any refusal: the published
 * stores and the vault key record keep their bytes. Synthetic values only; digests are logged, never values.
 */
@RunWith(AndroidJUnit4::class)
class IdentityClearKeyOnlyRefusalTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val key = requireNotNull(MnemonicDerivation.deriveKey(phrase))
    private val account = requireNotNull(WalletAddress.fromPrivateKey(key)).lowercase()

    private fun prefsFile(name: String) = File(context.applicationInfo.dataDir, "shared_prefs/$name.xml")
    private fun inboxFile() = File(context.noBackupFilesDir, "conet_chat_inbox_v1.json")
    private fun sha(f: File): String = MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

    private fun seed() {
        assertTrue(BeamioChatPgpStore.upsertFromWeb(context, JSONObject()
            .put("publicKeyArmor", "SYNTHETIC-PGP-PUBLIC-ARMOR").put("eoa", account).put("pgpKeyId", "SYNTHETIC-KEYID-0002")
            .put("routePublicKeyArmor", "SYNTHETIC-ROUTE-ARMOR").put("entryDomains", JSONArray().put("entry.synthetic.test"))))
        val enc = EncryptedSharedPreferences.create(
            context, "beamio_chat_pgp_v1",
            MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        assertTrue(enc.edit().putString("userPgpPrivateArmor", "SYNTHETIC-LEGACY-PRIVATE-ARMOR").commit())
        assertTrue(context.getSharedPreferences("beamio_chat_pgp_plain_v1", Context.MODE_PRIVATE).edit().putString("recipientEoa", account).commit())
        assertTrue(context.getSharedPreferences("beamio_chat_wallet_v1", Context.MODE_PRIVATE).edit()
            .putString("eoa", account).putString("iv", "SYNTHETIC-IV").putString("ct", "SYNTHETIC-CT").commit())
        BeamioConetChatInboxStore.put(context, "ab".repeat(32), "-----BEGIN PGP MESSAGE-----\nSYNTHETIC-INBOX-BODY\n-----END PGP MESSAGE-----", "entry.synthetic.test")
        // The key record only: a readable key with no phrase (key-only).
        val imported = NativeWallet.vault(context).importKey(account, key.copyOf())
        assertTrue("the synthetic key-only record is present: $imported",
            imported == NativeWalletVault.Import.OK || imported == NativeWalletVault.Import.ALREADY_PRESENT)
        NativeSessionState.markReady(account)
    }

    private fun awaitSnapshot() {
        val deadline = System.currentTimeMillis() + 60_000
        var nextKick = 0L
        while (NativeWallet.vault(context).snapshotState() == null) {
            assertTrue("the vault snapshot is known", System.currentTimeMillis() < deadline)
            if (System.currentTimeMillis() >= nextKick) {
                VaultSnapshotRefresh.schedule(context)
                nextKick = System.currentTimeMillis() + 5_000
            }
            Thread.sleep(200)
        }
    }

    private fun digests(): Map<String, String> {
        val files = listOf(prefsFile("beamio_chat_pgp_v1"), prefsFile("beamio_chat_pgp_plain_v1"), prefsFile("beamio_chat_wallet_v1"), inboxFile())
        val out = files.associate { f -> assertTrue("store file exists: ${f.name}", f.isFile); f.name to sha(f) }.toMutableMap()
        val rec = NativeWallet.migrationFiles(context).read(NativeWalletVault.REC)
        assertTrue("the key record exists", rec != null)
        out["vault.rec"] = MessageDigest.getInstance("SHA-256").digest(rec!!).joinToString("") { "%02x".format(it) }
        return out
    }

    private fun clearAnswer(reqId: Int): JSONObject {
        val acks = CopyOnWriteArrayList<JSONObject>()
        val answered = CountDownLatch(1)
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "clearIdentity").put("reqId", reqId)) { payload ->
            val event = payload.optJSONObject("event") ?: payload
            if (event.optString("type") == "ack" && event.opt("reqId")?.toString() == reqId.toString()) {
                acks += event
                answered.countDown()
            }
        }
        assertTrue("the identity clear answers", answered.await(90, TimeUnit.SECONDS))
        return acks.single()
    }

    @Test
    fun aKeyOnlyAccountIsRefusedWithReasonKeyOnlyWithOrWithoutClearPendingAndNothingChanges() {
        seed()
        awaitSnapshot()
        val before = digests()
        before.forEach { (name, d) -> Log.i("ClearKeyOnly", "before $name=$d") }

        val first = clearAnswer(9201)
        Log.i("ClearKeyOnly", "key-only clear (no clear_pending) ok=${first.optBoolean("ok")} error=${first.optString("error")} reason=${first.optString("reason")}")
        assertEquals("unregister_refused without clear_pending", "unregister_refused", first.optString("error"))
        assertEquals("the reason is key_only", "key_only", first.optString("reason"))
        assertEquals(false, first.optBoolean("ok"))

        // With clear_pending set the key-only precheck no longer applies: the command reaches the redo path. This fixture has no confirmed backup
        // of the held wallet, so the clear() check (1b) refuses (backup_unconfirmed), and that refusal writes nothing.
        assertTrue("set clear_pending", ClearFlagFiles(pageRecordFiles(context)).setClearPending(account))
        val second = clearAnswer(9202)
        Log.i("ClearKeyOnly", "key-only clear (clear_pending) ok=${second.optBoolean("ok")} error=${second.optString("error")} reason=${second.optString("reason")}")
        assertEquals("unregister_refused on the redo path", "unregister_refused", second.optString("error"))
        assertEquals("the redo path refuses on the unconfirmed backup, not on key_only", "backup_unconfirmed", second.optString("reason"))

        val after = digests()
        after.forEach { (name, d) -> Log.i("ClearKeyOnly", "after $name=$d equal=${before[name] == d}") }
        assertEquals("nothing is removed or changed: stores, inbox and the key record", before, after)
    }
}
