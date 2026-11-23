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
import network.conet.chat.nativekey.RecoveryBackupConfirmation
import network.conet.chat.nativekey.VaultSnapshotRefresh
import network.conet.chat.nativekey.WalletAddress
import network.conet.chat.nativekey.pageRecordFiles
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Continuation of an interrupted identity clear (2026-11-22, aligned). The interruption is between the deletion of the phrase and the
 * deletion of the wallet W: the account is key-only (a readable key record, no phrase), clear_pending is set, and the backup of the held wallet was
 * confirmed before the clear started. clearIdentity completes the redo: the identity_cleared markers are written, clear_pending is cleared, and the
 * published stores keep their bytes. Synthetic values only; digests are logged, never values.
 */
@RunWith(AndroidJUnit4::class)
class IdentityClearResumeInterruptedTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val key = requireNotNull(MnemonicDerivation.deriveKey(phrase))
    private val account = requireNotNull(WalletAddress.fromPrivateKey(key)).lowercase()

    private fun prefsFile(name: String) = File(context.applicationInfo.dataDir, "shared_prefs/$name.xml")
    private fun inboxFile() = File(context.noBackupFilesDir, "conet_chat_inbox_v1.json")
    private fun sha(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** The interrupted state: published stores, a key-only record (no phrase, no mnemonic set), the backup confirmed, clear_pending set. */
    private fun seedInterrupted() {
        assertTrue(BeamioChatPgpStore.upsertFromWeb(context, JSONObject()
            .put("publicKeyArmor", "SYNTHETIC-PGP-PUBLIC-ARMOR").put("eoa", account).put("pgpKeyId", "SYNTHETIC-KEYID-0003")
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
        BeamioConetChatInboxStore.put(context, "cd".repeat(32), "-----BEGIN PGP MESSAGE-----\nSYNTHETIC-INBOX-BODY-2\n-----END PGP MESSAGE-----", "entry.synthetic.test")
        // The wallet W only: the phrase has been deleted by the first step of the interrupted clear.
        val imported = NativeWallet.vault(context).importKey(account, key.copyOf())
        assertTrue("the synthetic key-only record is present: $imported",
            imported == NativeWalletVault.Import.OK || imported == NativeWalletVault.Import.ALREADY_PRESENT)
        // The backup of the held wallet was confirmed before the clear started (PY.10), so the (1b) check of the continuation passes.
        assertTrue("the recovery backup of the account is confirmed", RecoveryBackupConfirmation.confirmRecoveryBackup(context, account))
        // The interrupted clear: its marker was set before the wallet deletion, and the pointer is erased last.
        assertTrue("the interrupted clear marker is set", ClearFlagFiles(pageRecordFiles(context)).setClearPending(account))
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

    /** Digests of the published stores only (the vault key record is unpublished and is removed by the clear). */
    private fun publishedDigests(): Map<String, String> {
        val files = listOf(prefsFile("beamio_chat_pgp_v1"), prefsFile("beamio_chat_pgp_plain_v1"), prefsFile("beamio_chat_wallet_v1"), inboxFile())
        return files.associate { f -> assertTrue("store file exists: ${f.name}", f.isFile); f.name to sha(f.readBytes()) }
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
        assertTrue("the resumed identity clear answers", answered.await(90, TimeUnit.SECONDS))
        return acks.single()
    }

    @Test
    fun anInterruptedClearAfterThePhraseDeletionResumesAndCompletes() {
        seedInterrupted()
        awaitSnapshot()
        val before = publishedDigests()
        before.forEach { (name, d) -> Log.i("ClearResume", "before $name=$d") }

        val ack = clearAnswer(9301)
        Log.i("ClearResume", "resumed clear ok=${ack.optBoolean("ok")} error=${ack.optString("error")} reason=${ack.optString("reason")}")
        assertTrue("the interrupted clear completes: $ack", ack.optBoolean("ok"))
        assertEquals("the kept published items are reported by count: wallet copy, PGP store, inbox", 3, ack.optJSONObject("result")?.optInt("keptPublished") ?: -1)

        val flags = ClearFlagFiles(pageRecordFiles(context))
        assertTrue("the identity_cleared marker is written by the continuation", flags.identityCleared())
        assertFalse("clear_pending is cleared after the markers", flags.clearPendingState() == true)

        val after = publishedDigests()
        after.forEach { (name, d) -> Log.i("ClearResume", "after $name=$d equal=${before[name] == d}") }
        assertEquals("the published stores keep their bytes through the continuation", before, after)
    }
}
