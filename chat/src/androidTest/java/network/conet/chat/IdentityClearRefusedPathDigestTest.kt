package network.conet.chat

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import network.conet.chat.nativekey.MnemonicDerivation
import network.conet.chat.nativekey.NativeSessionState
import network.conet.chat.nativekey.NativeWallet
import network.conet.chat.nativekey.NativeWalletVault
import network.conet.chat.nativekey.VaultSnapshotRefresh
import network.conet.chat.nativekey.WalletAddress
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
 * REFUSED-PATH test only. The identity clear is refused at the unregister check (`unregister_refused`), so no
 * deletion step runs. This test proves only that the published PGP store (every key, including the legacy private armor), the shipped wallet
 * store and the inbox file keep their bytes when the clear is refused. It does NOT cover the deletion path: B4 (clearKeepingLegacy removed)
 * and B6 (the inbox is not removed) after a passing unregister are not exercised by any instrumented test yet.
 * Synthetic values only; digests are logged, never values. Runs on a task-dedicated emulator only (S25 is never a target).
 */
@RunWith(AndroidJUnit4::class)
class IdentityClearRefusedPathDigestTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    // A synthetic recovery phrase (no wallet): the account carries a phrase, so the identity clear runs in G2 and not as key-only.
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val key = requireNotNull(MnemonicDerivation.deriveKey(phrase))
    private val account = requireNotNull(WalletAddress.fromPrivateKey(key)).lowercase()

    private fun prefsFile(name: String) = File(context.applicationInfo.dataDir, "shared_prefs/$name.xml")
    private fun inboxFile() = File(context.noBackupFilesDir, "conet_chat_inbox_v1.json")
    private fun sha(f: File): String = MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

    private fun seed() {
        // Published PGP store (BeamioChatPgpStore, prefs beamio_chat_pgp_v1): the public, route, entries, node and mailbox fields.
        assertTrue("seed the PGP public fields", BeamioChatPgpStore.upsertFromWeb(context, JSONObject()
            .put("publicKeyArmor", "SYNTHETIC-PGP-PUBLIC-ARMOR").put("eoa", account).put("pgpKeyId", "SYNTHETIC-KEYID-0001")
            .put("routePublicKeyArmor", "SYNTHETIC-ROUTE-ARMOR").put("entryDomains", JSONArray().put("entry.synthetic.test"))))
        // The legacy private armor (KEY_PRIVATE) is read-only history; seed it through the same encrypted preferences the store reads.
        val enc = EncryptedSharedPreferences.create(
            context, "beamio_chat_pgp_v1",
            MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        assertTrue("seed the legacy private armor", enc.edit().putString("userPgpPrivateArmor", "SYNTHETIC-LEGACY-PRIVATE-ARMOR").commit())
        // Plain PGP preferences (beamio_chat_pgp_plain_v1) carry the same secrets on a device without the encrypted store.
        assertTrue(context.getSharedPreferences("beamio_chat_pgp_plain_v1", Context.MODE_PRIVATE).edit()
            .putString("recipientEoa", account).commit())
        // Shipped wallet store (BeamioChatWalletKeyStore.PREFS = beamio_chat_wallet_v1).
        assertTrue(context.getSharedPreferences("beamio_chat_wallet_v1", Context.MODE_PRIVATE).edit()
            .putString("eoa", account).putString("iv", "SYNTHETIC-IV").putString("ct", "SYNTHETIC-CT").commit())
        // Inbox (conet_chat_inbox_v1.json), one synthetic entry through the store's own write path.
        // The store accepts only an armor shaped as a PGP message; the body is synthetic (no key, no content).
        BeamioConetChatInboxStore.put(context, "ab".repeat(32), "-----BEGIN PGP MESSAGE-----\nSYNTHETIC-INBOX-BODY\n-----END PGP MESSAGE-----", "entry.synthetic.test")
        // The current vault account (a synthetic test record) and the session ready for it: the identity clear runs in G2.
        // A previous run on the same emulator may have stored the same synthetic record: OK or ALREADY_PRESENT both leave it in place.
        val imported = NativeWallet.vault(context).importMnemonicKey(account, key.copyOf(), phrase)
        assertTrue("the synthetic vault record with its phrase is present: $imported",
            imported == NativeWalletVault.Import.OK || imported == NativeWalletVault.Import.ALREADY_PRESENT)
        NativeSessionState.markReady(account)
    }

    private fun awaitSnapshot() {
        // The snapshot is filled by the refresh job (the same one the identity clear schedules); trigger it, and retry while it is pending.
        val deadline = System.currentTimeMillis() + 60_000
        var nextKick = 0L
        while (NativeWallet.vault(context).snapshotState() == null) {
            assertTrue("the vault snapshot is known before the clear", System.currentTimeMillis() < deadline)
            if (System.currentTimeMillis() >= nextKick) {
                VaultSnapshotRefresh.schedule(context)
                nextKick = System.currentTimeMillis() + 5_000
            }
            Thread.sleep(200)
        }
    }

    private fun digests(): Map<String, String> {
        val names = listOf(prefsFile("beamio_chat_pgp_v1"), prefsFile("beamio_chat_pgp_plain_v1"), prefsFile("beamio_chat_wallet_v1"), inboxFile())
        return names.associate { f ->
            assertTrue("the store file exists: ${f.name}", f.isFile)
            f.name to sha(f)
        }
    }

    @Test
    fun anIdentityClearLeavesThePublishedStoresAndTheInboxByteForByteUnchanged() {
        seed()
        awaitSnapshot()
        val before = digests()
        before.forEach { (name, d) -> Log.i("ClearDigest", "before $name=$d") }

        val reqId = 9001
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
        val ack = acks.single()
        Log.i("ClearDigest", "identityClear ok=${ack.optBoolean("ok")} error=${ack.optString("error")}")
        // The refused path is the expected answer: the unregister check refuses the clear, so nothing is removed. Any other answer means the
        // fixture does not reach the refused path, and this test would prove nothing.
        assertEquals("the clear is refused at the unregister check (the refused path only)", false, ack.optBoolean("ok"))
        assertEquals("the refusal code is unregister_refused", "unregister_refused", ack.optString("error"))
        // The account holds a phrase and its backup is not confirmed: the reason is backup_unconfirmed (PROTOCOL-unregister-refused-reason-field).
        assertEquals("the reason is backup_unconfirmed", "backup_unconfirmed", ack.optString("reason"))

        val after = digests()
        after.forEach { (name, d) -> Log.i("ClearDigest", "after $name=$d equal=${before[name] == d}") }
        assertEquals("on the refused path the PGP store, the shipped wallet store and the inbox file are unchanged", before, after)
    }
}
