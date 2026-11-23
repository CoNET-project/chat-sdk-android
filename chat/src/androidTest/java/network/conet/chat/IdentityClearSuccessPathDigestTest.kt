package network.conet.chat

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import network.conet.chat.nativekey.BeamioShellRecordImport
import network.conet.chat.nativekey.ClearFlagFiles
import network.conet.chat.nativekey.LegacyWalletRecord
import network.conet.chat.nativekey.MnemonicDerivation
import network.conet.chat.nativekey.MnemonicSetStore
import network.conet.chat.nativekey.NativeSource
import network.conet.chat.nativekey.ShellImportCode
import network.conet.chat.nativekey.pageRecordFiles
import network.conet.chat.nativekey.NativeSessionState
import network.conet.chat.nativekey.NativeWallet
import network.conet.chat.nativekey.NativeWalletVault
import network.conet.chat.nativekey.RecoveryBackupConfirmation
import network.conet.chat.nativekey.VaultSnapshotRefresh
import network.conet.chat.nativekey.WalletAddress
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
 * SUCCESS-PATH test (2026-11-22). The fixture makes the identity clear pass the unregister check
 * (no migration records, no native PGP record, the backup of the held wallet confirmed) so that the deletion steps really run. Then:
 *  - the published stores keep their bytes: beamio_chat_pgp_v1.xml (every PGP key, including the legacy private armor), beamio_chat_pgp_plain_v1.xml,
 *    beamio_chat_wallet_v1.xml (the shipped wallet store) and conet_chat_inbox_v1.json (the inbox);
 *  - the unpublished vault entries (REC, MNEM, MARK, COMMIT) are removed by design (the control).
 * Synthetic values only; digests are logged, never values. Runs on a task-dedicated emulator only (S25 is never a target).
 */
@RunWith(AndroidJUnit4::class)
class IdentityClearSuccessPathDigestTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val key = requireNotNull(MnemonicDerivation.deriveKey(phrase))
    private val account = requireNotNull(WalletAddress.fromPrivateKey(key)).lowercase()

    private fun prefsFile(name: String) = File(context.applicationInfo.dataDir, "shared_prefs/$name.xml")
    private fun inboxFile() = File(context.noBackupFilesDir, "conet_chat_inbox_v1.json")
    private fun sha(f: File): String = MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

    private fun seed() {
        assertTrue("seed the PGP public fields", BeamioChatPgpStore.upsertFromWeb(context, JSONObject()
            .put("publicKeyArmor", "SYNTHETIC-PGP-PUBLIC-ARMOR").put("eoa", account).put("pgpKeyId", "SYNTHETIC-KEYID-0001")
            .put("routePublicKeyArmor", "SYNTHETIC-ROUTE-ARMOR").put("entryDomains", JSONArray().put("entry.synthetic.test"))))
        val enc = EncryptedSharedPreferences.create(
            context, "beamio_chat_pgp_v1",
            MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
        assertTrue("seed the legacy private armor", enc.edit().putString("userPgpPrivateArmor", "SYNTHETIC-LEGACY-PRIVATE-ARMOR").commit())
        assertTrue(context.getSharedPreferences("beamio_chat_pgp_plain_v1", Context.MODE_PRIVATE).edit()
            .putString("recipientEoa", account).commit())
        assertTrue(context.getSharedPreferences("beamio_chat_wallet_v1", Context.MODE_PRIVATE).edit()
            .putString("eoa", account).putString("iv", "SYNTHETIC-IV").putString("ct", "SYNTHETIC-CT").commit())
        BeamioConetChatInboxStore.put(context, "ab".repeat(32), "-----BEGIN PGP MESSAGE-----\nSYNTHETIC-INBOX-BODY\n-----END PGP MESSAGE-----", "entry.synthetic.test")
        val imported = NativeWallet.vault(context).importMnemonicKey(account, key.copyOf(), phrase)
        assertTrue("the synthetic vault record with its phrase is present: $imported",
            imported == NativeWalletVault.Import.OK || imported == NativeWalletVault.Import.ALREADY_PRESENT)
        NativeSessionState.markReady(account)
        // A retained mnemonic set in the store: kept by the clear, not re-adopted automatically.
        assertTrue("seed the retained mnemonic set", MnemonicSetStore(File(context.noBackupFilesDir, MnemonicSetStore.DIRECTORY)).writePlain(account, phrase) is MnemonicSetStore.Write.Stored)
        // The backup of the held wallet is confirmed (PY.10): the unregister check passes for a held W.
        assertTrue("the recovery backup of the account is confirmed", RecoveryBackupConfirmation.confirmRecoveryBackup(context, account))
    }

    private fun awaitSnapshot() {
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

    /** The unpublished vault entries present before the clear (the control): REC, MNEM, MARK, COMMIT. */
    private fun vaultEntries(): Map<String, Boolean> {
        val files = NativeWallet.migrationFiles(context)
        return listOf(NativeWalletVault.REC, NativeWalletVault.MNEM, NativeWalletVault.MARK, NativeWalletVault.COMMIT)
            .associateWith { files.read(it) != null }
    }

    @Test
    fun aPassingIdentityClearDeletesOnlyTheUnpublishedFormatsAndKeepsThePublishedStores() {
        seed()
        awaitSnapshot()
        val retained = retainedBytes(MnemonicSetStore(File(context.noBackupFilesDir, MnemonicSetStore.DIRECTORY)))
        val entriesBefore = vaultEntries()
        assertTrue("the control: the vault entries exist before the clear: $entriesBefore", entriesBefore.values.any { it })
        val before = digests()
        before.forEach { (name, d) -> Log.i("ClearSuccess", "before $name=$d") }

        val reqId = 9101
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
        Log.i("ClearSuccess", "identityClear ok=${ack.optBoolean("ok")} error=${ack.optString("error")}")
        // the completion judges only the items the clear removes; the kept published stores do not block it.
        assertTrue("the identity clear completes: $ack", ack.optBoolean("ok"))
        assertEquals("the kept published items are reported by count: wallet copy, PGP store, inbox", 3, ack.optJSONObject("result")?.optInt("keptPublished") ?: -1)
        // Item 3: the identity_cleared marker is set (no secret), and the kept wallet copy is not adopted automatically.
        assertTrue("the identity_cleared marker is set", ClearFlagFiles(pageRecordFiles(context)).identityCleared())
        val adopted = BeamioShellRecordImport.runFirstImport(context, account, LegacyWalletRecord.Found("{}".toByteArray()), null)
        assertEquals("the kept wallet copy is not adopted after the clear", ShellImportCode.ABSENT, adopted)
        assertEquals("no page copy is created from the kept wallet copy", null, BeamioShellRecordImport.storeFor(context, account).read())

        val after = digests()
        after.forEach { (name, d) -> Log.i("ClearSuccess", "after $name=$d equal=${before[name] == d}") }
        assertEquals("the published stores are unchanged: PGP store (all keys), shipped wallet store, inbox", before, after)

        val entriesAfter = vaultEntries()
        entriesAfter.forEach { (name, present) -> Log.i("ClearSuccess", "control vault $name present_after=$present") }
        assertFalse("the control: the unpublished vault entries are removed by design", entriesAfter.values.any { it })

        // after the clear the retained set is not re-adopted and no pointer is written.
        val store = MnemonicSetStore(File(context.noBackupFilesDir, MnemonicSetStore.DIRECTORY))
        assertTrue("the store answers absent after the identity clear", store.current() is MnemonicSetStore.Current.Absent)
        assertTrue("no account is adopted from the store or the vault",
            NativeSource.accountOf(NativeSource.decide(NativeWallet.vault(context).state(), store.current(), null)) == null)
        assertEquals("the retained set file and the pointer keep their bytes", retained, retainedBytes(store))

        // Interrupted clear: clear_pending set again, the redo runs (retained entries are not counted as held).
        assertTrue("the interrupted clear marker is set", ClearFlagFiles(pageRecordFiles(context)).setClearPending(account))
        val redoAcks = CopyOnWriteArrayList<JSONObject>()
        val redone = CountDownLatch(1)
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "clearIdentity").put("reqId", reqId + 1)) { payload ->
            val event = payload.optJSONObject("event") ?: payload
            if (event.optString("type") == "ack" && event.opt("reqId")?.toString() == (reqId + 1).toString()) {
                redoAcks += event
                redone.countDown()
            }
        }
        assertTrue("the redo answers", redone.await(90, TimeUnit.SECONDS))
        assertTrue("the interrupted clear is redone and completes: ${redoAcks.single()}", redoAcks.single().optBoolean("ok"))

        // Explicit restore or import of the same account releases the identity_cleared state; the set answers again.
        val reimport = store.writePlain(account, phrase)
        assertTrue("the explicit write of the set: $reimport", reimport is MnemonicSetStore.Write.Stored)
        assertTrue("the explicit write releases the marker", !store.identityCleared())
        assertTrue("the set answers again after the explicit restore", store.current() is MnemonicSetStore.Current.Found)
        Log.i("ClearSuccess", "readopt after explicit write: ok")

        val finalDigests = digests()
        assertEquals("the published stores are unchanged across the clear and the redo", before, finalDigests)
    }

    private fun retainedBytes(store: MnemonicSetStore): Map<String, String> {
        val dir = File(context.noBackupFilesDir, MnemonicSetStore.DIRECTORY)
        return listOf("current.v1").plus(dir.list()?.filter { it.startsWith("set.") }?.sorted() ?: emptyList())
            .filter { File(dir, it).isFile }.associateWith { sha(File(dir, it)) }
    }
}
