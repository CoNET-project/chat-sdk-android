package network.conet.chat

import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.platform.app.InstrumentationRegistry
import network.conet.chat.nativekey.LegacyStoreReport
import network.conet.chat.nativekey.NativeWallet
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Evidence source (2026-11-20). The SAME file is used for the pre-fix and the post-fix build, so only the production code differs.
 * Fresh install with the legacy report absent; cases: noarmor (no legacy PGP armor), orphan (an armor fixture with no wallet, unchanged
 * afterwards). Diagnostics (tag EvidenceNoKey): adoption and snapshot state around the adoption calls, then each walletStatus answer.
 */
class FreshInstallNoKeyEvidenceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun walletStatus(reqId: String): JSONObject? {
        val answers = CopyOnWriteArrayList<JSONObject>()
        val emit: (JSONObject) -> Unit = { payload ->
            payload.optJSONObject("event")?.let { ev ->
                if (ev.optString("type") == "ack" && ev.optString("reqId") == reqId) answers += ev
            }
        }
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "walletStatus").put("reqId", reqId), emit)
        val deadline = System.currentTimeMillis() + 15_000L
        while (answers.isEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(20)
        return answers.firstOrNull()
    }

    private fun legacyPgpPrefs() = EncryptedSharedPreferences.create(
        context,
        "beamio_chat_pgp_v1",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    private fun digest(s: String): String =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }.take(16)

    private fun runToNoKey(label: String) {
        val t0 = System.currentTimeMillis()
        val report = LegacyStoreReport.reportLegacyStore(context, LegacyStoreReport.ABSENT)
        Log.i("EvidenceNoKey", "$label T0 ms=$t0 reportLegacyStore value=absent code=$report")
        assertEquals("ok", report)
        val vault = NativeWallet.vault(context)
        val s0 = vault.snapshotWithKeyOnly() != null
        val walletAdopted = NativeWallet.migrateLegacy(context)
        val s1 = vault.snapshotWithKeyOnly() != null
        val pgpAdopted = NativeWallet.migrateLegacyPgp(context)
        val s2 = vault.snapshotWithKeyOnly() != null
        Log.i("EvidenceNoKey", "$label adopt.wallet=$walletAdopted settled=${NativeWallet.isLegacyWalletAdoptionSettled()} snapshot.before=$s0 after.wallet=$s1")
        Log.i("EvidenceNoKey", "$label adopt.pgp=$pgpAdopted snapshot.after.pgp=$s2")
        var status = ""
        var notReady = 0
        var firstNotReadyAt = -1L
        var lastNotReadyAt = -1L
        var firstNoKeyAt = -1L
        var i = 0
        val deadline = t0 + 20_000L
        while (System.currentTimeMillis() < deadline) {
            val ack = walletStatus("evid-${i++}") ?: continue
            val now = System.currentTimeMillis() - t0
            val result = ack.getJSONObject("result")
            status = result.getString("status")
            Log.i("EvidenceNoKey", "$label answer n=$i at=$now status=$status reason=${result.optString("notReadyReason", "-")}")
            if (status == NOT_READY) {
                notReady++
                if (firstNotReadyAt < 0) firstNotReadyAt = now
                lastNotReadyAt = now
            }
            if (status == NO_KEY) {
                firstNoKeyAt = now
                break
            }
            Thread.sleep(20)
        }
        val span = if (firstNotReadyAt >= 0) lastNotReadyAt - firstNotReadyAt else 0L
        Log.i("EvidenceNoKey", "$label FIRST_NO_KEY at=$firstNoKeyAt NOT_READY count=$notReady span=$span")
        assertEquals(NO_KEY, status)
    }

    @Test
    fun freshInstallWithoutArmorAnswersNoKey() {
        runToNoKey("noarmor")
    }

    @Test
    fun freshInstallWithOrphanArmorAnswersNoKey() {
        legacyPgpPrefs().edit().putString(KEY_PRIVATE, FIXTURE).commit()
        val before = digest(FIXTURE)
        runToNoKey("orphan")
        val after = legacyPgpPrefs().getString(KEY_PRIVATE, "").orEmpty()
        Log.i("EvidenceNoKey", "orphan armor.sha=$before after.sha=${digest(after)} unchanged=${after == FIXTURE}")
        assertEquals("the armor stays exactly as it was", FIXTURE, after)
    }

    private companion object {
        const val NO_KEY = "no_key"
        const val NOT_READY = "not_ready"
        const val KEY_PRIVATE = "userPgpPrivateArmor"
        // A test fixture for the orphan-armor case: not a key, not used anywhere else.
        const val FIXTURE = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nFIXTURE-NOT-A-KEY\n-----END PGP PRIVATE KEY BLOCK-----"
    }
}
