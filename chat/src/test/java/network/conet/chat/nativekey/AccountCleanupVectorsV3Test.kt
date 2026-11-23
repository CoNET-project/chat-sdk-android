package network.conet.chat.nativekey

import network.conet.chat.ChatHistoryFileNames
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.MessageDigest

/**
 * `accountCleanupOld` driven from VECTOR-accountCleanupOld-v3-2026-11-21.json (v196 §216, copied to spec/accountCleanupOld-vectors.v3.json by v197 §217).
 * The copy is pinned by its SHA-256; the test does not read anything outside the repository. Each case is run through the run the bridge uses, and the answer is the real ack
 * envelope from [accountCleanupAck].
 */
class AccountCleanupVectorsV3Test {
    @get:Rule
    val tmp = TemporaryFolder()

    private val pinned = "20c00809bc0a5952896fb2bce57ab15c76295c6ff71edf590c6e31da850b2df9"
    private val newEoa = "0x1111111111111111111111111111111111111111"
    private val oldEoa = "0x2222222222222222222222222222222222222222"
    private val newKey = "$newEoa:default"

    /** The byte copy in the repository (spec/), pinned by [pinned]. No path outside the repository. */
    private fun vectorBytes(): ByteArray = File("../spec/accountCleanupOld-vectors.v3.json").readBytes()

    private fun sha256(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun cases(): Map<String, JSONObject> {
        val doc = JSONObject(String(vectorBytes(), Charsets.UTF_8))
        val arr = doc.getJSONArray("cases")
        return (0 until arr.length()).map { arr.getJSONObject(it) }.associateBy { it.getString("id") }
    }

    /** A removal that does not take effect for the marked item (BR3-06: the deletion item cannot be read or removed). */
    private class FailingOnce(private val inner: CleanupAdapter) : CleanupAdapter {
        override fun scan(newAccountKey: String): AccountCleanupOld.Scan = inner.scan(newAccountKey)
        override fun remove(item: AccountCleanupOld.Item): Boolean = false
    }

    private fun history(): File {
        val h = tmp.newFolder("conet-chat")
        File(h, ChatHistoryFileNames.localName(newEoa)).writeText("new-local")
        File(h, ChatHistoryFileNames.localName(oldEoa)).writeText("old-local")
        return h
    }

    private fun runAck(gateNotReady: Boolean, failRemoval: Boolean, confirmed: Boolean, h: File): JSONObject {
        val state = AndroidVaultFiles(tmp.newFolder("state"))
        val confirmation = CleanupConfirmation(state)
        if (confirmed) AutoConfirmation.onPageConfirm(confirmation, newEoa, newEoa, newEoa, 1L)
        val adapter: CleanupAdapter = HistoryDirCleanup(h) { listOf(oldEoa) }.let { if (failRemoval) FailingOnce(it) else it }
        val out = AccountCleanupRun(CleanupJournal(state), confirmation, listOf(adapter)).run(
            payloadFields = listOf("accountKey", "idempotencyKey"),
            accountKey = newEoa,
            idempotencyKey = "idem-v3",
            gateNotReady = gateNotReady,
            newAccountKey = newKey,
            newAccountReadable = true,
            readBack = ReadBackCheck.Verdict.PASS,
        )
        return accountCleanupAck("req-v3", out)
    }

    @Test
    fun theVectorFileIsThePinnedCopy() {
        assertEquals(pinned, sha256(vectorBytes()))
    }

    /** BR3-05: gate locked or not ready: not_ready, cleanupPending false, nothing removed. */
    @Test
    fun br305GateNotReady() {
        val expect = cases().getValue("BR3-05-gate-not_ready").getJSONObject("expect")
        val h = history()
        val before = h.listFiles().orEmpty().associate { it.name to it.readText() }
        val ack = runAck(gateNotReady = true, failRemoval = false, confirmed = true, h = h)
        assertEquals(expect.getString("type"), ack.getString("type"))
        assertEquals(expect.getBoolean("ok"), ack.getBoolean("ok"))
        assertEquals(expect.getString("error"), ack.getString("error"))
        assertEquals(false, ack.getJSONObject("result").getBoolean("cleanupPending"))
        assertEquals(0, ack.getJSONObject("result").getInt("keptUnattributed"))
        assertEquals(before, h.listFiles().orEmpty().associate { it.name to it.readText() })
    }

    /** BR3-06: gate passed, a deletion item cannot be removed: clear_incomplete, cleanupPending true. */
    @Test
    fun br306ItemFailureIsClearIncomplete() {
        val expect = cases().getValue("BR3-06-item-clear_incomplete").getJSONObject("expect")
        val ack = runAck(gateNotReady = false, failRemoval = true, confirmed = true, h = history())
        assertEquals(expect.getBoolean("ok"), ack.getBoolean("ok"))
        assertEquals(expect.getString("error"), ack.getString("error"))
        assertTrue(ack.getJSONObject("result").getBoolean("cleanupPending"))
        assertTrue(ack.getJSONObject("result").has("keptUnattributed"))
    }

    /** BR3-07: gate passed, read-back matches, deletion complete: ok true, no error field, cleanupPending false. */
    @Test
    fun br307SuccessIsOkWithNoError() {
        val expect = cases().getValue("BR3-07-success").getJSONObject("expect")
        val ack = runAck(gateNotReady = false, failRemoval = false, confirmed = true, h = history())
        assertEquals(expect.getBoolean("ok"), ack.getBoolean("ok"))
        assertFalse("ok true has no error field", ack.has("error"))
        assertFalse(ack.getJSONObject("result").getBoolean("cleanupPending"))
        assertTrue(ack.getJSONObject("result").has("keptUnattributed"))
    }
}
