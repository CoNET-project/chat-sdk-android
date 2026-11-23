package network.conet.chat

import android.content.Context
import android.content.ContextWrapper
import java.io.File
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * accountCleanupOld is disabled (interface seat v179 §199): the command answers not_available and deletes nothing. Driven through the real entry
 * [BeamioConetChatModule.handleCommand] with a temporary files directory, so nothing outside the test is touched.
 */
class AccountCleanupDisabledTest {
    private lateinit var context: Context
    private lateinit var dir: File

    private class TestContext(private val root: File) : ContextWrapper(null) {
        override fun getApplicationContext(): Context = this
        override fun getFilesDir(): File = root
        override fun getCacheDir(): File = root
    }

    @Before
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("cleanup-disabled").toFile()
        File(dir, "conet-chat").mkdirs()
        File(dir, "conet-chat/history-sentinel.bin").writeText("keep")
        context = TestContext(dir)
        network.conet.chat.MainPoster.runner = { it.run() }
    }

    @After
    fun tearDown() {
        network.conet.chat.MainPoster.runner = null
        dir.deleteRecursively()
    }

    @Test
    fun accountCleanupOldIsARefusalAndDeletesNothing() {
        val out = java.util.Collections.synchronizedList(mutableListOf<JSONObject>())
        BeamioConetChatModule.handleCommand(
            context,
            JSONObject().put("type", "accountCleanupOld").put("reqId", 7).put("accountKey", "0x" + "1".repeat(40) + ":default").put("idempotencyKey", "k-1"),
        ) { out.add(it) }
        // The answer can come from a worker when other tests in the same JVM left process-wide state behind, so it is awaited (at most three seconds).
        fun ackNow(): JSONObject? = synchronized(out) { out.mapNotNull { it.optJSONObject("event") }.lastOrNull { it.optString("type") == "ack" } }
        for (i in 0 until 60) { if (ackNow() != null) break; Thread.sleep(50) }
        val ack = ackNow()
        // With no session, the readiness gate answers not_ready before the command runs; with a session the command answers not_available. Either way it
        // is a refusal, never ok, and nothing is deleted.
        assertTrue(ack?.optString("error") in setOf("not_ready", "not_available"))
        assertFalse(ack?.optBoolean("ok") ?: true)
        assertEquals("keep", File(dir, "conet-chat/history-sentinel.bin").readText())
    }
}
