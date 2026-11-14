package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * TP-01 to TP-10 and SA-01 to SA-04 (spec r3bw §25.52AA.2, §25.52AA.3). The page chooses the transport; the SDK runs the same rule here as a
 * reference, so the vectors pin it. The Android SDK accepts only `window.BeamioShellRecord` and refuses the chat-module channel with
 * `not_supported`; the iOS rows are the iOS SDK's and are checked here only as the reference rule.
 */
class ShellRecordTransportTest {
    private val doc = JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))

    /** §25.52AA.2: the transport the page uses, and the error when it is refused. */
    private fun selectTransport(platform: String, windowInjected: Boolean, chatChannel: Boolean, originAllowed: Boolean): Pair<String, String?> = when {
        windowInjected -> if (originAllowed) "window" to null else "refused" to "origin_refused"
        platform == "android" -> "refused" to "not_supported"
        platform == "ios" && chatChannel -> if (originAllowed) "chat" to null else "refused" to "origin_refused"
        else -> "none" to null
    }

    /** §25.52AA.3: the channels each SDK accepts. */
    private fun acceptsChannel(platform: String, channel: String): Boolean = when (platform) {
        "android" -> channel == "window"
        "ios" -> channel == "window" || channel == "chat"
        else -> false
    }

    @Test
    fun theTransportRuleMatchesTheTransportVectors() {
        val cases = doc.getJSONArray("transportCases")
        assertEquals(10, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val input = c.getJSONObject("input")
            val (via, error) = selectTransport(
                input.getString("platform"),
                input.getBoolean("windowInjected"),
                input.getBoolean("chatChannel"),
                input.getBoolean("originAllowed"),
            )
            val expect = c.getJSONObject("expect")
            assertEquals(c.getString("id"), expect.getString("via"), via)
            assertEquals(c.getString("id"), if (expect.isNull("error")) null else expect.getString("error"), error)
        }
    }

    @Test
    fun theSdkAcceptanceMatchesTheSdkVectors() {
        val cases = doc.getJSONArray("sdkAcceptCases")
        assertEquals(4, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val input = c.getJSONObject("input")
            assertEquals(c.getString("id"), c.getBoolean("expect"), acceptsChannel(input.getString("platform"), input.getString("channel")))
        }
    }

    @Test
    fun theAndroidChatChannelIsRefusedWithNotSupportedAndNeverAnOriginError() {
        // SA-02, TP-03: the module's shellRecord branch answers the ack refusal not_supported (the page must not fall back to the chat module).
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertTrue(module.contains("shellAck(echo, \"not_supported\", emptyList())"))
    }
}
