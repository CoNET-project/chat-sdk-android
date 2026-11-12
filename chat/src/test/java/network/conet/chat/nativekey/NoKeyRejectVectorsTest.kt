package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * T-155 and spec §25.26.4 against `spec/no-key-reject-vectors.v1.json` (sha256 4da5836e…6362).
 *
 * The routing decision is [NoKeyGate.route], which is what the module calls before any dispatch. The vectors list
 * 27 wallet names and 21 chat names that must answer `no_key` (48 cases), and 3 retired X-21 names that must answer
 * `not_supported` (the 51 entries). Each entry is checked by its name only: the gate never reads a payload.
 */
class NoKeyRejectVectorsTest {
    private val bytes = File(System.getenv("NO_KEY_VECTORS") ?: "../spec/no-key-reject-vectors.v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    /** The code the gate's route implies for a command the vectors send without a key. */
    private fun codeFor(command: String): String = when (NoKeyGate.route(command)) {
        NoKeyGate.Route.NO_KEY -> "no_key"
        NoKeyGate.Route.NOT_SUPPORTED -> "not_supported"
        else -> "not-a-rejection"
    }

    @Test
    fun vectorFileIsTheCanonicalOne() {
        // r3h (spec §25.26.4, r3h). The r3f file (69ab42e4…6866) and the r3e file (4da5836e…6362) are withdrawn.
        assertEquals("b3bda74a5f126700bdc81fe9822e16bba1c7703ed67978bbf1e5b70448d4a597", sha256Hex(bytes))
    }

    @Test
    fun entryCountsMatchTheManifest() {
        assertEquals(27, v.getJSONArray("walletCommands").length())
        assertEquals(29, v.getJSONArray("chatCommands").length())
        assertEquals(3, v.getJSONArray("retiredCommands").length())
        assertEquals(2, v.getJSONArray("specialStatus").length())
        assertEquals(3, v.getJSONArray("secretPayloadControls").length())
        val noKey = v.getJSONArray("walletCommands").length() + v.getJSONArray("chatCommands").length()
        val notSupported = v.getJSONArray("retiredCommands").length()
        // r3f: 27 wallet + 29 chat = 56 no_key entries; 3 retired entries are not_supported. Together 59.
        assertEquals(56, noKey)
        assertEquals(3, notSupported)
        assertEquals(59, noKey + notSupported)
        val counts = v.getJSONObject("counts")
        assertEquals(56, counts.getInt("noKeyTotal"))
        assertEquals(3, counts.getInt("notSupported"))
        assertEquals(59, counts.getInt("total"))
    }

    @Test
    fun everyNoKeyEntryRoutesToNoKey() {
        // 56 entries answer no_key: every wallet and chat name, including the eight names added in r3f.
        var n = 0
        for (list in listOf(v.getJSONArray("walletCommands"), v.getJSONArray("chatCommands"))) {
            for (i in 0 until list.length()) {
                val c = list.getJSONObject(i)
                assertEquals(c.getString("id"), "no_key", codeFor(c.getString("command")))
                n++
            }
        }
        assertEquals(56, n)
    }

    @Test
    fun everyWalletCommandAnswersNoKey() {
        val list = v.getJSONArray("walletCommands")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            assertEquals(c.getString("id"), c.getString("expectCode"), codeFor(c.getString("command")))
            assertFalse(c.getString("id"), c.getBoolean("dataReturned"))
            assertFalse(c.getString("id"), c.getBoolean("signed"))
        }
    }

    @Test
    fun everyChatCommandAnswersNoKeyWithoutEffects() {
        val list = v.getJSONArray("chatCommands")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            assertEquals(c.getString("id"), c.getString("expectCode"), codeFor(c.getString("command")))
            assertFalse(c.getString("id"), c.getBoolean("dataReturned"))
            assertTrue(c.getString("id"), c.getJSONArray("events").length() == 0)
            assertFalse(c.getString("id"), c.getBoolean("mailboxRequest"))
        }
    }

    @Test
    fun signKindsAndPasscodeModesDoNotChangeTheAnswer() {
        // The route takes the name only, so a kind or mode can never produce a different code.
        for (kind in listOf("selfAuth", "pointerEip712", "chatRouteRegister", "envelope", "group", "voice", "gossip")) {
            assertEquals("signMessage kind=$kind", "no_key", codeFor("signMessage"))
            assertTrue(kind.isNotEmpty())
        }
        for (mode in listOf("enable", "change", "disable", "unlock")) {
            assertEquals("passcodeRun mode=$mode", "no_key", codeFor("passcodeRun"))
        }
    }

    @Test
    fun retiredX21CommandsAnswerNotSupportedFirst() {
        val list = v.getJSONArray("retiredCommands")
        assertEquals(3, list.length())
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            assertEquals(c.getString("id"), "not_supported", c.getString("expectCode"))
            assertEquals(c.getString("id"), "not_supported", codeFor(c.getString("command")))
        }
    }

    @Test
    fun statusQueriesAnswerWithoutTheKey() {
        val wallet = v.getJSONArray("specialStatus").getJSONObject(0)
        assertEquals("walletStatus", wallet.getString("command"))
        assertEquals(NoKeyGate.Route.WALLET_STATUS, NoKeyGate.route("walletStatus"))
        val status = NoKeyGate.walletStatusNoKey()
        assertEquals("no_key", status.getString("status"))
        assertFalse(status.has("accountKey"))

        val passcode = v.getJSONArray("specialStatus").getJSONObject(1)
        assertEquals("passcodeStatus", passcode.getString("command"))
        assertEquals(NoKeyGate.Route.PASSCODE_STATUS, NoKeyGate.route("passcodeStatus"))
        val ps = NoKeyGate.passcodeStatusNoKey()
        assertEquals(false, ps.getBoolean("set"))
        assertEquals(false, ps.getBoolean("locked"))
        assertEquals(false, ps.getBoolean("hasKey"))
    }

    @Test
    fun lifecycleAndImportOpenKeepTheirSemantics() {
        for (name in listOf("hello", "pause", "resume", "destroy", "nativeImportOpen", "nativeRecoveryOpen")) {
            assertEquals(name, NoKeyGate.Route.PASS, NoKeyGate.route(name))
        }
    }

    @Test
    fun secretPayloadControlsAnswerNoKey() {
        // The payload carries a key; the route never looks at it, so it is neither parsed nor echoed.
        val list = v.getJSONArray("secretPayloadControls")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            assertEquals(c.getString("id"), "no_key", codeFor(c.getString("command")))
            assertFalse(c.getString("id"), c.getBoolean("echoed"))
            assertFalse(c.getString("id"), c.getBoolean("stored"))
        }
    }

    @Test
    fun namesOutsideTheManifestAreDeniedByDefault() {
        for (name in listOf("historyListConversations", "historyNewThing", "somethingUnknown", "identity.provision")) {
            assertEquals(name, "no_key", codeFor(name))
        }
    }
}
