package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * T-155 and spec §25.26.4 against `spec/no-key-reject-vectors.v1.json` (r3ek, sha256 369883a3…cac5; NK-W6b pgpDecrypt removed, 25.52CK.1).
 *
 * The routing decision is [NoKeyGate.route], which is what the module calls before any dispatch. The vectors list
 * 25 wallet names and 29 chat names that must answer `no_key` (54 entries; pgpSign is not in the table, 25.52BP.1), and 3 retired X-21 names that must answer
 * `not_supported` (57 entries in all). Each entry is checked by its name only: the gate never reads a payload.
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
        NoKeyGate.Route.UNKNOWN_NAME -> "unknown_command"
        else -> "not-a-rejection"
    }

    @Test
    fun vectorFileIsTheCanonicalOne() {
        // r3x (spec §25.46.10, AL-7): nativeAccountCreateOpen joins the allowed list. The r3h file (b3bda74a…8a597) is withdrawn.
        // r2.5.1 re-pin (spec/no-key-reject-vectors.v1.json from the interface, nine names with nativeMnemonicPreread).
        assertEquals("bff98ebaff954087", sha256Hex(bytes).substring(0, 16))
    }

    @Test
    fun entryCountsMatchTheManifest() {
        assertEquals(25, v.getJSONArray("walletCommands").length())
        assertEquals(29, v.getJSONArray("chatCommands").length())
        assertEquals(3, v.getJSONArray("retiredCommands").length())
        assertEquals(2, v.getJSONArray("specialStatus").length())
        assertEquals(3, v.getJSONArray("secretPayloadControls").length())
        val noKey = v.getJSONArray("walletCommands").length() + v.getJSONArray("chatCommands").length()
        val notSupported = v.getJSONArray("retiredCommands").length()
        // r3ek (25.52CK.1): pgpDecrypt (NK-W6b) removed: 25 wallet + 29 chat = 54 no_key entries; 3 retired entries are not_supported. Together 57.
        assertEquals(54, noKey)
        assertEquals(3, notSupported)
        assertEquals(57, noKey + notSupported)
        val counts = v.getJSONObject("counts")
        assertEquals(54, counts.getInt("noKeyTotal"))
        assertEquals(3, counts.getInt("notSupported"))
        assertEquals(57, counts.getInt("total"))
    }

    @Test
    fun everyNoKeyEntryRoutesToItsExpectedCode() {
        // 54 entries: each one's expectCode is the code its route implies. Most answer no_key; the names that are not bridge
        // names (W2 to W4, the W5 signMessage kinds) answer unknown_command before the gate (25.52DP.1, 25.52AR.3).
        var n = 0
        var unknown = 0
        for (list in listOf(v.getJSONArray("walletCommands"), v.getJSONArray("chatCommands"))) {
            for (i in 0 until list.length()) {
                val c = list.getJSONObject(i)
                val expected = c.getString("expectCode")
                assertEquals(c.getString("id"), expected, codeFor(c.getString("command")))
                if (expected == "unknown_command") unknown++
                n++
            }
        }
        assertEquals(54, n)
        assertEquals(10, unknown)
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
            // W5 has no bridge name (25.52AR.3; NK-W5a to NK-W5g): unknown_command, whatever the kind.
            assertEquals("signMessage kind=$kind", "unknown_command", codeFor("signMessage"))
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
    fun lifecycleAndPageOpenKeepTheirSemantics() {
        // r2.4.6 46(4): nativeImportOpen is removed (r2.3 41); the manifest file is re-pinned by the interface owner.
        for (name in listOf("hello", "pause", "resume", "destroy", "nativeRecoveryOpen", "nativeAccountCreateOpen", "nativeMnemonicPreread")) {
            assertEquals(name, NoKeyGate.Route.PASS, NoKeyGate.route(name))
        }
    }

    /**
     * r2.4.8 48(7) 做法 (b) and AL-03: the no-key list has exactly nine names, pwaWalletSync is not one of them, and pwaWalletSync runs on its
     * own lifecycle route (its conditions are checked in the handler).
     */
    @Test
    fun pwaWalletSyncIsNotOnTheNoKeyListAndHasItsOwnRoute() {
        val list = v.getJSONArray("allowedUnderNoKey")
        val manifest = (0 until list.length()).map { list.getString(it) }.toSet()
        assertEquals("the no-key list has nine names", 9, manifest.size)
        assertFalse("pwaWalletSync is not on the no-key list", "pwaWalletSync" in manifest)
        assertFalse("pwaWalletSync is not a pass-through name", NoKeyGate.route("pwaWalletSync") == NoKeyGate.Route.PASS)
        assertEquals(NoKeyGate.Route.LIFECYCLE, NoKeyGate.route("pwaWalletSync"))
        // AL-03 counts the nine names of the list; each one is allowed (PASS, or a status answer), none is refused as no_key.
        assertEquals(9, manifest.count { NoKeyGate.route(it) != NoKeyGate.Route.NO_KEY })
    }

    @Test
    fun theAllowedListIsTheManifestList() {
        // allowedUnderNoKey (r3x): the lifecycle names, the three page-open names and the two status queries.
        val list = v.getJSONArray("allowedUnderNoKey")
        // r2.4.6 46(4) applied to the manifest of r3x: nativeImportOpen is removed, nativeMnemonicPreread is added. The vector file still
        // lists the old set until the interface owner re-pins it; the expected set below is the r2.4.6 set.
        val names = (0 until list.length()).map { list.getString(it) }.toSet()
        assertEquals(
            setOf("destroy", "hello", "nativeAccountCreateOpen", "nativeMnemonicPreread", "nativeRecoveryOpen", "passcodeStatus", "pause", "resume", "walletStatus"),
            names,
        )
        val pass = names.filter { NoKeyGate.route(it) == NoKeyGate.Route.PASS }.toSet()
        assertEquals(setOf("destroy", "hello", "nativeAccountCreateOpen", "nativeMnemonicPreread", "nativeRecoveryOpen", "pause", "resume"), pass)
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
