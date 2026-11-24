package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The read-only precheck of the mailbox node: a node is used only when AddressPGP records it (`nodeKeyExists`, the PWA's pickRecordedMailbox
 * rule) and GuardianNodesInfoV6 knows its route key (the contract's own requirement), so a registration never reverts in the paid transaction.
 */
class RouteRecordedTest {
    private val addressPgp = AddressPgpConfig.default.contract
    private val guardian = "0x" + "77".repeat(20)

    private fun keccakHex(id: String) = ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256(id.toByteArray(Charsets.UTF_8)))

    private fun word(addr: String) = "0x" + addr.removePrefix("0x").lowercase().padStart(64, '0')

    private fun abiString(text: String): String {
        val b = text.toByteArray(Charsets.UTF_8)
        val padded = b.joinToString("") { "%02x".format(it) }.padEnd(((b.size + 31) / 32) * 64, '0')
        return "0x" + "%064x".format(32) + "%064x".format(b.size) + padded
    }

    /** A fake chain: the nodes AddressPGP records, the route keys GuardianNodes knows (with an ip), and a switch that makes every call fail. */
    private class Chain(val recorded: Set<String>, val known: Map<String, String>, var failing: Boolean = false) {
        val calls = ArrayList<String>()
    }

    private fun rpcOf(c: Chain, keccak: (String) -> String = ::keccakHex0) = AddressPgpRead.Rpc { method, params ->
        require(method == "eth_call")
        if (c.failing) throw IllegalStateException("rpc down")
        val call = (params.get(0) as JSONObject)
        val to = call.getString("to")
        val data = call.getString("data")
        c.calls += data.take(10)
        when {
            data.startsWith(AddressPgpRead.selector("nodeKeyExists(bytes32)")) -> {
                val h = data.removePrefix(AddressPgpRead.selector("nodeKeyExists(bytes32)"))
                "0x" + (if (c.recorded.any { keccak(it) == h }) "1" else "0").padStart(64, '0')
            }
            data.startsWith(AddressPgpRead.selector("guardianNodes()")) -> word(guardian)
            data.startsWith(AddressPgpRead.selector("getPGPKeyIPaddress(string)")) -> {
                require(to.equals(guardian, ignoreCase = true))
                val ids = c.known.keys.firstOrNull { RouteRecorded.callDataString("getPGPKeyIPaddress(string)", it) == data }
                abiString(ids?.let { c.known[it] } ?: "")
            }
            else -> throw AssertionError("unexpected call $data")
        }
    }

    @Test
    fun aNodeIsRecordedOnlyWhenBothAddressPgpAndTheGuardianContractKnowIt() {
        val c = Chain(recorded = setOf("AAAA", "BBBB"), known = mapOf("BBBB" to "1.2.3.4", "CCCC" to "5.6.7.8"))
        val rpc = rpcOf(c)
        assertFalse("not recorded by AddressPGP", RouteRecorded.isRecorded("CCCC", rpc))
        assertFalse("recorded by AddressPGP but the guardian contract has no ip for it (the registration would revert)", RouteRecorded.isRecorded("AAAA", rpc))
        assertTrue(RouteRecorded.isRecorded("BBBB", rpc))
        assertFalse(RouteRecorded.isRecorded("  ", rpc))
    }

    @Test
    fun aFailedReadThrowsAndIsNeverNotRecorded() {
        val c = Chain(setOf("AAAA"), mapOf("AAAA" to "1.1.1.1"), failing = true)
        try {
            RouteRecorded.isRecorded("AAAA", rpcOf(c))
            throw AssertionError("must throw")
        } catch (e: IllegalStateException) {
            assertEquals("rpc down", e.message)
        }
        // A malformed answer is a failure too.
        val bad = AddressPgpRead.Rpc { _, _ -> "0x12" }
        try {
            RouteRecorded.isRecorded("AAAA", bad)
            throw AssertionError("must throw")
        } catch (e: IllegalStateException) {
            assertEquals("route_read_failed", e.message)
        }
    }

    @Test
    fun theEndpointFailoverTriesTheBackupAndFailsWhenBothFail() {
        val down = AddressPgpRead.Rpc { _, _ -> throw IllegalStateException("down") }
        val up = rpcOf(Chain(setOf("BBBB"), mapOf("BBBB" to "1.2.3.4")))
        assertTrue(RouteRecorded.isRecorded("BBBB", RouteRecorded.failover(listOf(down, up))))
        try {
            RouteRecorded.isRecorded("BBBB", RouteRecorded.failover(listOf(down, down)))
            throw AssertionError("must throw")
        } catch (e: IllegalStateException) {
            assertEquals("down", e.message)
        }
    }

    @Test
    fun thePickTakesTheFirstRecordedNodeAndSkipsTheUnrecordedOnesWithoutAnyWrite() {
        val checked = ArrayList<String>()
        val r = RouteRecorded.pick(listOf("N1", "N2", "N3", "N4"), { checked += it; it == "N3" })
        assertEquals("N3", (r as RouteChoice.Ok).routeKeyId)
        assertEquals(listOf("N1", "N2", "N3"), checked)
    }

    @Test
    fun thePickAnswersNoneWhenNoCandidateIsRecordedAndUnreadableWhenACheckFails() {
        assertTrue(RouteRecorded.pick(listOf("N1", "N2"), { false }) is RouteChoice.None)
        assertTrue(RouteRecorded.pick(emptyList(), { true }) is RouteChoice.None)
        var n = 0
        assertTrue("a failed check picks nothing", RouteRecorded.pick(listOf("N1", "N2", "N3"), { if (n++ == 1) throw IllegalStateException("x") else false }) is RouteChoice.Unreadable)
    }

    @Test
    fun thePickChecksAtMostEightDistinctNodesAndDeduplicatesByCase() {
        val checked = ArrayList<String>()
        RouteRecorded.pick((1..20).map { "n$it" } + listOf("N1"), { checked += it; false })
        assertEquals(8, checked.size)
        val seen = ArrayList<String>()
        RouteRecorded.pick(listOf("abc", "ABC", " abc ", "", "def"), { seen += it; false })
        assertEquals(listOf("abc", "def"), seen)
    }

    @Test
    fun theProductionPickIsMemoizedPerRunAndAnUnreadableCheckIsNotRemembered() {
        val src = File("src/main/java/network/conet/chat/nativekey/KpgpUpgrade.kt").readText()
        assertTrue(src.contains("chooseRoute = routeOnce"))
        assertTrue(src.contains("if (result !is RouteChoice.Unreadable) chosen = result"))
        assertTrue("the roster is shuffled, then checked", src.contains(".map { it.domain }.shuffled()"))
        assertFalse("no unchecked random pick remains", src.contains(".randomOrNull()"))
        // Nothing here writes: the precheck source holds only eth_call.
        val check = File("src/main/java/network/conet/chat/nativekey/RouteRecorded.kt").readText()
        assertTrue(check.contains("\"eth_call\""))
        assertFalse(check.contains("eth_sendRawTransaction") || check.contains("eth_sendTransaction"))
    }

    companion object {
        fun keccakHex0(id: String) = ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256(id.toByteArray(Charsets.UTF_8)))
    }
}
