package network.conet.chat.nativekey

import network.conet.chat.BridgeCommandTable
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * walletEoaAddress on the window channel (spec §25.52Y.42 第 5 项 (c), (d); r3ny 第 9 项). The origin and the main frame are
 * decided first; a request from a source that is not allowed never reaches the vault or the gate. The address is the only result.
 */
class WalletEoaAddressBridgeTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

    private fun request(type: String = "walletEoaAddress", reqId: Any = "r1"): JSONObject =
        JSONObject().put("type", type).put("reqId", reqId)

    private fun vaultWithKeyOnlyAccount(): NativeWalletVault {
        val v = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        v.importKey(eoa, MnemonicDerivation.deriveKey(phrase)!!)
        return v
    }

    /** The origin must be the embedded origin and the main frame. Anything else is refused. */
    @Test
    fun onlyTheAllowedOriginInTheMainFrameIsAllowed() {
        val allowed = BeamioShellRecordImport.ALLOWED_ORIGIN
        assertTrue(WalletEoaAddressBridge.originAllowed(allowed, isMainFrame = true))
        assertFalse(WalletEoaAddressBridge.originAllowed(allowed, isMainFrame = false))
        assertFalse(WalletEoaAddressBridge.originAllowed("https://example.invalid", isMainFrame = true))
        assertFalse(WalletEoaAddressBridge.originAllowed(null, isMainFrame = true))
    }

    /** A refused origin is answered origin_refused, and the vault and the gate are never read. */
    @Test
    fun aRefusedOriginNeverReachesTheVault() {
        val reply = WalletEoaAddressBridge.answer(originAllowed = false, body = request()) {
            fail("the vault must not be read for a refused origin")
            throw IllegalStateException("unreachable")
        }
        assertEquals("origin_refused", reply.getString("error"))
        assertFalse(reply.getBoolean("ok"))
    }

    /** G1 with a key-only account: the address only, and no other field. */
    @Test
    fun anAllowedRequestReturnsTheAddressOnly() {
        val v = vaultWithKeyOnlyAccount()
        val reply = WalletEoaAddressBridge.answer(originAllowed = true, body = request()) { v to NoKeyGate.Gate.G1 }
        assertTrue(reply.getBoolean("ok"))
        assertEquals("ack", reply.getString("type"))
        assertEquals("r1", reply.getString("reqId"))
        val result = reply.getJSONObject("result")
        assertEquals(eoa, result.getString("eoa"))
        assertEquals(1, result.length())
    }

    /** G2 answers the same address (spec §25.52Y.42 第 5 项 (d)). */
    @Test
    fun g2AnswersTheSameAddress() {
        val v = vaultWithKeyOnlyAccount()
        val reply = WalletEoaAddressBridge.answer(originAllowed = true, body = request()) { v to NoKeyGate.Gate.G2 }
        assertEquals(eoa, reply.getJSONObject("result").getString("eoa"))
    }

    /** G0 (no record) answers no_key. */
    @Test
    fun g0AnswersNoKey() {
        val v = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val reply = WalletEoaAddressBridge.answer(originAllowed = true, body = request()) { v to NoKeyGate.Gate.G0 }
        assertEquals("no_key", reply.getString("error"))
        assertFalse(reply.getBoolean("ok"))
    }

    /** Any extra field is bad_request, and the name is walletEoaAddress or unknown_command. */
    @Test
    fun aMalformedRequestIsRefusedBeforeTheVaultIsRead() {
        val reads = mutableListOf<Int>()
        val current = { reads.add(1); vaultWithKeyOnlyAccount() to NoKeyGate.Gate.G1 }
        val extra = request().put("privateKeyHex", "0x00")
        assertEquals("bad_request", WalletEoaAddressBridge.answer(true, extra) { current() }.getString("error"))
        assertEquals("unknown_command", WalletEoaAddressBridge.answer(true, request(type = "walletCredential")) { current() }.getString("error"))
        assertEquals("bad_request", WalletEoaAddressBridge.answer(true, JSONObject().put("type", "walletEoaAddress")) { current() }.getString("error"))
        assertTrue("the vault was read for a malformed request", reads.isEmpty())
    }

    /** The chat channel does not carry the name: it is not in the chat table, and is answered unknown_command there. */
    @Test
    fun theChatChannelDoesNotCarryWalletEoaAddress() {
        assertFalse(BridgeCommandTable.isRegistered(WalletEoaAddressBridge.NAME))
        assertTrue(WalletEoaAddressBridge.NAME in BridgeCommandTable.WINDOW_CHANNEL)
    }

    /** walletCredential is never on the chat channel; on the window channel it is served only behind the SDK's declaration. */
    @Test
    fun walletCredentialIsNotOnTheChatChannel() {
        assertFalse(BridgeCommandTable.isRegistered("walletCredential"))
        assertTrue("walletCredential" in BridgeCommandTable.WINDOW_CHANNEL)
    }

    private fun publicBridge(vault: NativeWalletVault?, gate: NoKeyGate.Gate = NoKeyGate.Gate.G1): ShellRecordBridge {
        val files = NativeTestFiles()
        return ShellRecordBridge(
            account = { ShellRecordAccount.NotReady },
            migrating = { false },
            outcome = { null },
            walletEoaAddress = vault?.let { v -> { v to gate } },
        )
    }

    /**
     * The shell's window call reaches walletEoaAddress through the bridge that BeamioShellRecordImport.handle delegates to. The
     * request from the embedded page returns the address only. (The public entry itself needs an Android Context, which these unit tests cannot
     * build; the delegation is checked by source below.)
     */
    @Test
    fun theBridgeReturnsTheAddressOnlyForTheEmbeddedPage() {
        val v = vaultWithKeyOnlyAccount()
        val reply = publicBridge(v).handle(ShellOrigin.EMBEDDED_PAGE, request(), 64)
        assertTrue(reply.getBoolean("ok"))
        val result = reply.getJSONObject("result")
        assertEquals(eoa, result.getString("eoa"))
        assertEquals(1, result.length())
    }

    /** A call from any origin other than the embedded page is origin_refused, and the vault is not read. */
    @Test
    fun theBridgeRefusesAnOtherOriginWithoutReadingTheVault() {
        val reply = publicBridge(null).handle(ShellOrigin.OTHER, request(), 64)
        assertEquals("origin_refused", reply.getString("error"))
        var read = false
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.NotReady },
            migrating = { false },
            outcome = { null },
            walletEoaAddress = { read = true; error("must not be read") },
        )
        bridge.handle(ShellOrigin.OTHER, request(), 64)
        assertFalse("the vault was read for an other origin", read)
    }

    /** A bridge without the wallet lookup does not serve the name: it stays unknown_command, as before. */
    @Test
    fun aBridgeWithoutTheWalletLookupDoesNotServeTheName() {
        val reply = publicBridge(null).handle(ShellOrigin.EMBEDDED_PAGE, request(), 64)
        assertEquals("unknown_command", reply.getString("error"))
    }

    /** The public entry delegates to the bridge, and the bridge gets the vault and the gate from the context (source structure). */
    @Test
    fun thePublicEntryDelegatesToTheBridgeThatServesTheName() {
        val source = File("src/main/java/network/conet/chat/nativekey/ShellRecord.kt").readText(Charsets.UTF_8)
        assertTrue("the public handle delegates to the bridge", source.contains("bridge(context).handle(origin, body, requestBytes)"))
        assertTrue("the bridge supplies the wallet lookup", source.contains("walletEoaAddress = walletCurrent(context)"))
        assertTrue("the bridge answers walletEoaAddress before the unknown-action refusal",
            source.indexOf("WalletEoaAddressBridge.NAME") < source.indexOf("else -> return reply(\"unknown_command\""))
    }
}
