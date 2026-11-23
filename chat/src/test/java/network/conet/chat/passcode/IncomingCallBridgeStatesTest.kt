package network.conet.chat.passcode

import android.content.Context
import android.content.ContextWrapper
import java.io.File
import network.conet.chat.BeamioConetChatModule
import network.conet.chat.MainPoster
import network.conet.chat.nativekey.MnemonicDerivation
import network.conet.chat.nativekey.NativeSessionState
import network.conet.chat.nativekey.NativeTestFiles
import network.conet.chat.nativekey.NativeTestWrap
import network.conet.chat.nativekey.NativeWallet
import network.conet.chat.nativekey.NativeWalletVault
import network.conet.chat.nativekey.WalletAddress
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Behavioural negatives in the five gate states (2026-11-20): `incomingCallBind` and `incomingCallUnbind`, sent through the real
 * [BeamioConetChatModule.handleCommand], are answered `unknown_command` in G0 (no record), G1 (record, session not initialised), G2 (initialised,
 * EOA equal), LOCKED and busy (a PGP migration in progress). The shared registry is unchanged by them.
 *
 * The states are driven from the test doubles ([NativeTestWrap], [NativeTestFiles]): the vault is installed as the process vault, its snapshot is
 * published by one read, the session flag is set through [NativeSessionState], and the busy flag is set directly. A control `walletStatus` must
 * then answer differently across the states; without that, a state that did not take effect would pass unnoticed. The test is driven from the
 * real entry; there is no source-order substitute.
 */
class IncomingCallBridgeStatesTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val eoa: String = checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(phrase)))).lowercase()
    private val callId = "call-states-0001"
    private lateinit var context: Context

    private enum class Drive { G0, G1, G2, LOCKED_G1, LOCKED_G2, BUSY }

    /** A context whose application context is itself and whose files live in a temporary directory. */
    private class TestContext(private val dir: File) : ContextWrapper(null) {
        override fun getApplicationContext(): Context = this
        override fun getFilesDir(): File = dir
        override fun getCacheDir(): File = dir
    }

    @Before
    fun setUp() {
        context = TestContext(kotlin.io.path.createTempDirectory("incoming-call-states").toFile())
        MainPoster.runner = { it.run() }
        // Order independence (found 2026-11-22; the test also fails alone at and): the module's first command runs the start-up redo while
        // appContext is null, and that redo reads SharedPreferences, which this context cannot supply, so it blocked every gated command with not_ready.
        // Other tests happen to set appContext first. Set it here, as they do, so the redo is not run by this test. Test-only.
        BeamioConetChatModule::class.java.getDeclaredField("appContext").apply { isAccessible = true }.set(BeamioConetChatModule, context)
    }

    @After
    fun tearDown() {
        MainPoster.runner = null
        BeamioConetChatModule.pgpMigrateRunning.set(false)
        NativeSessionState.reset()
        NativeWallet.installVaultForTest(null)
        IncomingCalls.registry.onSessionEnded(eoa, SessionGeneration.Reason.LOGOUT)
    }

    /** Installs the vault and session for [drive], and publishes the vault snapshot with one read. */
    private fun prepare(drive: Drive) {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = NativeWalletVault(wrap, files)
        if (drive != Drive.G0) {
            val key = checkNotNull(MnemonicDerivation.deriveKey(phrase))
            assertEquals(NativeWalletVault.Import.OK, vault.importMnemonicKey(eoa, key, phrase))
        }
        if (drive == Drive.LOCKED_G1 || drive == Drive.LOCKED_G2) {
            // Every stored file is corrupted: the record no longer reads, so the vault is locked.
            for (name in files.map.keys.toList()) files.map[name] = byteArrayOf(1, 2, 3)
        }
        NativeWallet.installVaultForTest(vault)
        vault.state() // publishes the snapshot the gate reads (never the keystore on this thread)
        when (drive) {
            Drive.G2, Drive.LOCKED_G2, Drive.BUSY -> NativeSessionState.markReady("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa")
            else -> NativeSessionState.reset()
        }
        BeamioConetChatModule.pgpMigrateRunning.set(drive == Drive.BUSY)
    }

    private fun send(body: JSONObject): List<JSONObject> {
        val out = mutableListOf<JSONObject>()
        BeamioConetChatModule.handleCommand(context, body) { out.add(it) }
        return out
    }

    private fun envelope(type: String, reqId: Any) = JSONObject()
        .put("type", type)
        .put("reqId", reqId)
        .put("callId", callId)
        .put("eoa", eoa)

    /** The module emits `{action:"chatModuleEvent", event:{...}}`; the ack is the event with type "ack". */
    private fun ackOf(out: List<JSONObject>): JSONObject? =
        out.mapNotNull { it.optJSONObject("event") }.lastOrNull { it.optString("type") == "ack" }

    /** The control: a known command whose answer depends on the gate state. */
    private fun walletStatusOf(reqId: Int): String {
        val out = send(JSONObject().put("type", "walletStatus").put("reqId", reqId))
        val result = ackOf(out)?.optJSONObject("result") ?: error("expected a walletStatus result, got $out")
        return result.toString()
    }

    @Test
    fun theNamesAreUnknownCommandInEachGateStateAndTheRegistryIsUnchanged() {
        val controls = linkedMapOf<Drive, String>()
        var reqId = 1
        for (drive in Drive.values()) {
            prepare(drive)
            controls[drive] = walletStatusOf(reqId++) // the state took effect
            if (drive == Drive.BUSY) assertTrue("the busy flag is set", BeamioConetChatModule.pgpMigrateRunning.get())

            IncomingCalls.registry.onSessionEnded(eoa, SessionGeneration.Reason.LOGOUT)
            assertTrue(IncomingCalls.registry.incomingCallBind(callId, eoa))

            for (name in listOf("incomingCallBind", "incomingCallUnbind")) {
                val ack = ackOf(send(envelope(name, reqId++))) ?: error("$drive: expected an ack for $name")
                assertEquals("$drive $name", "unknown_command", ack.optString("error"))
                assertFalse("$drive $name", ack.optBoolean("ok"))
            }
            assertTrue(
                "$drive: the registration still holds the native call",
                IncomingCalls.registry.check(callId, eoa, eoa) is IncomingCallRegistry.CallCheck.Proceed,
            )
        }
        assertTrue(
            "the control must show the states take effect (distinct walletStatus answers), got $controls",
            controls.values.toSet().size >= 3,
        )
    }
}
