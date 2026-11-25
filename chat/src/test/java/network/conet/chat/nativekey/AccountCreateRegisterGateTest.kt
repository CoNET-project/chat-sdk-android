package network.conet.chat.nativekey

import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The gate of `accountCreateRegister` (0.2.32, protocol clarification 4): it follows a successful `nativeAccountCreateOpen`, which leaves the device in
 * G1, so the gate lets it through in G0, G1 and G2 and its own handler decides. With no account the handler answers `not_ready`, never `no_key`; with a
 * readable account it goes on to the registry although the session is not initialised. Every other key command keeps `no_key` in G0 and `not_ready` in G1.
 */
class AccountCreateRegisterGateTest {
    private val random = SecureRandom()
    private val phraseText = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val key = MnemonicDerivation.deriveKey(phraseText)!!
    private val eoa = WalletAddress.fromPrivateKey(key)!!
    private val cheap: (ByteArray, RecoveryRecord.Stored) -> ByteArray = { p, s -> MessageDigest.getInstance("SHA-256").digest(p + s.salt) }
    private val build = { n: String, p: ByteArray, e: String, k: ByteArray, ph: ByteArray -> AccountRegisterPayload.build(n, p, e, k, ph, random, cheap) }

    @Before
    fun reset() = AccountRegisterCommand.Flight.resetForTests()

    private fun ready() = AccountRegisterCommand.MaterialRead.Ready(AccountRegisterCommand.Material(eoa, key.copyOf(), phraseText.toByteArray()))

    @Test
    fun theGateLetsTheCommandThroughInEveryStateAndTheHandlerDecides() {
        assertEquals(NoKeyGate.Route.PASS, NoKeyGate.route("accountCreateRegister"))
        for (gate in NoKeyGate.Gate.values()) {
            val answer = NoKeyGate.answerFor("accountCreateRegister", gate)
            assertEquals("the gate leaves it to the handler in $gate", "allowed", answer)
            assertNotEquals(NoKeyGate.NO_KEY, answer)
            assertNotEquals(NoKeyGate.NOT_READY, answer)
        }
    }

    @Test
    fun theOtherKeyCommandsAreStillGated() {
        for (name in listOf("walletSignMessage", "walletSignTypedData", "pgpDecryptInbound", "historySign", "chatRouteRegister", "pgpIdentityCreate")) {
            assertEquals("$name in G0", NoKeyGate.NO_KEY, NoKeyGate.answerFor(name, NoKeyGate.Gate.G0))
            assertEquals("$name in G1", NoKeyGate.NOT_READY, NoKeyGate.answerFor(name, NoKeyGate.Gate.G1))
            assertEquals("$name in G2", "dispatch", NoKeyGate.answerFor(name, NoKeyGate.Gate.G2))
        }
    }

    @Test
    fun withNoAccountTheHandlerAnswersNotReadyAndNeverReadsTheRegistry() {
        val registryReads = AtomicInteger()
        val r = AccountRegisterCommand.run(
            "qa.tag_1", "pw-gate-test".toByteArray(),
            { AccountRegisterCommand.MaterialRead.NotReady(false) },
            { registryReads.incrementAndGet(); null },
            build,
        )
        assertEquals("not_ready", r.error)
        assertEquals("no account is not no_key", false, r.error == NoKeyGate.NO_KEY)
        assertEquals(0, registryReads.get())
    }

    @Test
    fun withAReadableAccountAndNoSessionTheHandlerGoesOnToTheRegistry() {
        // G1: a record exists and the session is not initialised. The handler takes its material from the vault, so the registry is read.
        val registryReads = AtomicInteger()
        val r = AccountRegisterCommand.run(
            "qa.tag_1", "pw-gate-test".toByteArray(),
            { ready() },
            { registryReads.incrementAndGet(); null },
            build,
        )
        assertTrue(r.ok)
        assertEquals(1, registryReads.get())
        assertEquals(setOf("accountName", "wallet", "signMessage", "recover", "recoverCodeBase58"), r.result!!.keys().asSequence().toSet())
    }

    @Test
    fun theHandlerDoesNotReadTheSession() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        val handler = module.substringAfter("private fun accountCreateRegisterCommand(").substringBefore("/** The read-only chain check")
        assertFalse("it needs no initialised session", handler.contains("NativeSessionState") || handler.contains("currentSession()"))
        val command = File("src/main/java/network/conet/chat/nativekey/AccountRegisterCommand.kt").readText()
        assertFalse(command.contains("NativeSessionState"))
        // It is dispatched from the route that skips the gate, in the same place as the other pass-through handlers.
        assertTrue(module.contains("\"accountCreateRegister\" -> accountCreateRegisterCommand(body)"))
    }
}
