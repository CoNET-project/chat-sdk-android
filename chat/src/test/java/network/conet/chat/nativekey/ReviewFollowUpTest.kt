package network.conet.chat.nativekey

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * Hardening checks: K gets the registered bytes, the history store's HTTP cannot be replaced by a caller of the SDK,
 * and the production restore machine is built in one place, always with the gate.
 */
class ReviewFollowUpTest {
    private val random = SecureRandom()
    private val account = "0x" + "ab".repeat(20)
    private val own = RecKeys.generate(account, random)

    private fun main(path: String) = File("src/main/java/network/conet/chat/$path").readText(Charsets.UTF_8)

    @Test
    fun theMirroredKHoldsTheRegisteredPublicArmorBytesNotTheDerivedOnes() {
        // The same key, the registered text carries different bytes (extra blank lines): the fingerprint is the same, the bytes are not.
        val registeredText = own.publicArmor.trimEnd() + "\n\n\n"
        assertTrue("the fixture really differs", registeredText != own.publicArmor)
        val k = AccountPgpK(MemoryAccountPgpKBackend())
        val chain = RecChain(registered = registeredOf(own, account, publicArmor = registeredText), backup = "")
        val out = AutoRecovery.mirrorVault(account, KpgpUpgrade.LRecord(own.privateArmor, own.identity.subkeyKeyId), k, chain, 1L, random)
        assertEquals("mirrored:vault_record", out.logCode)
        val item = k.read(account, PgpMigrationPolicy.WORKSPACE)!!
        assertEquals(registeredText, item.getString("publicKeyArmor"))
        assertEquals(own.identity.subkeyKeyId, item.getString("keyId"))
    }

    @Test
    fun theHistoryStoreTransportIsNotAConstructorParameterAndIsInternal() {
        val src = main("BeamioConetChatHistoryStore.kt")
        val ctor = src.substring(src.indexOf("class BeamioConetChatHistoryStore("), src.indexOf(") {\n    /**\n     * The HTTP POST"))
        assertFalse("no transport in the public constructor", ctor.contains("transport"))
        assertTrue("the replaceable HTTP is internal", src.contains("internal var transport: ((String, String, Int) -> Pair<Int, String>)? = null"))
        val module = main("BeamioConetChatModule.kt")
        assertFalse("production never sets it", module.contains(".transport ="))
    }

    @Test
    fun theProductionRestoreMachineIsBuiltOnlyByTheBridgeAndAlwaysWithTheGate() {
        val builders = File("src/main/java/network/conet/chat").walkTopDown().filter { it.name.endsWith(".kt") }
            .filter { Regex("""\bPgpRestoreMachine\(""").containsMatchIn(it.readText(Charsets.UTF_8).replace(Regex("""class PgpRestoreMachine\("""), "")) }
            .map { it.name }.toList()
        assertEquals("only the bridge builds the machine in main: $builders", listOf("PgpRestoreBridge.kt"), builders)
        val bridge = main("nativekey/PgpRestoreBridge.kt")
        assertEquals("one construction", 1, Regex("""\bPgpRestoreMachine\(""").findAll(bridge).count())
        assertTrue(Regex("""recoveryGate\s*=\s*PageRecoveryGate\(\)""").containsMatchIn(bridge))
    }
}
