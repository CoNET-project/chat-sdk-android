package network.conet.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * DR-21 (revision 1): the hello declares `receipt.delivery.v1` when, and only when, this build has the whole receipt implementation. The shared hello
 * vector (the shared chat-daemon vectors) carries it at the end of the Android list; [ChatDaemonConformanceTest] compares the full list with that vector.
 */
class HelloReceiptCapabilityTest {
    @Test
    fun theBuildHasTheWholeImplementationSoItDeclaresTheCapability() {
        assertTrue(SenderReceipt.implementationComplete())
        assertEquals("receipt.delivery.v1", SenderReceipt.CAPABILITY)
        val names = BeamioConetChatProtocol.CAPABILITIES
        assertTrue(names.contains("receipt.delivery.v1"))
        val hello = BeamioConetChatProtocol.helloResult().getJSONArray("capabilities")
        assertTrue((0 until hello.length()).any { hello.getString(it) == "receipt.delivery.v1" })
    }

    @Test
    fun itFollowsTheProductionNamesAndComesBeforeAnyQaName() {
        val names = BeamioConetChatProtocol.CAPABILITIES
        assertEquals("identity.native-keys.v1", names[names.indexOf("receipt.delivery.v1") - 1])
        val after = names.drop(names.indexOf("receipt.delivery.v1") + 1)
        assertTrue("only QA names may follow: $after", after.all { it == "wallet.credential.v1" || it.contains("identity.state") || it.contains("first") })
    }

    @Test
    fun noOtherSourceDeclaresItAndTheListHasNoDuplicate() {
        val src = java.io.File("src/main/java/network/conet/chat/BeamioConetChatProtocol.kt").readText()
        assertEquals("one place declares it", 1, Regex("""SenderReceipt\.CAPABILITY""").findAll(src).count())
        assertTrue(src.contains("SenderReceipt.CAPABILITY.takeIf { SenderReceipt.implementationComplete() }"))
        assertEquals(BeamioConetChatProtocol.CAPABILITIES.size, BeamioConetChatProtocol.CAPABILITIES.toSet().size)
    }
}
