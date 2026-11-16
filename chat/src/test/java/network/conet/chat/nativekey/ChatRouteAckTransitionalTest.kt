package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Y.73 第 2、3 项: the transitional allowance for chatRouteRegister's four-field ack. These checks run while the allowance stands.
 * - The ack carries exactly the eight registration keys, no more and no fewer (a field added to the ack breaks this).
 * - The allowance is named Y.73-transitional in the audit list, so it cannot be mistaken for a permanent exemption.
 * The expiry itself (both shells shipping the submitted branch, or the first formal package with it) is a release action; it cannot be read from source,
 * so the release that expires it must delete the entry and the ack field together. Rule-level; no vector claim.
 */
class ChatRouteAckTransitionalTest {
    private val eightKeys = setOf("wallet", "keyID", "publicKeyArmored", "encrypKeyArmored", "routeKeyID", "timestamp", "nonce", "signature")

    private fun moduleSource(): String {
        val f = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt")
        return f.readText(Charsets.UTF_8)
    }

    @Test
    fun theAckCarriesExactlyTheEightRegistrationKeys() {
        val src = moduleSource()
        val start = src.indexOf("private fun chatRouteRegisterCommand(")
        val end = src.indexOf("private fun pgpIdentityCreateWaiting(")
        assertTrue("the handler is found", start >= 0 && end > start)
        val body = src.substring(start, end)
        val keys = Regex("""\.put\("([A-Za-z]+)",\s*built\.""").findAll(body).map { it.groupValues[1] }.toSet()
        assertEquals("the ack's result keys", eightKeys, keys)
    }

    @Test
    fun theAllowanceIsNamedAsTransitionalInTheAuditList() {
        val audit = File("src/test/java/network/conet/chat/identity/BridgeKeyAuditTest.kt").readText(Charsets.UTF_8)
        assertTrue("Y.73-transitional is named at the entry", audit.contains("Y.73-transitional"))
        assertTrue("the expiry condition is written at the entry", audit.contains("expiry:"))
    }
}
