package network.conet.chat.nativekey

import network.conet.chat.BeamioConetChatProtocol
import network.conet.chat.BuildConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Capability identity.kpresent.v1 (spec 25.52X.5, 25.52Y.90; coordinator ruling on c7b4fea): the hello answer declares it, because the G0
 * `no_key` answer carries kPresent. The name is checked in the declared list and in the answer itself.
 */
class KPresentCapabilityTest {
    @Test
    fun helloDeclaresIdentityKPresentV1() {
        assertEquals("identity.kpresent.v1", BeamioConetChatProtocol.KPRESENT_CAPABILITY)
        assertTrue("declared in CAPABILITIES", BeamioConetChatProtocol.CAPABILITIES.contains("identity.kpresent.v1"))
        val caps = BeamioConetChatProtocol.helloResult().getJSONArray("capabilities")
        val names = (0 until caps.length()).map { caps.getString(it) }
        assertTrue("hello answer carries identity.kpresent.v1", names.contains("identity.kpresent.v1"))
    }

    @Test
    fun theNativeKeysCapabilityIsNotDeclaredByTheKPresentChange() {
        // identity.native-keys.v1 stays QA-only (BuildConfig); declaring kPresent does not declare it.
        assertEquals(BuildConfig.NATIVE_KEYS_QA, BeamioConetChatProtocol.CAPABILITIES.contains("identity.native-keys.v1"))
    }
}
