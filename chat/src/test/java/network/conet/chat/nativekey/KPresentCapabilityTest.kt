package network.conet.chat.nativekey

import network.conet.chat.BeamioConetChatProtocol
import network.conet.chat.BuildConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Capability identity.kpresent.v1 (spec 25.52X.5). Retracted (coordinator ruling on 8ff45ab): hello does not declare it until `already_exists`
 * carries the eoa on every path, including the import page, which has no SDK event yet.
 */
class KPresentCapabilityTest {
    @Test
    fun helloDoesNotDeclareIdentityKPresentV1UntilTheImportPathCarriesTheEoa() {
        assertEquals("identity.kpresent.v1", BeamioConetChatProtocol.KPRESENT_CAPABILITY)
        assertFalse("not declared in CAPABILITIES", BeamioConetChatProtocol.CAPABILITIES.contains("identity.kpresent.v1"))
        val caps = BeamioConetChatProtocol.helloResult().getJSONArray("capabilities")
        val names = (0 until caps.length()).map { caps.getString(it) }
        assertFalse("hello answer does not carry identity.kpresent.v1", names.contains("identity.kpresent.v1"))
    }

    @Test
    fun theNativeKeysCapabilityIsNotDeclaredByTheKPresentChange() {
        // identity.native-keys.v1 stays QA-only (BuildConfig); declaring kPresent does not declare it.
        assertEquals(BuildConfig.NATIVE_KEYS_QA, BeamioConetChatProtocol.CAPABILITIES.contains("identity.native-keys.v1"))
    }
}
