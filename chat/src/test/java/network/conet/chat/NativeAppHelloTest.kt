package network.conet.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The `nativeApp` field of the hello answer (v156 §176.2–176.4). The format vectors are the spec's: two valid and six invalid. The PackageManager read
 * (`readHostNativeApp`) needs a device; it is verified on the Android shell, not on the JVM.
 */
class NativeAppHelloTest {
    @Test
    fun theSpecValidExamplesAreAccepted() {
        assertNotNull(BeamioConetChatProtocol.nativeAppOf("ios", "1.5.8", "105"))
        val android = BeamioConetChatProtocol.nativeAppOf("android", "1.0.165", "184")
        assertNotNull(android)
        assertEquals("android", android!!.getString("platform"))
        assertEquals("1.0.165", android.getString("version"))
        assertEquals("184", android.getString("build"))
    }

    @Test
    fun theSpecInvalidExamplesGiveNoNativeApp() {
        assertNull("missing version", BeamioConetChatProtocol.nativeAppOf("android", "", "184"))
        assertNull("more than three segments", BeamioConetChatProtocol.nativeAppOf("ios", "1.5.8.1.2", "105"))
        assertNull("a leading v", BeamioConetChatProtocol.nativeAppOf("ios", "v1.5.8", "105"))
        assertNull("a non-digit build", BeamioConetChatProtocol.nativeAppOf("android", "1.0.165", "10a"))
        assertNull("an unknown platform", BeamioConetChatProtocol.nativeAppOf("web", "1.5.8", "105"))
        assertNull("a null build", BeamioConetChatProtocol.nativeAppOf("android", "1.0.165", null))
    }

    @Test
    fun helloCarriesNativeAppOnlyWhenItIsValid() {
        val valid = BeamioConetChatProtocol.nativeAppOf("android", "1.0.165", "184")
        val withApp = BeamioConetChatProtocol.helloResult(valid)
        assertEquals("android", withApp.getJSONObject("nativeApp").getString("platform"))
        assertEquals("184", withApp.getJSONObject("nativeApp").getString("build"))
        // No valid value: the field is absent, so the shell treats the host as old (v156 §176.1).
        assertFalse(BeamioConetChatProtocol.helloResult(null).has("nativeApp"))
        assertFalse(BeamioConetChatProtocol.helloResult(BeamioConetChatProtocol.nativeAppOf("web", "1", "1")).has("nativeApp"))
    }

    @Test
    fun theNativeAppIsNotTheSdkVersion() {
        // The version comes from the host package, not the SDK constant (v156 §176.3).
        val host = BeamioConetChatProtocol.nativeAppOf("android", "9.9.9", "42")!!
        assertTrue(host.getString("version") != BeamioConetChatProtocol.SDK_VERSION)
        assertEquals("9.9.9", host.getString("version"))
    }
}
