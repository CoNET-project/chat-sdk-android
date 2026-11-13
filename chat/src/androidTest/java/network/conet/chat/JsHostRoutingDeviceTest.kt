package network.conet.chat

import androidx.test.platform.app.InstrumentationRegistry
import network.conet.chat.nativekey.NativePgpKeyGen
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Host WebView routing on a real Chromium WebView. Encrypt and entry wrap must complete through `postResult`:
 * on Chromium 124 the `evaluateJavascript` return is `{}` for these async scripts, and the old code reported
 * `encrypt_fail` from that return. Synthetic keys from the restore acceptance vectors only. No account, no network,
 * and no key or armor is printed; the checks compare outcomes.
 */
class JsHostRoutingDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val assets = InstrumentationRegistry.getInstrumentation().context.assets
    private val host = BeamioOpenPgpHost.shared(context)

    private val publicP3: String
    private val publicP4: String

    init {
        val doc = JSONObject(
            assets.open("pgp-restore-acceptance-vectors.v1.json").bufferedReader(Charsets.UTF_8).use { it.readText() },
        )
        val keys = doc.getJSONObject("syntheticKeys")
        publicP3 = NativePgpKeyGen.publicArmorOf(keys.getJSONObject("P3").getString("privateArmor"))!!
        publicP4 = NativePgpKeyGen.publicArmorOf(keys.getJSONObject("P4").getString("privateArmor"))!!
    }

    /** Runs one host call and waits for its single answer (the host's callback), up to 40 s. */
    private fun <T> answer(call: ((Result<T>) -> Unit) -> Unit): Result<T> {
        val ref = AtomicReference<Result<T>?>(null)
        val latch = CountDownLatch(1)
        call { r ->
            ref.set(r)
            latch.countDown()
        }
        assertTrue("no answer within 40 s", latch.await(40, TimeUnit.SECONDS))
        return ref.get()!!
    }

    private fun innerTo(publicArmor: String): String {
        val r = answer<String> { cb -> host.encryptToRoute(publicArmor, """{"text":"synthetic"}""", cb) }
        assertTrue("encrypt_to_route failed: ${r.exceptionOrNull()?.message}", r.isSuccess)
        return r.getOrNull()!!
    }

    @Test
    fun encryptToRouteCompletesThroughPostResult() {
        val r = answer<String> { cb -> host.encryptToRoute(publicP3, """{"text":"synthetic"}""", cb) }
        assertTrue("encrypt_to_route failed: ${r.exceptionOrNull()?.message}", r.isSuccess)
        assertTrue(r.getOrNull()!!.contains("BEGIN PGP MESSAGE"))
    }

    @Test
    fun wrapToAnotherEntryKeyCompletesThroughPostResult() {
        val inner = innerTo(publicP3)
        val r = answer<String> { cb -> host.wrapArmorToEntryRoute(inner, publicP4, cb) }
        assertTrue("wrap failed: ${r.exceptionOrNull()?.message}", r.isSuccess)
        val outer = r.getOrNull()!!
        assertTrue(outer.contains("BEGIN PGP MESSAGE"))
        assertFalse("wrap must not return the inner armor unchanged", outer == inner)
    }

    @Test
    fun wrapToTheInnerRecipientIsAFailureNotTheUnwrappedArmor() {
        val inner = innerTo(publicP3)
        val r = answer<String> { cb -> host.wrapArmorToEntryRoute(inner, publicP3, cb) }
        assertTrue("same-node wrap must fail", r.isFailure)
        assertEquals("same_node_entry", r.exceptionOrNull()!!.message)
    }

    @Test
    fun wrapOfNonPgpTextFailsWithoutCallingTheWebView() {
        val r = answer<String> { cb -> host.wrapArmorToEntryRoute("plain text", publicP4, cb) }
        assertTrue(r.isFailure)
        assertEquals("not_pgp_armor", r.exceptionOrNull()!!.message)
    }

    @Test
    fun wrapToAnEntryWithoutKeyFails() {
        val inner = innerTo(publicP3)
        val r = answer<String> { cb -> host.wrapArmorToEntryRoute(inner, "", cb) }
        assertTrue(r.isFailure)
        assertEquals("no_entry_key", r.exceptionOrNull()!!.message)
    }
}
