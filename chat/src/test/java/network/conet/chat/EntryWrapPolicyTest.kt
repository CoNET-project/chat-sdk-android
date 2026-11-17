package network.conet.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Entry-route wrap outcomes on the JVM. Every failure is a failure result; none yields the unwrapped inner armor.
 * Synthetic armor bodies only.
 */
class EntryWrapPolicyTest {
    private val inner = "-----BEGIN PGP MESSAGE-----\nINNER\n-----END PGP MESSAGE-----"
    private val outer = "-----BEGIN PGP MESSAGE-----\nOUTER\n-----END PGP MESSAGE-----"
    private val entryKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nENTRY\n-----END PGP PUBLIC KEY BLOCK-----"

    @Test
    fun preflightRefusesInputThatCannotBeWrapped() {
        assertEquals("not_pgp_armor", EntryWrapPolicy.preflight("plain text", entryKey))
        assertEquals("no_entry_key", EntryWrapPolicy.preflight(inner, ""))
        assertEquals("no_entry_key", EntryWrapPolicy.preflight(inner, "-----BEGIN PGP MESSAGE-----"))
        assertNull(EntryWrapPolicy.preflight(inner, entryKey))
    }

    @Test
    fun aRejectedWrapIsAFailureWithItsCode() {
        val r = EntryWrapPolicy.outcome(JsJsonResult(ok = false, error = "same_node_entry"), inner)
        assertTrue(r.isFailure)
        assertEquals("same_node_entry", r.exceptionOrNull()!!.message)
    }

    @Test
    fun aRejectedWrapWithoutACodeIsAFailure() {
        val r = EntryWrapPolicy.outcome(JsJsonResult(ok = false), inner)
        assertTrue(r.isFailure)
        assertEquals("wrap_fail", r.exceptionOrNull()!!.message)
    }

    @Test
    fun aTimeoutIsAFailureNotTheInnerArmor() {
        val r = EntryWrapPolicy.outcome(JsJsonResult(ok = false, error = "js_bridge_timeout"), inner)
        assertTrue(r.isFailure)
        assertEquals("js_bridge_timeout", r.exceptionOrNull()!!.message)
    }

    @Test
    fun anOkAnswerWithoutArmorIsAFailure() {
        val r = EntryWrapPolicy.outcome(JsJsonResult(ok = true, armor = ""), inner)
        assertTrue(r.isFailure)
        assertEquals("wrap_no_armor", r.exceptionOrNull()!!.message)
    }

    @Test
    fun anOkAnswerThatReturnsTheInnerArmorUnchangedIsAFailure() {
        val r = EntryWrapPolicy.outcome(JsJsonResult(ok = true, armor = inner), inner)
        assertTrue(r.isFailure)
        assertEquals("wrap_unchanged", r.exceptionOrNull()!!.message)
    }

    @Test
    fun anOkAnswerWithAWrappedArmorIsASuccess() {
        val r = EntryWrapPolicy.outcome(JsJsonResult(ok = true, armor = outer), inner)
        assertTrue(r.isSuccess)
        assertEquals(outer, r.getOrNull())
    }
}
