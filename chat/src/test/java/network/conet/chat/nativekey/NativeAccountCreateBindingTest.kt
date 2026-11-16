package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The binding lookup of `nativeAccountCreateOpen` (§25.52Z.3, R1487). Each row is the table's answer: the ack, the result, and whether the page opened.
 * The host is a fake: it records whether it was asked to open.
 */
class NativeAccountCreateBindingTest {

    private class FakeHost(private val opens: Boolean = true) : NativeOpenRules.Host {
        var openCalls = 0
        override fun registered(): Boolean = true
        override fun open(reqId: Any): Boolean {
            openCalls++
            return opens
        }
    }

    private val account = "alice"
    private val fields = listOf("type", "reqId", "account")
    private val gate = NoKeyGate.Gate.G0

    private fun run(binding: BindingCode?, host: FakeHost): NativeOpenRules.Reply =
        NativeOpenRules.accountCreateOpen(
            fields,
            "B-1",
            account,
            gate,
            host,
            guardDenial = null,
            binding = binding?.let { code -> { code } },
        )

    @Test
    fun alreadyBoundAnswersOkWithPageNoneAndTheResultWithoutOpening() {
        val host = FakeHost()
        val r = run(BindingCode.ALREADY_BOUND, host)
        assertEquals(true, r.ok)
        assertEquals("none", r.page)
        assertEquals("already_bound", r.result)
        assertEquals(0, host.openCalls)
    }

    @Test
    fun aFailedLookupAnswersOkWithPageNoneAndLookupUnavailableWithoutOpening() {
        val host = FakeHost()
        val r = run(BindingCode.LOOKUP_UNAVAILABLE, host)
        assertEquals(true, r.ok)
        assertEquals("none", r.page)
        assertEquals("lookup_unavailable", r.result)
        assertEquals(0, host.openCalls)
    }

    @Test
    fun aConfirmedAbsenceOpensThePageAndCarriesNoResult() {
        val host = FakeHost()
        val r = run(BindingCode.CREATE, host)
        assertEquals(true, r.ok)
        assertEquals("opened", r.page)
        assertNull(r.result)
        assertEquals(1, host.openCalls)
    }

    @Test
    fun aHostThatRefusesTheConfirmedAbsenceAnswersNotAvailable() {
        val host = FakeHost(opens = false)
        val r = run(BindingCode.CREATE, host)
        assertEquals("not_available", r.error)
        assertNull(r.result)
    }

    @Test
    fun withoutALookupTheCreateChecksAreUnchanged() {
        val host = FakeHost()
        val r = run(null, host)
        assertEquals("opened", r.page)
        assertEquals(1, host.openCalls)
    }
}
