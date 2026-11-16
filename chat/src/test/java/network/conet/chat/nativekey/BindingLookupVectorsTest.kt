package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The binding lookup group (§25.52Z.3, §25.52HH, §25.52HI; vectors `bindingLookupCases` BL-01 to BL-52). Each case gives its raw outcome (or the
 * revert data, classified exactly as HH.4 says), the elapsed total, the local source and the device facts, as the vector title states them. The
 * expected code, page and creationEntered come from the vector file.
 *
 * Scope: the decision and the mapping. The live `eth_call` reader and the wiring into the native create command are not part of this check.
 */
class BindingLookupVectorsTest {
    private val doc = JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))

    private class Case(
        val kind: BindingKind,
        val raw: RawOutcome? = null,
        val data: String? = null,
        val totalMs: Long = 0L,
        val local: LocalSource = LocalSource.NONE,
        val device: BindingDevice = BindingDevice(),
    ) {
        fun rawOutcome(): RawOutcome = raw ?: RegistryMapping.classifyRevertData(data)
    }

    private val tagZero = { Case(BindingKind.TAG, raw = RawOutcome.ZERO_ADDRESS) }

    /** The inputs of each case, read from its title (BL-01 to BL-52). */
    private val inputs: Map<String, Case> = mapOf(
        "BL-01" to tagZero(),
        "BL-02" to Case(BindingKind.EOA, raw = RawOutcome.REVERT_NOT_FOUND),
        "BL-03" to Case(BindingKind.TAG, raw = RawOutcome.BOUND),
        "BL-04" to Case(BindingKind.EOA, raw = RawOutcome.BOUND),
        "BL-05" to Case(BindingKind.EOA, raw = RawOutcome.REVERT_NOT_FOUND, local = LocalSource.POSITIVE),
        "BL-06" to Case(BindingKind.EOA, raw = RawOutcome.REVERT_NOT_FOUND, local = LocalSource.POSITIVE),
        "BL-07" to Case(BindingKind.EOA, raw = RawOutcome.REVERT_NOT_FOUND, local = LocalSource.UNREADABLE),
        "BL-08" to Case(BindingKind.TAG, raw = RawOutcome.RPC_ERROR),
        "BL-09" to Case(BindingKind.EOA, raw = RawOutcome.HTTP_ERROR),
        "BL-10" to Case(BindingKind.TAG, raw = RawOutcome.TIMEOUT, totalMs = 4_000L),
        "BL-11" to Case(BindingKind.EOA, raw = RawOutcome.REVERT_OTHER),
        "BL-12" to Case(BindingKind.TAG, raw = RawOutcome.DECODE_FAILED),
        "BL-13" to Case(BindingKind.EOA, raw = RawOutcome.EXISTS_TRUE_NAME_EMPTY),
        "BL-14" to Case(BindingKind.TAG, raw = RawOutcome.SEMANTIC_FAILED),
        "BL-15" to Case(BindingKind.EOA, raw = RawOutcome.REVERT_NOT_FOUND, totalMs = 10_500L),
        "BL-16" to Case(BindingKind.TAG, raw = RawOutcome.BOUND, totalMs = 10_500L),
        "BL-17" to Case(BindingKind.TAG, raw = RawOutcome.BOUND, local = LocalSource.UNREADABLE),
        "BL-18" to Case(BindingKind.TAG, raw = RawOutcome.ZERO_ADDRESS, local = LocalSource.UNREADABLE),
        "BL-19" to Case(BindingKind.TAG, raw = RawOutcome.ZERO_ADDRESS, totalMs = 10_000L),
        "BL-20" to Case(BindingKind.TAG, raw = RawOutcome.CONNECTION_REFUSED),
        "BL-21" to Case(BindingKind.EOA, raw = RawOutcome.HTTP_ERROR),
        "BL-22" to Case(BindingKind.TAG, raw = RawOutcome.RPC_ERROR),
        "BL-23" to Case(BindingKind.EOA, raw = RawOutcome.REVERT_OTHER),
        "BL-24" to Case(BindingKind.EOA, data = "0xfaba8ebe"),
        "BL-25" to Case(BindingKind.TAG, raw = RawOutcome.TRUNCATED),
        "BL-26" to Case(BindingKind.TAG, raw = RawOutcome.DECODE_FAILED),
        "BL-27" to Case(BindingKind.TAG, raw = RawOutcome.SEMANTIC_FAILED),
        "BL-28" to Case(BindingKind.EOA, raw = RawOutcome.EXISTS_FALSE),
        "BL-29" to Case(BindingKind.TAG, raw = RawOutcome.NON_JSON),
        "BL-30" to Case(BindingKind.TAG, raw = RawOutcome.NO_RESULT),
        "BL-31" to Case(BindingKind.TAG, raw = RawOutcome.ZERO_ADDRESS, totalMs = 3_000L),
        "BL-32" to Case(BindingKind.TAG, raw = RawOutcome.RPC_ERROR, device = BindingDevice(kPresent = true, walletRecord = true)),
        "BL-33" to Case(BindingKind.EOA, raw = RawOutcome.REVERT_OTHER, local = LocalSource.POSITIVE),
        "BL-34" to Case(BindingKind.TAG, raw = RawOutcome.TIMEOUT, totalMs = 9_000L, device = BindingDevice(kPresent = true, walletRecord = true)),
        "BL-35" to Case(BindingKind.TAG, raw = RawOutcome.BOUND, totalMs = 10_500L, local = LocalSource.POSITIVE),
        "BL-36" to Case(BindingKind.EOA, data = "0xfaba8ebe" + "0".repeat(64)),
        "BL-37" to Case(BindingKind.EOA, data = "0x"),
        "BL-38" to Case(BindingKind.EOA, raw = RawOutcome.EXISTS_FALSE),
        "BL-39" to Case(BindingKind.TAG, data = "0xfaba8ebe"),
        "BL-40" to Case(BindingKind.EOA, data = "0xfaba8ebe"),
        "BL-41" to Case(BindingKind.EOA, data = "0xFABA8EBE"),
        "BL-42" to Case(BindingKind.EOA, data = "0xfaba8ebe" + "0".repeat(64)),
        "BL-43" to Case(BindingKind.EOA, data = "0x"),
        "BL-44" to Case(BindingKind.EOA, data = null),
        "BL-45" to Case(BindingKind.EOA, data = "0x08c379a0" + "00".repeat(36)),
        "BL-46" to Case(BindingKind.EOA, data = "0xfaba8eb"),
        "BL-47" to Case(BindingKind.EOA, data = "0xfaba8ebf"),
        "BL-48" to Case(BindingKind.EOA, data = "0xfaba8ebe00"),
        "BL-49" to Case(BindingKind.TAG, data = "0xfaba8ebe"),
        "BL-50" to Case(BindingKind.TAG, raw = RawOutcome.ZERO_ADDRESS, device = BindingDevice(kPresent = true, walletRecord = false)),
        "BL-51" to Case(BindingKind.TAG, raw = RawOutcome.BOUND, device = BindingDevice(kPresent = true, walletRecord = false)),
        "BL-52" to Case(BindingKind.TAG, raw = RawOutcome.RPC_ERROR, device = BindingDevice(kPresent = true, walletRecord = true)),
    )

    @Test
    fun theBindingGroupHasFiftyTwoCasesAndEachHasAnInput() {
        val list = doc.getJSONArray("bindingLookupCases")
        assertEquals(52, list.length())
        val ids = (0 until list.length()).map { list.getJSONObject(it).getString("id") }
        assertEquals(ids.toSet(), inputs.keys)
    }

    @Test
    fun everyBindingCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("bindingLookupCases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            val id = c.getString("id")
            val input = inputs.getValue(id)
            val expect = c.getJSONObject("expect")
            val got = BindingDecision.decide(input.kind, input.rawOutcome(), input.totalMs, input.local, input.device)
            val wantCode = expect.getString("code")
            val wantPage = expect.getString("page")
            val wantEnter = expect.optBoolean("creationEntered", false)
            if (got.wire != wantCode) failures += "$id code ${got.wire} != $wantCode"
            if (got.page != wantPage) failures += "$id page ${got.page} != $wantPage"
            if (got.creationEntered != wantEnter) failures += "$id creationEntered ${got.creationEntered} != $wantEnter"
        }
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun theTotalBudgetIsTenSecondsAndEachReadIsCappedAtFourSeconds() {
        assertEquals(10_000L, RegistryBudget.TOTAL_MS)
        assertEquals(4_000L, RegistryBudget.PER_CALL_MS)
        val deadline = RegistryBudget.deadlineFrom(1_000L)
        assertEquals(11_000L, deadline)
        assertEquals(4_000L, RegistryBudget.perCallTimeout(deadline, 1_000L))
        assertEquals(2_000L, RegistryBudget.perCallTimeout(deadline, 9_000L))
        assertEquals(null, RegistryBudget.perCallTimeout(deadline, 11_000L))
        assertTrue(RegistryBudget.perCallTimeout(deadline, 12_000L) == null)
    }
}
