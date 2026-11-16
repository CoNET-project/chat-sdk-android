package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The binding lookup group (§25.52Z.3, §25.52HH, §25.52HI, §25.52Y.58; vectors `bindingLookupCases`). Each case carries machine-readable inputs:
 * `ctx` (the path, the query kind, the lookup result, the elapsed total, the endpoint), `local` (the wallet key, the ACTIVE and non-ACTIVE K, and
 * whether a local read failed), and `expected` (code, page, creationEntered). The harness reads only these fields.
 */
class BindingLookupVectorsTest {
    private val doc = JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))

    /** The raw outcome a `lookupResult` names, for the query kind. Only the vocabulary of the vector file is accepted. */
    private fun rawOf(kind: BindingKind, result: String): RawOutcome = when (result) {
        "absent_exact" -> if (kind == BindingKind.EOA) RawOutcome.REVERT_NOT_FOUND else RawOutcome.REVERT_NOT_FOUND
        "empty" -> RawOutcome.ZERO_ADDRESS
        "bound" -> RawOutcome.BOUND
        "revert" -> RawOutcome.REVERT_OTHER
        "revert_args" -> RawOutcome.REVERT_WITH_ARGS
        "revert_empty" -> RawOutcome.REVERT_EMPTY
        "success_exists_false" -> RawOutcome.EXISTS_FALSE
        "semantic_invalid" -> RawOutcome.SEMANTIC_FAILED
        "rpc_error" -> RawOutcome.RPC_ERROR
        "http_error" -> RawOutcome.HTTP_ERROR
        "timeout" -> RawOutcome.TIMEOUT
        "connection_refused" -> RawOutcome.CONNECTION_REFUSED
        "truncated" -> RawOutcome.TRUNCATED
        "undecodable", "invalid_response" -> RawOutcome.DECODE_FAILED
        "non_json" -> RawOutcome.NON_JSON
        "no_result" -> RawOutcome.NO_RESULT
        else -> throw IllegalArgumentException("unknown lookupResult $result")
    }

    private fun kindOf(q: String): BindingKind = when (q) {
        "eoa" -> BindingKind.EOA
        "tag" -> BindingKind.TAG
        else -> throw IllegalArgumentException("unknown queryKind $q")
    }

    private fun bindingOf(c: JSONObject): Pair<LocalSource, BindingDevice> {
        val local = c.getJSONObject("local")
        return BindingLocalSources.of(
            keyReady = local.getBoolean("walletKey"),
            vaultUnreadable = false,
            kActive = local.getBoolean("kActive"),
            kNonActive = local.getBoolean("kNonActive"),
            kUnreadable = local.getBoolean("readFailed"),
            kPresent = local.getBoolean("kPresent"),
        )
    }

    @Test
    fun theBindingGroupHasFiftyFourCasesEachWithMachineReadableInputs() {
        val list = doc.getJSONArray("bindingLookupCases")
        assertEquals(54, list.length())
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            assertTrue(c.has("ctx") && c.has("local") && c.has("expected"))
        }
    }

    @Test
    fun everyBindingCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("bindingLookupCases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            val id = c.getString("id")
            val ctx = c.getJSONObject("ctx")
            val expected = c.getJSONObject("expected")
            val kind = kindOf(ctx.getString("queryKind"))
            val raw = rawOf(kind, ctx.getString("lookupResult"))
            val (local, device) = bindingOf(c)
            val got = BindingDecision.decide(kind, raw, ctx.getLong("totalMs"), local, device)
            if (got.wire != expected.getString("code")) failures += "$id code ${got.wire} != ${expected.getString("code")}"
            if (got.page != expected.getString("page")) failures += "$id page ${got.page} != ${expected.getString("page")}"
            if (got.creationEntered != expected.getBoolean("creationEntered")) {
                failures += "$id creationEntered ${got.creationEntered} != ${expected.getBoolean("creationEntered")}"
            }
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
    }
}
