package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The bridge answers of the derivation commands (W2 to W4, C5, W7 and the C1 refusal) against `spec/derivation-vectors.v1.json`.
 * Each answer is compared with the vector, and each answer is checked for the values that must never cross the bridge.
 */
class NativeDerivationCommandsTest {
    private val doc = JSONObject(
        String(File(System.getenv("DERIVATION_VECTORS") ?: "../spec/derivation-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val inputs = doc.getJSONObject("inputs")
    private val pHex = inputs.getString("P")
    private val p = ByteArray(32) { pHex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private val eoa = inputs.getString("eoa")
    private val accountKey = eoa + ":default"
    private val cases: Map<String, JSONObject> = doc.getJSONArray("cases").let { arr ->
        (0 until arr.length()).associate { arr.getJSONObject(it).getString("id") to arr.getJSONObject(it).getJSONObject("expect") }
    }

    @After
    fun clearVoiceKeys() {
        VoiceChannelKeys.clear()
    }

    private fun keysOf(o: JSONObject): Set<String> = o.keys().asSequence().map { it.toString() }.toSet()

    /** The values that must never cross the bridge: the account key, R_db and R_proto (N-01). */
    private fun assertNoRoot(result: JSONObject) {
        val text = result.toString()
        assertFalse("P crosses the bridge", text.contains(pHex))
        assertFalse("R_db crosses the bridge", text.contains(cases.getValue("D-06").getString("RDB")))
        assertFalse("R_proto crosses the bridge", text.contains(cases.getValue("D-01").getString("RPROTO")))
    }

    @Test
    fun c5DeriveSubkeysReturnsExactlyTheFourChildren() {
        val out = NativeDerivationCommands.deriveSubkeys(p, accountKey, eoa)
        assertTrue(out.ok)
        val r = out.result!!
        assertEquals(setOf("kId", "kIdx", "dek", "kcv"), keysOf(r))
        val d7 = cases.getValue("D-07")
        assertEquals(d7.getString("kId"), r.getString("kId"))
        assertEquals(d7.getString("kIdx"), r.getString("kIdx"))
        assertEquals(d7.getString("dek"), r.getString("dek"))
        assertEquals(d7.getString("kcv"), r.getString("kcv"))
        assertNoRoot(r)
    }

    @Test
    fun w2DeriveLocalKeysReturnsDekKIdxKId() {
        val out = NativeDerivationCommands.deriveLocalKeys(p, accountKey, eoa)
        val r = out.result!!
        assertEquals(setOf("DEK", "K_idx", "K_id"), keysOf(r))
        assertEquals(cases.getValue("D-07").getString("dek"), r.getString("DEK"))
        assertEquals(cases.getValue("D-07").getString("kIdx"), r.getString("K_idx"))
        assertEquals(cases.getValue("D-07").getString("kId"), r.getString("K_id"))
        assertNoRoot(r)
    }

    @Test
    fun w3ProtocolKeysReturnsTheIndexKeyAndTheGenesisCid() {
        val r = NativeDerivationCommands.protocolKeys(p, accountKey, eoa).result!!
        assertEquals(setOf("indexEncKey", "genesisCid"), keysOf(r))
        assertEquals(cases.getValue("D-02").getString("indexEncKey"), r.getString("indexEncKey"))
        assertEquals(cases.getValue("D-03").getString("genesisCid"), r.getString("genesisCid"))
        assertNoRoot(r)
    }

    @Test
    fun w4FragmentKeysMatchTheVectorsForTheGenesisAndTheNextFragment() {
        val genesis = cases.getValue("D-03").getString("genesisCid")
        val next = cases.getValue("D-05").getString("prevCid")
        val batch = JSONArray()
            .put(JSONObject().put("seq", 0).put("prevCid", genesis))
            .put(JSONObject().put("seq", 1).put("prevCid", next))
        val r = NativeDerivationCommands.fragmentKeys(p, accountKey, batch, eoa).result!!
        val keys = r.getJSONArray("fragKeys")
        assertEquals(2, keys.length())
        assertEquals(cases.getValue("D-04").getString("fragKey"), keys.getJSONObject(0).getString("fragKey"))
        assertEquals(cases.getValue("D-05").getString("fragKey"), keys.getJSONObject(1).getString("fragKey"))
        assertNoRoot(r)
    }

    @Test
    fun w4RefusesABatchOutsideOneToSixtyFour() {
        assertEquals(NativeDerivationCommands.BAD_REQUEST, NativeDerivationCommands.fragmentKeys(p, accountKey, null, eoa).error)
        assertEquals(NativeDerivationCommands.BAD_REQUEST, NativeDerivationCommands.fragmentKeys(p, accountKey, JSONArray(), eoa).error)
        val tooMany = JSONArray()
        repeat(NativeDerivationCommands.MAX_BATCH + 1) { tooMany.put(JSONObject().put("seq", it).put("prevCid", "c")) }
        assertEquals(NativeDerivationCommands.BAD_REQUEST, NativeDerivationCommands.fragmentKeys(p, accountKey, tooMany, eoa).error)
    }

    @Test
    fun w4RefusesABadSeqOrAnEmptyPrevCid() {
        val negative = JSONArray().put(JSONObject().put("seq", -1).put("prevCid", "c"))
        val empty = JSONArray().put(JSONObject().put("seq", 0).put("prevCid", ""))
        assertEquals(NativeDerivationCommands.BAD_REQUEST, NativeDerivationCommands.fragmentKeys(p, accountKey, negative, eoa).error)
        assertEquals(NativeDerivationCommands.BAD_REQUEST, NativeDerivationCommands.fragmentKeys(p, accountKey, empty, eoa).error)
    }

    @Test
    fun theAccountKeyMustBeTheVaultsLowerCaseAccountInTheDefaultWorkspace() {
        assertEquals(NativeDerivationCommands.ACCOUNT_MISMATCH, NativeDerivationCommands.deriveSubkeys(p, "0x" + "1".repeat(40) + ":default", eoa).error)
        assertEquals(NativeDerivationCommands.BAD_REQUEST, NativeDerivationCommands.deriveSubkeys(p, eoa.uppercase() + ":default", eoa).error)
        assertEquals(NativeDerivationCommands.BAD_REQUEST, NativeDerivationCommands.deriveSubkeys(p, "$eoa:work", eoa).error)
        assertEquals(NativeDerivationCommands.BAD_REQUEST, NativeDerivationCommands.deriveSubkeys(p, eoa, eoa).error)
    }

    @Test
    fun w7ReturnsTheTemporaryAddressAndTheVectorSignature() {
        val tk = ByteArray(32) { 0x5a }
        val w = cases.getValue("W-01")
        VoiceChannelKeys.register(inputs.getString("sid"), tk)
        val body = JSONObject()
            .put("sid", inputs.getString("sid"))
            .put("wk", inputs.getString("wk"))
            .put("relayKeyId", inputs.getString("relayKeyId"))
            .put("timestamp", inputs.getLong("timestamp"))
        val out = NativeDerivationCommands.ephemeralSign(body)
        assertTrue(out.ok)
        assertEquals(setOf("temp", "tempSig"), keysOf(out.result!!))
        assertEquals(w.getString("temp"), out.result!!.getString("temp"))
        assertEquals(w.getString("tempSig"), out.result!!.getString("tempSig"))
    }

    @Test
    fun w7RefusesABadSidAndAnUnknownChannel() {
        val body = JSONObject()
            .put("sid", "0123456789ABCDEF0123456789ABCDEF")
            .put("wk", inputs.getString("wk"))
            .put("relayKeyId", "k")
            .put("timestamp", 1L)
        assertEquals(NativeDerivationCommands.BAD_REQUEST, NativeDerivationCommands.ephemeralSign(body).error)
        val unknown = JSONObject(body.toString()).put("sid", inputs.getString("sid"))
        assertEquals(NativeDerivationCommands.UNKNOWN_CHANNEL, NativeDerivationCommands.ephemeralSign(unknown).error)
        val stringTime = JSONObject(unknown.toString()).put("timestamp", "1762992000")
        assertEquals(NativeDerivationCommands.BAD_REQUEST, NativeDerivationCommands.ephemeralSign(stringTime).error)
    }

    @Test
    fun aDerivationRefusalCarriesNoResult() {
        val out = NativeDerivationCommands.Outcome.fail(NativeDerivationCommands.NOT_SUPPORTED)
        assertNull(out.result)
        assertFalse(out.ok)
    }
}
