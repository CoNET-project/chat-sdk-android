package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * `spec/identity-public-vectors.v1.json` (spec r3ae §25.48): the 13 cases for `identityPublic`. Each case sets the gate from its
 * state (a locked G2 is still G2), gives the decision the native public facts the case describes, and compares the ack with
 * the vector. The payload is read only in G2.
 */
class IdentityPublicVectorsTest {
    private val bytes = File(System.getenv("IDENTITY_PUBLIC_VECTORS") ?: "../spec/identity-public-vectors.v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))
    private val cases = v.getJSONArray("cases")

    private val accountEoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
    private val publicArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-public-only\n-----END PGP PUBLIC KEY BLOCK-----"

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun caseOf(id: String): JSONObject {
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("id") == id) return c
        }
        error("no case $id")
    }

    private fun gateFor(state: String): NoKeyGate.Gate = when (state) {
        "G0" -> NoKeyGate.Gate.G0
        "G1" -> NoKeyGate.Gate.G1
        "G2" -> NoKeyGate.Gate.G2
        else -> error("unknown state $state")
    }

    /**
     * The native facts a case describes. The PGP part is present only with `pgp`, and then `pgpReady` needs the route key too
     * (IP-03 has a PGP key and no route key, so it is not ready).
     */
    private fun sourceFor(env: JSONObject): IdentityPublic.Source {
        val pgp = if (env.optBoolean("pgp")) {
            IdentityPublic.PgpPublic(
                keyId = "syn-pgp-key-0001",
                publicArmor = publicArmor,
                routeArmor = if (env.optBoolean("route")) "synthetic-route-public-0001" else "",
            )
        } else {
            null
        }
        return object : IdentityPublic.Source {
            override fun eoa(): String? = accountEoa
            override fun pgp(): IdentityPublic.PgpPublic? = pgp
        }
    }

    /** The ack the decision gives for one case's call. */
    private fun run(c: JSONObject): JSONObject {
        val env = c.getJSONObject("env")
        val req = c.getJSONArray("steps").getJSONObject(0).getJSONObject("req")
        val reqId = PgpDecryptInbound.reqIdOf(req)
        val reply = IdentityPublic.answer(
            gateFor(env.getString("state")),
            { req.keys().asSequence().map { it.toString() }.toList() },
            reqId,
            sourceFor(env),
        )
        return IdentityPublic.ackPayload(reqId, reply)
    }

    @Test
    fun vectorFileIsTheCanonicalOne() {
        assertEquals("478d2a7d0ccad18e586a71f057738cc58616cfbaf8f233684f7c10afdbdee095", sha256Hex(bytes))
    }

    @Test
    fun caseCountsMatchTheVector() {
        assertEquals(13, cases.length())
        assertEquals(13, v.getJSONObject("counts").getInt("cases"))
        for ((group, n) in listOf("A" to 5, "B" to 4, "C" to 4)) {
            assertEquals(group, n, (0 until cases.length()).count { cases.getJSONObject(it).getString("group") == group })
        }
    }

    @Test
    fun theNamesAreTheCanonicalAndBridgeNames() {
        val names = v.getJSONObject("names")
        assertEquals("identity.public", names.getString("canonical"))
        assertEquals("identityPublic", names.getString("bridge"))
    }

    @Test
    fun everyCaseMatchesTheVector() {
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val want = c.getJSONArray("expect").getJSONObject(0).getJSONObject("detail").getJSONObject("event")
            assertSameJson(id, want, run(c))
        }
    }

    /** The same keys and the same values, nested objects included. The org.json build here has no `similar`. */
    private fun assertSameJson(id: String, want: JSONObject, got: JSONObject) {
        val wantKeys = want.keys().asSequence().map { it.toString() }.toSet()
        val gotKeys = got.keys().asSequence().map { it.toString() }.toSet()
        assertEquals("$id keys", wantKeys, gotKeys)
        for (k in wantKeys) {
            val w = want.get(k)
            val g = got.get(k)
            if (w is JSONObject && g is JSONObject) {
                assertSameJson("$id.$k", w, g)
            } else {
                assertEquals("$id $k", w.toString(), g.toString())
            }
        }
    }

    @Test
    fun aSuccessfulResultCarriesOnlyThePublicFields() {
        // The result of every ok case: no forbidden key (§25.48.5), and the account key is eoa:default.
        val forbidden = v.getJSONArray("forbiddenResultKeys")
        for (id in listOf("IP-01", "IP-02", "IP-03", "IP-04", "IP-12")) {
            val result = run(caseOf(id)).getJSONObject("result")
            for (f in 0 until forbidden.length()) {
                assertFalse("$id carries ${forbidden.getString(f)}", result.has(forbidden.getString(f)))
            }
            assertEquals(id, accountEoa + ":default", result.getString("accountKey"))
        }
    }

    @Test
    fun aRejectedCallCarriesNoResult() {
        for (id in listOf("IP-05", "IP-06", "IP-07", "IP-08", "IP-09", "IP-10", "IP-11", "IP-13")) {
            assertFalse(id, run(caseOf(id)).has("result"))
        }
    }

    @Test
    fun theGateAnswersBeforeThePayloadIsRead() {
        // G0 and G1 never read the field names: a payload that would throw on read still gets no_key or not_ready.
        val poisoned = { error("the payload was read") }
        assertEquals(IdentityPublic.NO_KEY, IdentityPublic.answer(NoKeyGate.Gate.G0, poisoned, "x", sourceFor(JSONObject())).error)
        assertEquals(IdentityPublic.NOT_READY, IdentityPublic.answer(NoKeyGate.Gate.G1, poisoned, "x", sourceFor(JSONObject())).error)
    }

    @Test
    fun theCredentialFieldListIsTheVectorList() {
        val want = v.getJSONArray("credentialFields")
        assertEquals(want.length(), IdentityPublic.CREDENTIAL_FIELDS.size)
        for (i in 0 until want.length()) {
            val field = want.getString(i)
            assertTrue(field, field in IdentityPublic.CREDENTIAL_FIELDS)
            val reply = IdentityPublic.answer(
                NoKeyGate.Gate.G2,
                { listOf("type", "reqId", field) },
                "x",
                sourceFor(JSONObject().put("pgp", true).put("route", true)),
            )
            assertEquals(field, IdentityPublic.KEY_REFUSED, reply.error)
            assertEquals(field, field, reply.refused)
        }
    }

    @Test
    fun theCommandIsNotOnTheAllowedListAndIsNotRoutedAsPass() {
        assertEquals(NoKeyGate.Route.NO_KEY, NoKeyGate.route("identityPublic"))
        assertFalse(NoKeyGate.route("identityPublic") == NoKeyGate.Route.PASS)
    }
}
