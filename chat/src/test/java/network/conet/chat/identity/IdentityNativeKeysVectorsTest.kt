package network.conet.chat.identity

import network.conet.chat.identity.IdentityProvisionContract.NativeKeyState
import network.conet.chat.identity.IdentityProvisionContract.Result
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * identity.native-keys.v1 against `spec/identity-native-keys-vectors.v1.json` (batch 17, sha256 0dea5599…).
 * Synthetic material only. Checks the request rules, the ready mapping and the response keys.
 */
class IdentityNativeKeysVectorsTest {
    private val bytes = File(System.getenv("IDENTITY_VECTORS") ?: "../spec/identity-native-keys-vectors.v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))

    private fun stateOf(name: String): NativeKeyState = when (name) {
        "has_key_readback_ok" -> NativeKeyState.HAS_KEY_READBACK_OK
        "no_key" -> NativeKeyState.NO_KEY
        "key_address_mismatch" -> NativeKeyState.KEY_ADDRESS_MISMATCH
        else -> error("unknown nativeState $name")
    }

    @Test
    fun vectorFileIsTheBatch17Copy() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("0dea55998971dfdfc4fa7ff195784f8e7f437454b96ee4855f603f7f2e09e0b1", sha)
    }

    @Test
    fun forbiddenKeysMatchTheVector() {
        val arr = v.getJSONArray("forbiddenKeys")
        assertEquals((0 until arr.length()).map { arr.getString(it) }, IdentityProvisionContract.FORBIDDEN_KEYS)
    }

    @Test
    fun responseKeysMatchTheVector() {
        val allowed = v.getJSONObject("responseShape").getJSONArray("allowedKeys")
        assertEquals((0 until allowed.length()).map { allowed.getString(it) }.toSet(), IdentityProvisionContract.RESPONSE_KEYS)
    }

    @Test
    fun everyRequestCaseMatchesItsExpectedResult() {
        val cases = v.getJSONArray("requestCases")
        assertEquals(10, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val expect = c.getJSONObject("expect")
            val got = IdentityProvisionContract.validate(c.getJSONObject("input"))
            if (expect.getBoolean("ok")) {
                assertTrue("$name should be accepted, got $got", got is Result.Accept)
                assertEquals(c.getJSONObject("input").getString("eoa"), (got as Result.Accept).eoa)
            } else {
                assertTrue("$name should be rejected, got $got", got is Result.Reject)
                val rej = got as Result.Reject
                assertEquals("$name error", expect.getString("error"), rej.error)
                if (expect.has("field")) assertEquals("$name field", expect.getString("field"), rej.field)
            }
        }
    }

    @Test
    fun readyReportMatchesEveryVariantAndHasOnlyAllowedKeys() {
        val variants = v.getJSONArray("readyVariants")
        assertEquals(3, variants.length())
        for (i in 0 until variants.length()) {
            val r = variants.getJSONObject(i)
            val eoa = r.getJSONObject("expect").getString("eoa")
            val resp = IdentityProvisionContract.readyResponse(eoa, stateOf(r.getString("nativeState")))
            assertEquals("variant ${r.getString("nativeState")}", r.getJSONObject("expect").getBoolean("ready"), resp.getBoolean("ready"))
            assertEquals(eoa, resp.getString("eoa"))
            assertEquals(IdentityProvisionContract.RESPONSE_KEYS, resp.keys().asSequence().toSet())
        }
    }

    @Test
    fun keyAddressMismatchNeverReportsReady() {
        val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
        assertEquals(false, IdentityProvisionContract.readyResponse(eoa, NativeKeyState.KEY_ADDRESS_MISMATCH).getBoolean("ready"))
    }

    @Test
    fun forbiddenKeyIsRefusedEvenWhenNested() {
        val body = JSONObject()
            .put("eoa", "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa")
            .put("pgpPublicKeyArmored", "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----")
            .put("identity", JSONObject().put("privateKeyHex", "00"))
        val r = IdentityProvisionContract.validate(body)
        assertEquals("key_over_bridge_refused", (r as Result.Reject).error)
        assertEquals("privateKeyHex", r.field)
    }
}
