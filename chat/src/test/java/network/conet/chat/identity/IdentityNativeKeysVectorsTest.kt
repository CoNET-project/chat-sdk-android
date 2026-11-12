package network.conet.chat.identity

import network.conet.chat.identity.IdentityProvisionContract.Command
import network.conet.chat.identity.IdentityProvisionContract.NativeKeyState
import network.conet.chat.identity.IdentityProvisionContract.Result
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * identity.native-keys.v1 against `spec/identity-native-keys-vectors.v1.json` (batch 24, sha256 7aa7b4db…).
 * Synthetic material only. Checks the placement rules, canonical form N (NFKD, S removed, Mn/Me/Cf removed),
 * the key-name whitelist, eoa canonical form, PGP armor value rules, I-4 (case-insensitive names,
 * "PRIVATEKEYBLOCK" at any depth, 64-hex with 0x or 0X outside the exact path `payload.nodes`), the ready
 * mapping and the response keys.
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

    private fun commandOf(wire: String): Command = when (wire) {
        "provisionIdentity" -> Command.PROVISION_IDENTITY
        "init" -> Command.INIT
        else -> error("unknown command $wire")
    }

    @Test
    fun vectorFileIsTheCurrentBatchCopy() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("7aa7b4dbd93d0d42b594ab18f1d70e85a7d4b9dbba484bd7d6aba4e3851864b9", sha)
    }

    @Test
    fun forbiddenKeysMatchTheVectorCaseInsensitively() {
        val arr = v.getJSONArray("forbiddenKeysCaseInsensitive")
        val vector = (0 until arr.length()).map { arr.getString(it) }
        assertEquals(vector.toSet(), IdentityProvisionContract.FORBIDDEN_KEYS.map { it.lowercase() }.toSet())
    }

    @Test
    fun responseKeysMatchTheVector() {
        val allowed = v.getJSONObject("responseShape").getJSONArray("allowedKeys")
        assertEquals((0 until allowed.length()).map { allowed.getString(it) }.toSet(), IdentityProvisionContract.RESPONSE_KEYS)
    }

    @Test
    fun everyRequestCaseMatchesItsExpectedResult() {
        val cases = v.getJSONArray("requestCases")
        assertEquals(53, cases.length())
        // Batch 24: seven value-shape rules (0, 0a, 1–5); the vector's text is authoritative.
        assertEquals(7, v.getJSONArray("valueShapeRules").length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val expect = c.getJSONObject("expect")
            val got = IdentityProvisionContract.validate(commandOf(c.getString("command")), c.getJSONObject("input"))
            if (expect.getBoolean("ok")) {
                assertTrue("$name should be accepted, got $got", got is Result.Accept)
                assertEquals(name, identityEoa(c), (got as Result.Accept).eoa)
            } else {
                assertTrue("$name should be rejected, got $got", got is Result.Reject)
                val rej = got as Result.Reject
                assertEquals("$name error", expect.getString("error"), rej.error)
                if (expect.has("field")) assertEquals("$name field", expect.getString("field"), rej.field)
            }
        }
    }

    /** The eoa the accepted case carries, at the placement its command requires. */
    private fun identityEoa(c: JSONObject): String {
        val input = c.getJSONObject("input")
        val src = if (c.getString("command") == "init") input.getJSONObject("identity") else input
        return src.getString("eoa")
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
    fun forbiddenKeyIsRefusedEvenWhenNestedAndUpperCased() {
        val body = JSONObject()
            .put("eoa", "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa")
            .put("pgpPublicKeyArmored", "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----")
            .put("identity", JSONObject().put("PRIVATEKEYHEX", "00"))
        val r = IdentityProvisionContract.validate(Command.PROVISION_IDENTITY, body) as Result.Reject
        assertEquals("key_over_bridge_refused", r.error)
        assertEquals("PRIVATEKEYHEX", r.field)
    }
}
