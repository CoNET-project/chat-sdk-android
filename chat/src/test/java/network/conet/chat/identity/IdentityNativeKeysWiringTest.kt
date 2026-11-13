package network.conet.chat.identity

import network.conet.chat.identity.IdentityProvisionContract.Command
import network.conet.chat.identity.IdentityProvisionContract.NativeKeyState
import network.conet.chat.identity.IdentityProvisionContract.Result
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The module's `provisionIdentity` and `init` paths run through [IdentityProvisionContract]. This pins the vault-to-state
 * mapping the reply uses, the reply keys, and the refusals that now guard both commands. Synthetic material only.
 */
class IdentityNativeKeysWiringTest {
    private val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
    private val otherEoa = "0x1111111111111111111111111111111111111111"
    private val pgp = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nTEST-ONLY-SYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----"

    @Test
    fun vaultStateMapsToTheThreeReportedStates() {
        assertEquals(NativeKeyState.NO_KEY, IdentityProvisionContract.nativeKeyState(null, eoa))
        assertEquals(NativeKeyState.HAS_KEY_READBACK_OK, IdentityProvisionContract.nativeKeyState(eoa, eoa))
        assertEquals(
            NativeKeyState.HAS_KEY_READBACK_OK,
            IdentityProvisionContract.nativeKeyState("0x" + eoa.substring(2).uppercase(), eoa),
        )
        assertEquals(NativeKeyState.KEY_ADDRESS_MISMATCH, IdentityProvisionContract.nativeKeyState(otherEoa, eoa))
    }

    @Test
    fun readyIsTrueOnlyWhenTheKeyReadBackForThisAccount() {
        val cases = listOf(
            NativeKeyState.HAS_KEY_READBACK_OK to true,
            NativeKeyState.NO_KEY to false,
            NativeKeyState.KEY_ADDRESS_MISMATCH to false,
        )
        for ((state, ready) in cases) {
            val reply = IdentityProvisionContract.readyResponse(eoa, state)
            assertEquals("state=$state", ready, reply.getBoolean("ready"))
            assertEquals(eoa, reply.getString("eoa"))
            assertEquals(IdentityProvisionContract.RESPONSE_KEYS, reply.keys().asSequence().toSet())
        }
    }

    @Test
    fun provisionAcceptsPublicMaterialForACanonicalEoa() {
        val body = JSONObject()
            .put("eoa", eoa)
            .put("pgpPublicKeyArmored", pgp)
            .put("ownRouteArmoredPublicKey", pgp)
        val r = IdentityProvisionContract.validate(Command.PROVISION_IDENTITY, body)
        assertEquals(eoa, (r as Result.Accept).eoa)
    }

    @Test
    fun provisionRejectsANonCanonicalEoa() {
        val body = JSONObject()
            .put("eoa", "0x" + eoa.substring(2).uppercase())
            .put("pgpPublicKeyArmored", pgp)
            .put("ownRouteArmoredPublicKey", pgp)
        val r = IdentityProvisionContract.validate(Command.PROVISION_IDENTITY, body)
        assertTrue(r is Result.Reject)
        assertEquals("bad_identity", (r as Result.Reject).error)
    }

    @Test
    fun initRefusesKeyMaterialBeforeAnyAccept() {
        val payload = JSONObject().put(
            "identity",
            JSONObject()
                .put("eoa", eoa)
                .put("pgpPublicKeyArmored", pgp)
                .put("ownRouteArmoredPublicKey", pgp)
                .put("privateKeyHex", "0x" + "ab".repeat(32)),
        )
        val r = IdentityProvisionContract.validate(Command.INIT, payload)
        assertTrue(r is Result.Reject)
        assertEquals("key_over_bridge_refused", (r as Result.Reject).error)
    }
}
