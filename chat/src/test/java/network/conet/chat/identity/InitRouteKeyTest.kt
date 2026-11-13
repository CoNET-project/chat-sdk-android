package network.conet.chat.identity

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The route public key is optional in `init` (r3aj, §25.30.2, §25.48.10). An omitted key is accepted and stays absent; a present
 * key must be PGP public armor, under the PWA's name and under the legacy alias. The contract decides this; the module only stores
 * what it accepts.
 */
class InitRouteKeyTest {
    private val eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
    private val route = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-route-public-only\n-----END PGP PUBLIC KEY BLOCK-----"

    /** An init payload whose `identity` carries [extra] next to the EOA. */
    private fun init(vararg extra: Pair<String, Any>): JSONObject {
        val id = JSONObject().put("eoa", eoa)
        for ((k, v) in extra) id.put(k, v)
        return JSONObject().put("identity", id)
    }

    private fun initVerdict(payload: JSONObject) = IdentityProvisionContract.validate(IdentityProvisionContract.Command.INIT, payload)

    private fun assertRejected(payload: JSONObject, error: String) {
        val r = initVerdict(payload)
        assertTrue("expected a rejection, got $r", r is IdentityProvisionContract.Result.Reject)
        assertEquals(error, (r as IdentityProvisionContract.Result.Reject).error)
    }

    @Test
    fun anInitWithoutTheRouteKeyIsAccepted() {
        val r = initVerdict(init())
        assertEquals(IdentityProvisionContract.Result.Accept(eoa), r)
    }

    @Test
    fun anInitWithTheRouteKeyAsPublicArmorIsAccepted() {
        val r = initVerdict(init("ownRouteArmoredPublicKey" to route))
        assertEquals(IdentityProvisionContract.Result.Accept(eoa), r)
    }

    @Test
    fun anEmptyRouteKeyIsNotAStandInForAnOmittedOne() {
        assertRejected(init("ownRouteArmoredPublicKey" to ""), "bad_identity")
    }

    @Test
    fun aRouteKeyThatIsNotArmorIsRefused() {
        assertRejected(init("ownRouteArmoredPublicKey" to "synthetic-route-public-0001"), "bad_identity")
    }

    @Test
    fun aRouteKeyThatIsPrivateArmorIsRefusedAsKeyMaterial() {
        val privateArmor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----"
        assertRejected(init("ownRouteArmoredPublicKey" to privateArmor), "key_over_bridge_refused")
    }

    @Test
    fun theLegacyRouteAliasIsValidatedWhenPresent() {
        assertRejected(init("routePublicKeyArmored" to ""), "bad_identity")
        assertEquals(IdentityProvisionContract.Result.Accept(eoa), initVerdict(init("routePublicKeyArmored" to route)))
    }

    @Test
    fun aProvisionIdentityWithoutTheRouteKeyIsAccepted() {
        val flat = JSONObject().put("eoa", eoa)
        val r = IdentityProvisionContract.validate(IdentityProvisionContract.Command.PROVISION_IDENTITY, flat)
        assertEquals(IdentityProvisionContract.Result.Accept(eoa), r)
    }
}
