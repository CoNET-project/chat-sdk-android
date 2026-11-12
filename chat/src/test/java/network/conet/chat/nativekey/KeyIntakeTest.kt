package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Which bridge payloads carry key fields (T-127, T-127b, T-103). Blank values do not count. */
class KeyIntakeTest {
    @Test
    fun initRefusesAWalletKeyInsideIdentity() {
        val payload = JSONObject().put("identity", JSONObject().put("eoa", "0x" + "1".repeat(40)).put("privateKeyHex", "ab".repeat(32)))
        assertEquals(listOf("privateKeyHex"), KeyIntake.initRefused(payload))
    }

    @Test
    fun initRefusesAWalletKeyAtTheTopLevel() {
        val payload = JSONObject().put("walletPrivateKey", "0x" + "ab".repeat(32))
        assertEquals(listOf("walletPrivateKey"), KeyIntake.initRefused(payload))
    }

    @Test
    fun initStillAcceptsPgpArmorUntilNativePgpExists() {
        // R7 is not approved: init keeps carrying PGP armor for now. This test pins that boundary.
        val payload = JSONObject().put("identity", JSONObject().put("pgpPrivateKeyArmored", "-----BEGIN PGP PRIVATE KEY BLOCK-----"))
        assertTrue(KeyIntake.initRefused(payload).isEmpty())
    }

    @Test
    fun blankValuesAreNotKeys() {
        val payload = JSONObject()
            .put("privateKeyHex", "")
            .put("identity", JSONObject().put("walletPrivateKey", "   "))
        assertTrue(KeyIntake.initRefused(payload).isEmpty())
    }

    @Test
    fun provisionRefusesEveryKeyField() {
        val payload = JSONObject()
            .put("eoa", "0x" + "1".repeat(40))
            .put("walletPrivateKey", "ab".repeat(32))
            .put("pgpPrivateKeyArmored", "x")
            .put("pgpPassphrase", "x")
            .put("mnemonic", "x")
        assertEquals(
            listOf("walletPrivateKey", "pgpPrivateKeyArmored", "pgpPassphrase", "mnemonic"),
            KeyIntake.provisionRefused(payload),
        )
    }

    @Test
    fun provisionWithPublicMaterialOnlyIsAccepted() {
        val payload = JSONObject()
            .put("eoa", "0x" + "1".repeat(40))
            .put("pgpPublicKeyArmored", "-----BEGIN PGP PUBLIC KEY BLOCK-----")
            .put("ownRouteArmoredPublicKey", "-----BEGIN PGP PUBLIC KEY BLOCK-----")
        assertTrue(KeyIntake.provisionRefused(payload).isEmpty())
    }
}
