package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * r2.5.19 59(1)(c): pwaWalletSync may carry phrase; any other credential-class field in the payload is key_over_bridge_refused, and the value is
 * never echoed. The check runs after trustedOrigin and before the format checks.
 */
class CredentialFieldTest {
    @Test
    fun thePhraseFieldIsTheOnlyAllowedCredentialFieldOfTheSync() {
        val body = JSONObject().put("type", "pwaWalletSync").put("reqId", "s").put("trustedOrigin", true).put("seq", 3).put("phrase", "a b c")
        assertNull(NativeSyncAck.credentialRefusal(body, allowedField = "phrase"))
    }

    @Test
    fun otherCredentialFieldsOfTheSyncAreRefused() {
        for (field in listOf("privateKeyHex", "mnemonic", "recoveryCode", "pin", "password", "walletPrivateKey", "pgpPassphrase")) {
            val body = JSONObject().put("phrase", "a b c").put(field, "x")
            assertEquals(field, "key_over_bridge_refused", NativeSyncAck.credentialRefusal(body, allowedField = "phrase"))
        }
    }

    @Test
    fun aPreReadAndASignalAllowNoCredentialField() {
        assertEquals("key_over_bridge_refused", NativeSyncAck.credentialRefusal(JSONObject().put("mnemonic", "x"), allowedField = null))
        assertNull(NativeSyncAck.credentialRefusal(JSONObject().put("type", "pwaEmptySignal").put("seq", 4).put("pwaState", "unknown"), allowedField = null))
    }

    @Test
    fun theCheckMatchesNamesRegardlessOfCase() {
        assertEquals("key_over_bridge_refused", NativeSyncAck.credentialRefusal(JSONObject().put("PrivateKeyHex", "x"), allowedField = "phrase"))
    }
}

/**
 * Review: eoaPrivateKey is a key field (25.52Y.38 第 8 项; the 25.52 list). Each of the three commands answers
 * key_over_bridge_refused and nothing is echoed; the name list also covers the spec's secret names.
 */
class CredentialFieldListTest {
    private val secret = "0x" + "cd".repeat(32)

    @Test
    fun eoaPrivateKeyIsRefusedByTheSyncWithoutAnEcho() {
        val body = JSONObject().put("type", "pwaWalletSync").put("reqId", "s").put("trustedOrigin", true).put("seq", 3).put("phrase", "a b c")
            .put("eoaPrivateKey", secret)
        val refusal = NativeSyncAck.credentialRefusal(body, allowedField = "phrase")
        assertEquals("key_over_bridge_refused", refusal)
        assertFalse("nothing echoed", (refusal ?: "").contains("cd".repeat(4)))
    }

    @Test
    fun eoaPrivateKeyIsRefusedByThePreReadWithoutAnEcho() {
        val body = JSONObject().put("type", "nativeMnemonicPreread").put("reqId", "np").put("trustedOrigin", true).put("seq", 6)
            .put("eoaPrivateKey", secret)
        val got = NativeSyncAck.prereadPayload("np", body) { MnemonicPreread.Answer.Unknown }
        assertEquals(false, got.getBoolean("ok"))
        assertEquals("key_over_bridge_refused", got.getString("error"))
        assertFalse("no value in the reply", got.toString().contains("cd".repeat(4)))
    }

    @Test
    fun eoaPrivateKeyIsRefusedBySignalWithoutAnEcho() {
        val body = JSONObject().put("type", "pwaEmptySignal").put("reqId", "e").put("trustedOrigin", true).put("seq", 4)
            .put("pwaState", "explicit_empty").put("eoaPrivateKey", secret)
        assertEquals("key_over_bridge_refused", NativeSyncAck.credentialRefusal(body, allowedField = null))
    }

    /** Every name of the spec's list is refused for each of the three commands (the sync keeps only phrase). */
    @Test
    fun theSpecListIsRefusedByEveryCommand() {
        val names = listOf(
            "privateKeyHex", "privateKeyArmored", "pgpPrivateKeyArmored", "pgpPassphrase", "walletPrivateKey", "mnemonic",
            "recoveryCode", "pin", "password", "accountPassword", "eoaPrivateKey", "privateKeyArmor", "encrypKeyArmored",
            "mnemonicPhrase", "recoveryWords", "seed", "recoveryPhrase", "duplicatePassword", "duplicateMnemonicPhrase",
            "duplicateCode", "_duplicateCode", "passphrase", "privateKeyArmorWrap",
        )
        for (name in names) {
            val body = JSONObject().put(name, "x")
            assertEquals(name, "key_over_bridge_refused", NativeSyncAck.credentialRefusal(body, allowedField = "phrase"))
            assertEquals(name, "key_over_bridge_refused", NativeSyncAck.credentialRefusal(body, allowedField = null))
        }
    }

    @Test
    fun ordinaryFieldsAreNotCredentials() {
        for (name in listOf("type", "reqId", "trustedOrigin", "seq", "pwaState", "phrase", "eoa", "account", "state")) {
            assertFalse(name, NativeSyncAck.isCredentialField(name))
        }
    }
}
