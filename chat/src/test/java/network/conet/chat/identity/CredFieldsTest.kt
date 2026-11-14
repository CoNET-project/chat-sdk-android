package network.conet.chat.identity

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 25.52AQ.2 (r3co) and 25.52AS.2 (r3cq): the CRED list, its commands, and the field names it finds. Values are never returned.
 */
class CredFieldsTest {
    private val cred = listOf(
        "privateKeyHex", "privateKeyArmored", "pgpPrivateKeyArmored", "pgpPassphrase", "walletPrivateKey", "mnemonic",
        "recoveryCode", "pin", "password", "accountPassword",
        "privateKeyArmor", "privateKeyArmorWrap", "encrypKeyArmored", "mnemonicPhrase", "recoveryWords", "passphrase",
    )

    @Test
    fun theIdentityForbiddenSetIsTheSixteenCredNames() {
        // 25.52AQ.2 (r3co), 25.52BG.2 (r3de): the full CRED list. The identity vector (six names) is a subset, not the set (25.52BG.6).
        assertEquals(16, IdentityProvisionContract.FORBIDDEN_KEYS.size)
        assertEquals(cred.toSet(), IdentityProvisionContract.FORBIDDEN_KEYS.toSet())
    }

    @Test
    fun theSevenCommandsAreTheCredCommands() {
        assertEquals(
            setOf("pgpRestore", "pgpRestoreEvaluate", "pgpDecryptInbound", "pgpIdentityCreate", "provisionIdentity", "init", "pgpMigrate"),
            CredFields.COMMANDS,
        )
    }

    @Test
    fun everyCredNameIsFoundAtTheTopLevel() {
        for (name in cred) {
            assertEquals(name, listOf(name), CredFields.namesIn(JSONObject().put(name, "value")))
        }
    }

    @Test
    fun aCredNameIsFoundInANestedObjectAndInAnArrayItem() {
        val body = JSONObject()
            .put("accountKey", JSONObject().put("recoveryWords", "w"))
            .put("list", JSONArray().put(JSONObject().put("encrypKeyArmored", "x")))
        assertEquals(listOf("encrypKeyArmored", "recoveryWords"), CredFields.namesIn(body))
    }

    @Test
    fun matchingIsCaseInsensitiveAndTheNameIsReturnedAsWritten() {
        assertEquals(listOf("PIN"), CredFields.namesIn(JSONObject().put("PIN", 1)))
    }

    @Test
    fun aZeroWidthOrCompatibilityFormOfACredNameStillMatches() {
        // "pi" + U+200B + "n" normalizes to "pin" (25.52N, the canonical form N); the field is returned as written.
        val written = "pi​n"
        assertEquals(listOf(written), CredFields.namesIn(JSONObject().put(written, 1)))
        val fullWidth = "ｐｉｎ" // fullwidth p, i, n: NFKD maps them to ASCII
        assertEquals(listOf(fullWidth), CredFields.namesIn(JSONObject().put(fullWidth, 1)))
    }

    @Test
    fun aValueIsNeverReturned() {
        val names = CredFields.namesIn(JSONObject().put("pin", "SECRET-VALUE"))
        assertEquals(listOf("pin"), names)
        assertTrue(names.none { it.contains("SECRET") })
    }

    @Test
    fun otherKeysAreNotCredentialFields() {
        assertEquals(emptyList<String>(), CredFields.namesIn(JSONObject().put("alpha", 1).put("zeta", 2)))
    }

    @Test
    fun namesAreUniqueAndInUtf8ByteOrder() {
        val body = JSONObject()
            .put("pin", JSONObject().put("password", 1))
            .put("list", JSONArray().put(JSONObject().put("pin", 2)).put(JSONObject().put("PIN", 3)))
        // Upper-case ASCII sorts before lower-case in UTF-8, so "PIN" comes before "pin"; "password" sorts after "PIN" and before "pin".
        assertEquals(listOf("PIN", "password", "pin"), CredFields.namesIn(body))
    }

    @Test
    fun refusalNamesAreOnlyForTheCredCommands() {
        val body = JSONObject().put("pin", 1)
        assertEquals(listOf("pin"), CredFields.refusalNames("init", body))
        assertEquals(emptyList<String>(), CredFields.refusalNames("send", body))
        assertEquals(emptyList<String>(), CredFields.refusalNames("shellRecordWrite", body))
    }

    @Test
    fun everyCommandRefusesEveryCredNameBeforeTheGate() {
        // 25.52BG.6: the identity commands (and the other CRED commands) are tested against the whole CRED list, not six names.
        for (command in CredFields.COMMANDS) {
            for (name in cred) {
                assertEquals("$command refuses $name", listOf(name), CredFields.refusalNames(command, JSONObject().put(name, "v")))
            }
        }
    }
}
