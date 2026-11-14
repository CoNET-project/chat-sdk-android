package network.conet.chat.identity

import network.conet.chat.identity.IdentityProvisionContract.Command
import network.conet.chat.identity.IdentityProvisionContract.Result
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * A4 audit evidence for the native-keys boundary (spec 25.26.5, 25.19.2, 25.19.4; T-50 and T-103).
 *
 * T-103 (payload audit of `identity.provision` and `init`): every name the contract refuses (25.19.2), in any placement (top level, nested,
 * inside an array) and in any letter case (as written, upper case, initial capital), is refused with `key_over_bridge_refused`. Snake-case
 * spellings (`private_key_hex`) are not normalised by the contract; that is open finding F4 in the A4 materials, not covered here.
 *
 * T-50 (source guard): no handler may read a forbidden key name from a bridge payload. The forbidden names are the union of the credential and
 * key fields of 25.41.3, `privateKeyArmor` and `encrypKeyArmored` (25.37.4 r3al), and `forbiddenKeysCaseInsensitive` in
 * identity-native-keys-vectors.v1.json. A quoted literal of any of them, in any letter case, anywhere in chat/src/main/java is listed below with
 * its reason. A new line fails this test until it is reviewed and listed. The scan covers main sources only; it does not cover chat/src/qa,
 * which holds the QA-only native entry (R591).
 */
class BridgeKeyAuditTest {
    private val validEoa = "0x" + "a1".repeat(20)

    /** The names the identity contract refuses (T-103, 25.19.2). */
    private val refusedByProvisionAndInit = listOf(
        "privateKeyHex",
        "walletPrivateKey",
        "privateKeyArmor",
        "pgpPrivateKeyArmored",
        "pgpPassphrase",
        "mnemonic",
    )

    /** The names T-50 guards: 25.41.3 credential and key fields, `privateKeyArmor` and `encrypKeyArmored` (r3al), and the vector list. */
    private val forbiddenNames = listOf(
        "privateKeyHex",
        "walletPrivateKey",
        "privateKeyArmor",
        "privateKeyArmored",
        "pgpPrivateKeyArmored",
        "pgpPassphrase",
        "mnemonic",
        "recoveryCode",
        "pin",
        "password",
        "accountPassword",
        "encrypKeyArmored",
    )

    @Test
    fun t103EveryForbiddenKeyIsRefusedInEveryPlacementAndCase() {
        val failures = mutableListOf<String>()
        for (name in refusedByProvisionAndInit) {
            for (spelling in listOf(name, name.uppercase(), name.replaceFirstChar { it.uppercase() })) {
                // identity.provision: the key at the top level, nested in an object, and inside an array.
                val provisionTop = JSONObject().put("eoa", validEoa).put(spelling, "x")
                failures += expectRefused("provisionIdentity top", Command.PROVISION_IDENTITY, provisionTop, spelling)
                val provisionNested = JSONObject().put("eoa", validEoa).put("wallet", JSONObject().put(spelling, "x"))
                failures += expectRefused("provisionIdentity nested", Command.PROVISION_IDENTITY, provisionNested, spelling)
                val provisionArray = JSONObject().put("eoa", validEoa).put("items", JSONArray().put(JSONObject().put(spelling, "x")))
                failures += expectRefused("provisionIdentity array", Command.PROVISION_IDENTITY, provisionArray, spelling)

                // init: the key at the top level of the payload, inside the identity object, nested, and inside an array.
                val initTop = JSONObject().put("identity", JSONObject().put("eoa", validEoa)).put(spelling, "x")
                failures += expectRefused("init top", Command.INIT, initTop, spelling)
                val initIdentity = JSONObject().put("identity", JSONObject().put("eoa", validEoa).put(spelling, "x"))
                failures += expectRefused("init identity", Command.INIT, initIdentity, spelling)
                val initNested = JSONObject().put("identity", JSONObject().put("eoa", validEoa).put("wallet", JSONObject().put(spelling, "x")))
                failures += expectRefused("init nested", Command.INIT, initNested, spelling)
                val initArray = JSONObject().put("identity", JSONObject().put("eoa", validEoa)).put("items", JSONArray().put(JSONObject().put(spelling, "x")))
                failures += expectRefused("init array", Command.INIT, initArray, spelling)
            }
        }
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun t103ValidPublicPayloadsAreAccepted() {
        // The contract refuses only key material: a public payload with the EOA is accepted (the control for the test above).
        assertTrue(IdentityProvisionContract.validate(Command.PROVISION_IDENTITY, JSONObject().put("eoa", validEoa)) is Result.Accept)
        assertTrue(
            IdentityProvisionContract.validate(Command.INIT, JSONObject().put("identity", JSONObject().put("eoa", validEoa))) is Result.Accept,
        )
    }

    private fun expectRefused(where: String, command: Command, body: JSONObject, key: String): List<String> {
        val result = IdentityProvisionContract.validate(command, body)
        return if (result is Result.Reject && result.error == "key_over_bridge_refused") {
            emptyList()
        } else {
            listOf("$where: $key was not refused (${result.javaClass.simpleName})")
        }
    }

    @Test
    fun t50NoHandlerReadsAForbiddenKeyFromTheBridgeExceptAsListed() {
        // Each entry: the file name and the trimmed source line that holds the quoted name, grouped by the reason it is allowed.
        val allowed = mapOf(
            "BeamioConetChatModule.kt" to setOf(
                // Read, but unreachable: validate(INIT) refuses these names first (A4 finding F1). Removal belongs to P-IMP-PGP.
                "pgpArmorInInit = id.optString(\"pgpPrivateKeyArmored\", \"\")",
                "pgpPassphraseInInit = id.optString(\"pgpPassphrase\", \"\")",
                // Refusal list of pgpRestore (PGP_RESTORE_REFUSED): a request naming one of them is refused. Only membership is tested.
                "\"privateKeyHex\", \"privateKeyArmored\", \"privateKeyArmor\", \"pgpPrivateKeyArmored\", \"pgpPassphrase\", \"passphrase\",",
                "\"walletPrivateKey\", \"mnemonic\", \"recoveryCode\", \"pin\", \"password\", \"accountPassword\",",
            ),
            "IdentityProvisionContract.kt" to setOf(
                // The contract's own refusal list (FORBIDDEN_KEYS). Membership only.
                "\"mnemonic\",",
                "\"pgpPassphrase\",",
                "\"pgpPrivateKeyArmored\",",
                "\"privateKeyArmor\",",
                "\"privateKeyHex\",",
                "\"walletPrivateKey\",",
            ),
            "IdentityPublic.kt" to setOf(
                // Refusal lists of identityPublic (CREDENTIAL_FIELDS, 25.48.3): a credential field is refused and not echoed.
                "\"pgpPassphrase\", \"walletPrivateKey\", \"mnemonic\", \"recoveryCode\", \"pin\", \"password\", \"accountPassword\",",
                "\"privateKeyHex\", \"privateKeyArmor\", \"privateKeyArmored\", \"pgpPrivateKeyArmored\", \"encrypKeyArmored\",",
            ),
            "KeyIntake.kt" to setOf(
                // Refusal lists of init and provisionIdentity (INIT_REFUSED, PROVISION_REFUSED): membership only.
                "val INIT_REFUSED: List<String> = listOf(\"privateKeyHex\", \"walletPrivateKey\")",
                "\"privateKeyHex\",",
                "\"walletPrivateKey\",",
                "\"privateKeyArmor\",",
                "\"pgpPrivateKeyArmored\",",
                "\"pgpPassphrase\",",
                "\"mnemonic\",",
            ),
            "MnemonicDerivation.kt" to setOf(
                // Not a field name: the BIP-39 PBKDF2 salt constant and its doc comment.
                "/** PBKDF2-HMAC-SHA512, 2048 rounds, salt \"mnemonic\" with an empty passphrase, 64 bytes. */",
                "val salt = \"mnemonic\".toByteArray(Charsets.UTF_8)",
            ),
            "NativeOpenRules.kt" to setOf(
                // Refusal list of the native open commands (CREDENTIAL_FIELDS, 25.41.3): a credential field is refused. Membership only.
                "\"privateKeyHex\", \"privateKeyArmored\", \"pgpPrivateKeyArmored\", \"pgpPassphrase\", \"walletPrivateKey\", \"mnemonic\",",
                "\"recoveryCode\", \"pin\", \"password\", \"accountPassword\",",
            ),
            "PgpDecryptInbound.kt" to setOf(
                // Refusal list of pgpDecryptInbound (FORBIDDEN, forbiddenKey): a forbidden name is refused. Membership only.
                "\"pgpPassphrase\", \"walletPrivateKey\", \"mnemonic\",",
                "\"privateKeyHex\", \"privateKeyArmored\", \"privateKeyArmor\", \"pgpPrivateKeyArmored\",",
            ),
            "PgpMigrationBridge.kt" to setOf(
                // Refusal list of pgpMigrate (KEY_FIELDS): a request naming one is refused with key_over_bridge_refused; only names are read.
                "\"mnemonic\",",
                "\"pgpPassphrase\",",
                "\"pgpPrivateKeyArmored\",",
                "\"privateKeyArmor\",",
                "\"privateKeyHex\",",
                "\"recoveryCode\",",
                "\"walletPrivateKey\",",
            ),
            "ShellRecord.kt" to setOf(
                // The page-record copy: the EOA private key (W field) and its record paths. These read or write the stored page record that
                // the page sends through window.BeamioShellRecord, under the record rules of 25.52H.2 and 25.52I.2. Whether an EOA key may be
                // returned by shellRecordRead is open (A4 finding F2) and awaits the interface owner's and PM's ruling.
                "!matches[0].has(\"privateKeyArmor\") -> \"needs_native_recovery\"",
                "fun accountHoldsEoaKey(record: JSONObject, eoa: String): Boolean = matchingProfiles(record, eoa).any { it.has(\"privateKeyArmor\") }",
                "if (profiles.optJSONObject(i)?.has(\"privateKeyArmor\") == true && i != pageSlot) unmatched += W_PROFILE_PATH",
                "if (storedProfile != null && storedProfile.has(\"privateKeyArmor\")) {",
                "val armor = profile?.optString(\"privateKeyArmor\", \"\").orEmpty()",
                // The W-field merge: the stored EOA key is copied into the record by mergeKey (argument form, 25.52H.2). It is written to the
                // record, not to a reply of its own.
                "\"privateKeyArmor\",",
                "} else if (storedSlot == null && hasProfileKey(stored, \"privateKeyArmor\")) {",
                // Path lists that strip or remove secret paths from the record (PGP_STRIP_PATHS, WALLET_REMOVAL_PATHS), and the forbidden-path
                // set (FORBIDDEN_PATHS, 25.52O.2): membership and removal only.
                "\"pgpPassphrase\",",
                "private val WALLET_REMOVAL_PATHS: List<String> = listOf(W_PROFILE_PATH, \"mnemonicPhrase\", \"recoveryWords\", \"mnemonic\", \"walletVault.mnemonic\")",
                // Key-shape detection for the record (KEY_SHAPED_EXACT and isKeyShaped, 25.52O.2): a name is classed as secret, not read.
                "\"seed\", \"walletPrivateKey\", \"recoveryCode\", \"recoveryPhrase\", \"recoveryWords\", \"duplicatePassword\", \"duplicateMnemonicPhrase\",",
                "key.startsWith(\"privateKey\") || key.startsWith(\"mnemonic\") || key.startsWith(\"pgpPassphrase\") ||",
                // The profile leaves allowed in the record schema (PROFILE_LEAVES), which keep the W field's privateKeyArmor (25.52H.2).
                "\"webFilter\", \"aaAccount\", \"keyID\", \"type\", \"publicKeyArmor\", \"privateKeyArmor\",",
            ),
        )
        // A quoted literal of a forbidden name, in any letter case, anywhere on the line. This also catches a name passed as an argument
        // (for example `mergeKey(…, "privateKeyArmor", …)`), which a call-only pattern would miss.
        val pattern = Regex("(?i)\"(" + forbiddenNames.joinToString("|") + ")\"")
        val root = File("src/main/java")
        assertTrue("run from the chat module directory", root.isDirectory)
        val found = mutableSetOf<String>()
        root.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }.forEach { f ->
            f.readLines().forEach { line ->
                if (pattern.containsMatchIn(line)) {
                    val trimmed = line.trim()
                    found += "${f.name}|$trimmed"
                }
            }
        }
        val expected = allowed.flatMap { (file, lines) -> lines.map { "$file|$it" } }.toSet()
        val unexpected = found - expected
        val missing = expected - found
        assertEquals("forbidden-key reads not on the list", emptyList<String>(), unexpected.toList().sorted())
        assertEquals("listed reads that no longer exist (update the list)", emptyList<String>(), missing.toList().sorted())
    }
}
