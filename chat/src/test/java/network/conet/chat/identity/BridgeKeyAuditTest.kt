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
 * inside an array), in any letter case, and in the canonical-variant spellings (full-width, zero-width, combining mark, no-break space, soft
 * hyphen), is refused with `key_over_bridge_refused`. Snake-case spellings (`private_key_hex`) are not normalised by the contract; that is open
 * finding F4 in the A4 materials and is not asserted here.
 *
 * T-50 (source guard): no handler may read a forbidden key name from a bridge payload. The forbidden names are the union of the credential and
 * key fields of 25.41.3, `privateKeyArmor` and `encrypKeyArmored` (25.37.4 r3al), and `forbiddenKeysCaseInsensitive` in
 * identity-native-keys-vectors.v1.json (12 names). The scan finds a quoted literal of any of them, in any letter case, anywhere on a line of
 * chat/src/main/java, and of chat/src/qa/java in a QA build. Every occurrence is listed with its reason, and counted: a new occurrence of an
 * already-listed line fails the test. Two groups are listed:
 *  - `allowed`: reads or checks that do not take a value from a bridge payload (stored-record reads, refusal and removal lists, schema lists,
 *    the QA-only redaction).
 *  - `pendingRuling`: writes or checks of W-class values from a bridge payload, which the interface owner has not placed in T-50 (R598/R604).
 *    These are listed so that new ones fail, but they are NOT counted as T-50 passing.
 * Known limit: a name built by concatenation (for example `"priv" + "ateKeyArmor"`) is not matched by the literal scan.
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
                failures += refusedEverywhere(spelling)
            }
        }
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun t103CanonicalVariantSpellingsAreRefusedToo() {
        // The variants: full-width letters, a zero-width space, a combining acute mark, a no-break space, and a soft hyphen.
        val variants = listOf(
            "ｐｒｉｖａｔｅＫｅｙＨｅｘ", // full-width privateKeyHex
            "privateKey​Hex",
            "privateKeýHex",
            "privateKey Hex",
            "privateKey­Hex",
            "mne​monic",
        )
        val failures = mutableListOf<String>()
        for (spelling in variants) failures += refusedEverywhere(spelling)
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

    /** Every placement of [spelling] for provisionIdentity and init. Returns the failures (empty when all are refused). */
    private fun refusedEverywhere(spelling: String): List<String> {
        val failures = mutableListOf<String>()
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
        return failures
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
        val qaBuild = System.getProperty("chatQaHooks") != null

        // Listed reads that take no value from a bridge payload. Each line is the trimmed source line; repeats are counted.
        val allowed: Map<String, List<String>> = mapOf(
            // chatRouteRegister (spec 25.28.3, PM R2085): the refusal list of the request fields the page may not send. Membership only;
            // no value is read from the payload.
            "ChatRouteRegister.kt" to listOf(
                "\"wallet\", \"message\", \"signature\", \"timestamp\", \"nonce\", \"encrypKeyArmored\", \"privateKeyHex\", \"pgpPrivateArmorSha256\",",
                "\"pgpPrivateArmored\", \"pgpPrivateKeyArmored\",",
            ),
            // walletCredential (spec 25.52Y.38 第 1 项 (a), 第 3 项 (e); r3nv 第 5 项): the single exception for the native-to-page output of the
            // recovery phrase, which is the phrase's output field and its kind name. It is not a read from a bridge payload. The bridge
            // does not register the name until the shell trust gate and capability bit are in place.
            "WalletCredential.kt" to listOf(
                "const val KIND_MNEMONIC = \"mnemonic\"",
                ".put(\"mnemonic\", read.phrase),",
                ".put(\"mnemonic\", read.phrase).put(\"blob\", blob))",
                "return ok(echo, JSONObject().put(\"eoa\", eoa).put(\"credentialKind\", WalletCredential.KIND_MNEMONIC).put(\"mnemonic\", phrase))",
            ),
            "BeamioConetChatModule.kt" to listOf(
                // chatRouteRegister's ack (spec 25.28.3): the encrypted backup (encrypKeyArmored is ciphertext, allowed) and the public material.
                ".put(\"publicKeyArmored\", built.publicKeyArmored).put(\"encrypKeyArmored\", built.encrypKeyArmored)",
                // Read, but unreachable: validate(INIT) refuses these names first (A4 finding F1). Removal belongs to P-IMP-PGP.
                "pgpArmorInInit = id.optString(\"pgpPrivateKeyArmored\", \"\")",
                "pgpPassphraseInInit = id.optString(\"pgpPassphrase\", \"\")",
                // Refusal list of pgpRestore (PGP_RESTORE_REFUSED): a request naming one of them is refused. Only membership is tested.
                "\"privateKeyHex\", \"privateKeyArmored\", \"privateKeyArmor\", \"pgpPrivateKeyArmored\", \"pgpPassphrase\", \"passphrase\",",
                "\"walletPrivateKey\", \"mnemonic\", \"recoveryCode\", \"pin\", \"password\", \"accountPassword\",",
            ),
            "IdentityProvisionContract.kt" to listOf(
                // The contract's own refusal list (FORBIDDEN_KEYS = CRED, 25.52AQ.2 c). Membership only.
                "\"mnemonic\",",
                "\"pgpPassphrase\",",
                "\"pgpPrivateKeyArmored\",",
                "\"privateKeyArmor\",",
                "\"privateKeyHex\",",
                "\"walletPrivateKey\",",
                "\"privateKeyArmored\",",
                "\"recoveryCode\",",
                "\"pin\",",
                "\"password\",",
                "\"accountPassword\",",
                "\"encrypKeyArmored\",",
            ),
            "IdentityPublic.kt" to listOf(
                // Refusal lists of identityPublic (CREDENTIAL_FIELDS, 25.48.3): a credential field is refused and not echoed.
                "\"pgpPassphrase\", \"walletPrivateKey\", \"mnemonic\", \"recoveryCode\", \"pin\", \"password\", \"accountPassword\",",
                "\"privateKeyHex\", \"privateKeyArmor\", \"privateKeyArmored\", \"pgpPrivateKeyArmored\", \"encrypKeyArmored\",",
            ),
            "KeyIntake.kt" to listOf(
                // Refusal lists of init and provisionIdentity (INIT_REFUSED, PROVISION_REFUSED): membership only.
                "val INIT_REFUSED: List<String> = listOf(\"privateKeyHex\", \"walletPrivateKey\")",
                "\"privateKeyHex\",",
                "\"walletPrivateKey\",",
                "\"privateKeyArmor\",",
                "\"pgpPrivateKeyArmored\",",
                "\"pgpPassphrase\",",
                "\"mnemonic\",",
            ),
            "MnemonicDerivation.kt" to listOf(
                // Not a field name: the BIP-39 PBKDF2 salt constant and its doc comment.
                "/** PBKDF2-HMAC-SHA512, 2048 rounds, salt \"mnemonic\" with an empty passphrase, 64 bytes. */",
                "val salt = \"mnemonic\".toByteArray(Charsets.UTF_8)",
            ),
            "NativeOpenRules.kt" to listOf(
                // Refusal list of the native open commands (CREDENTIAL_FIELDS, 25.41.3): a credential field is refused. Membership only.
                "\"privateKeyHex\", \"privateKeyArmored\", \"pgpPrivateKeyArmored\", \"pgpPassphrase\", \"walletPrivateKey\", \"mnemonic\",",
                "\"recoveryCode\", \"pin\", \"password\", \"accountPassword\",",
            ),
            "PgpDecryptInbound.kt" to listOf(
                // Refusal list of pgpDecryptInbound (FORBIDDEN, forbiddenKey): a forbidden name is refused. Membership only.
                "\"pgpPassphrase\", \"walletPrivateKey\", \"mnemonic\",",
                "\"privateKeyHex\", \"privateKeyArmored\", \"privateKeyArmor\", \"pgpPrivateKeyArmored\",",
            ),
            "ShellRecord.kt" to listOf(
                // Stored-record reads: the EOA key of the page record already held on the device (25.52H.2, 25.52I.2). They judge the stored copy,
                // and no payload value reaches a reply from them.
                "!matches[0].has(\"privateKeyArmor\") -> \"needs_native_recovery\"",
                "if (storedProfile != null && storedProfile.has(\"privateKeyArmor\")) {",
                "} else if (storedSlot == null && hasProfileKey(stored, \"privateKeyArmor\")) {",
                // Legacy import (25.52K.5): the armor of the legacy record, checked by address before it is stored. Not a bridge payload.
                "val armor = profile?.optString(\"privateKeyArmor\", \"\").orEmpty()",
                // BB.3 (r3cz): the legacy armor is normalized on first import, then stored. The stored legacy record, not a bridge payload.
                "profile.put(\"privateKeyArmor\", canonical)",
                // Removal and key-shape lists of the record (WALLET_REMOVAL_PATHS, FORBIDDEN_PATHS, PGP_STRIP_PATHS, KEY_SHAPED_EXACT,
                // isKeyShaped, PROFILE_LEAVES, 25.52N.4, 25.52O.2, 25.52O.5). Membership or removal only; PROFILE_LEAVES is the record schema.
                "\"pgpPassphrase\",",
                "\"pgpPassphrase\",", // the second occurrence (PGP_STRIP_PATHS; the first is FORBIDDEN_PATHS): counted, so both are listed
                "private val WALLET_REMOVAL_PATHS: List<String> = listOf(W_PROFILE_PATH, \"mnemonicPhrase\", \"recoveryWords\", \"mnemonic\", \"walletVault.mnemonic\")",
                "\"seed\", \"walletPrivateKey\", \"recoveryCode\", \"recoveryPhrase\", \"recoveryWords\", \"duplicatePassword\", \"duplicateMnemonicPhrase\",",
                "key.startsWith(\"privateKey\") || key.startsWith(\"mnemonic\") || key.startsWith(\"pgpPassphrase\") ||",
                "\"webFilter\", \"aaAccount\", \"keyID\", \"type\", \"publicKeyArmor\", \"privateKeyArmor\",",
            ),
        )

        // Category b of 25.52AE.1 (r3cc): W-class handling in the page record, on an exact W path only (profiles[*].privateKeyArmor for the account,
        // top-level mnemonicPhrase). Not a bridge parameter and not an answer value. Listed so that a new occurrence fails.
        val pageRecordW: Map<String, List<String>> = mapOf(
            "ShellRecord.kt" to listOf(
                // mergeKey copies the stored W armor into the merge result (mergeWallet, 25.52H.2, 25.52AE.1 row 498).
                "\"privateKeyArmor\",",
                // The W-class type check on write (walletTypeRefusal, 25.52AF.3 rule 1): it tests that the value is an object or array, and never
                // returns it.
                "if (objectOrArray(profile.opt(\"privateKeyArmor\"))) names += W_PROFILE_PATH",
                // The form check on write (walletFormRefusal, 25.52N.9 Q1, F2 condition 4): it reads the string only to test its form and its derived
                // address against keyID, and never returns it.
                "val armor = profile.opt(\"privateKeyArmor\")",
            ),
        )

        // Listed reads that stay pending the interface owner's ruling: not counted as T-50 passing. The first is the check of another profile's
        // privateKeyArmor (mergeWallet). 25.52AE.1 row 507 requires such a profile to be bad_request naming the path, and not merged; the current
        // behaviour is to be verified before this line can move to category b.
        val pendingRuling: Map<String, List<String>> = mapOf(
            "ShellRecord.kt" to listOf(
                "if (profiles.optJSONObject(i)?.has(\"privateKeyArmor\") == true && i != pageSlot) unmatched += W_PROFILE_PATH",
                // walletAccountMismatch (25.52AG.2 (b), r3ch/r3cj): a profile not of the account that carries privateKeyArmor (null included) is a
                // conflict. The presence is tested, the value is never read or echoed. Pending the owner's confirmation of the category.
                "if (!profile.optString(\"keyID\", \"\").equals(account, ignoreCase = true) && profile.has(\"privateKeyArmor\")) mismatch = true",
                // accountHoldsEoaKey (25.52P.4) is also called on the merged record at the write check (ShellRecord, after mergeWallet): that record
                // holds the page payload, so this line is pending like the other payload reads (audit of 00537c5). Its other callers read the
                // stored record only.
                "fun accountHoldsEoaKey(record: JSONObject, eoa: String): Boolean = matchingProfiles(record, eoa).any { it.has(\"privateKeyArmor\") }",
            ),
        )

        // The QA-only redaction in the QA source set (chat/src/qa), listed in a QA build only. It removes the EOA key from the QA record copy.
        val qaOnly: Map<String, List<String>> = mapOf(
            "NativeQaHooks.kt" to listOf(
                "if (profile.optString(\"keyID\", \"\").equals(account, ignoreCase = true)) profile.remove(\"privateKeyArmor\")",
            ),
        )

        val pattern = Regex("(?i)\"(" + forbiddenNames.joinToString("|") + ")\"")
        val roots = listOfNotNull(
            File("src/main/java"),
            File("src/qa/java").takeIf { qaBuild && it.isDirectory },
        )
        assertTrue("run from the chat module directory", File("src/main/java").isDirectory)
        val found = mutableListOf<String>()
        for (root in roots) {
            root.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }.forEach { f ->
                f.readLines().forEach { line ->
                    if (pattern.containsMatchIn(line)) found += "${f.name}|${line.trim()}"
                }
            }
        }
        val listed = (allowed.asSequence() + pageRecordW.asSequence() + pendingRuling.asSequence() + (if (qaBuild) qaOnly.asSequence() else emptySequence()))
            .flatMap { (file, lines) -> lines.map { "$file|$it" } }
            .toList()
        val foundCounts = found.groupingBy { it }.eachCount()
        val listedCounts = listed.groupingBy { it }.eachCount()
        val unexpected = foundCounts
            .filter { (k, v) -> v > (listedCounts[k] ?: 0) }
            .map { (k, v) -> "$k x${v - (listedCounts[k] ?: 0)}" }
            .sorted()
        val missing = listedCounts
            .filter { (k, v) -> v > (foundCounts[k] ?: 0) }
            .map { (k, v) -> "$k x${v - (foundCounts[k] ?: 0)}" }
            .sorted()
        assertEquals("forbidden-key reads not on the list (file|line xN)", emptyList<String>(), unexpected)
        assertEquals("listed reads that no longer exist (update the list)", emptyList<String>(), missing)
    }
}
