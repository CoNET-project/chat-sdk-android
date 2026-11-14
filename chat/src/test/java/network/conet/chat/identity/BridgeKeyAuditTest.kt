package network.conet.chat.identity

import network.conet.chat.identity.IdentityProvisionContract.Command
import network.conet.chat.identity.IdentityProvisionContract.Result
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * A4 audit evidence for the native-keys boundary (spec 25.26.5, 25.19.2, 25.19.4; T-50 and T-103).
 *
 * T-103 (payload audit of `identity.provision` and `init`): every forbidden key name, in any placement and any letter case, is refused with
 * `key_over_bridge_refused`, and no key material is accepted from the bridge.
 *
 * T-50 (bridge command parameter audit): a source guard. No handler may read a forbidden key name from a bridge payload. The matches below are the
 * only permitted reads; each is listed with the reason it is allowed. A new read fails this test until it is reviewed and listed.
 */
class BridgeKeyAuditTest {
    private val validEoa = "0x" + "a1".repeat(20)
    private val forbidden = listOf(
        "privateKeyHex",
        "walletPrivateKey",
        "privateKeyArmor",
        "pgpPrivateKeyArmored",
        "pgpPassphrase",
        "mnemonic",
    )

    @Test
    fun t103EveryForbiddenKeyIsRefusedInEveryPlacementAndCase() {
        val failures = mutableListOf<String>()
        for (name in forbidden) {
            for (spelling in listOf(name, name.uppercase(), name.replaceFirstChar { it.uppercase() })) {
                // identity.provision: the key at the top level of the body.
                val provision = JSONObject().put("eoa", validEoa).put(spelling, "x")
                failures += expectRefused("provisionIdentity top", Command.PROVISION_IDENTITY, provision, spelling)

                // init: the key at the top level of the payload, and inside the identity object.
                val initTop = JSONObject().put("identity", JSONObject().put("eoa", validEoa)).put(spelling, "x")
                failures += expectRefused("init top", Command.INIT, initTop, spelling)
                val initIdentity = JSONObject().put("identity", JSONObject().put("eoa", validEoa).put(spelling, "x"))
                failures += expectRefused("init identity", Command.INIT, initIdentity, spelling)

                // A nested placement inside the identity object.
                val nested = JSONObject().put("identity", JSONObject().put("eoa", validEoa).put("wallet", JSONObject().put(spelling, "x")))
                failures += expectRefused("init nested", Command.INIT, nested, spelling)
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
        // Each entry: file name and the trimmed source line that contains the read, and the reason it is allowed.
        val allowed = mapOf(
            // The init handler reads the PGP fields only after validate(INIT) has refused any forbidden key (the check is recursive), so these
            // reads are unreachable for those names. Recorded for P-IMP-PGP (A4 audit finding F1); removal is a later clean-up.
            "BeamioConetChatModule.kt" to setOf(
                "pgpArmorInInit = id.optString(\"pgpPrivateKeyArmored\", \"\")",
                "pgpPassphraseInInit = id.optString(\"pgpPassphrase\", \"\")",
            ),
            // The native page-record copy (not a bridge payload): the W-field presence checks and the legacy import read the stored EOA profile.
            "ShellRecord.kt" to setOf(
                "!matches[0].has(\"privateKeyArmor\") -> \"needs_native_recovery\"",
                "fun accountHoldsEoaKey(record: JSONObject, eoa: String): Boolean = matchingProfiles(record, eoa).any { it.has(\"privateKeyArmor\") }",
                "if (profiles.optJSONObject(i)?.has(\"privateKeyArmor\") == true && i != pageSlot) unmatched += W_PROFILE_PATH",
                "if (storedProfile != null && storedProfile.has(\"privateKeyArmor\")) {",
                "val armor = profile?.optString(\"privateKeyArmor\", \"\").orEmpty()",
            ),
        )
        val pattern = Regex(
            "(optString|optJSONObject|optJSONArray|opt|get|getString|has|getJSONObject)\\(\\s*\"(" +
                forbidden.joinToString("|") + "|privateKeyArmored|pgpPrivateKeyArmor)\"",
        )
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
