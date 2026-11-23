package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom

/**
 * The sidecar of the migration vectors, on the test side only (§25.52AL.3).
 *
 * The vectors keep their placeholder values (an armor `EOA`, an account `a1`). No key derives those, so a write that checks the form and the
 * derived address (§25.52N.9 Q1) would refuse the placeholders. This harness maps each placeholder to a key that really derives its address. The
 * keys are generated when the test runs, in memory only: they are not committed, not written to the spec, the vectors or a log, and they stand for
 * test accounts only. The vector files and their hashes are unchanged; only the copy the test reads is mapped.
 *
 * Mapping (profiles and the case context only; the states `ok` and `other` and the PGP key ids are not touched):
 * - keyID `a1` → the address of key A; `A1` → the same address in upper-case hex (a case difference only, as in the vector);
 *   `b2` → key B; `zz` → key C; the case context `eoa` `a1` → key A.
 * - privateKeyArmor `EOA` and `EOA2` and `NEW` → armor A (the account's own key); `OTHER` → armor C (another account's key). `x` is not a key and
 *   stays. Which vector expects a different key for a replacement is an open question for the interface owner (see the receipt).
 * The test accounts are [ACCOUNT] (key A) and [OTHER] (key B).
 */
internal object VectorSidecar {
    private val random = SecureRandom()

    /** A key that is a valid secp256k1 scalar. Generated per run; never written anywhere. */
    private fun freshKey(): ByteArray {
        while (true) {
            val k = ByteArray(32).also { random.nextBytes(it) }
            if (WalletAddress.fromPrivateKey(k) != null) return k
        }
    }

    private val keyA = freshKey()
    private val keyB = freshKey()
    private val keyC = freshKey()

    private fun armor(k: ByteArray): String = "0x" + k.joinToString("") { "%02x".format(it) }
    private fun address(k: ByteArray): String = requireNotNull(WalletAddress.fromPrivateKey(k)).lowercase()

    /** The test account of the vectors (key A). */
    val ACCOUNT: String = address(keyA)

    /** The armor of the test account's key (key A), in the canonical form. For fixtures the harness builds itself. */
    val ARMOR_OF_ACCOUNT: String = armor(keyA)

    /** The second test account of the vectors (key B). */
    val OTHER: String = address(keyB)

    private val addressA = address(keyA)
    private val addressB = address(keyB)
    private val addressC = address(keyC)

    private val keyIdMap: Map<String, String> = mapOf(
        "a1" to addressA,
        "A1" to "0x" + addressA.substring(2).uppercase(),
        "a2" to addressB,
        "b2" to addressB,
        "zz" to addressC,
    )

    private val armorMap: Map<String, String> = mapOf(
        "EOA" to armor(keyA),
        // EOA2 and NEW are the account's own key again (a second armor copy, or a replacement that derives the same account; WM-06, TR-46).
        "EOA2" to armor(keyA),
        "OTHER" to armor(keyC),
        "NEW" to armor(keyA),
    )

    /** A deep copy of [doc] with the placeholders of the profiles, the case context and `eoa` replaced. The input is not changed. */
    fun map(doc: JSONObject): JSONObject = transform(JSONObject(doc.toString())) as JSONObject

    private fun transform(node: Any?): Any? = when (node) {
        is JSONObject -> {
            for (key in node.keys().asSequence().toList()) {
                val value = node.opt(key)
                when {
                    key == "profiles" && value is JSONArray -> for (i in 0 until value.length()) {
                        value.optJSONObject(i)?.let { mapProfile(it) }
                    }
                    key == "eoa" && value == "a1" -> node.put(key, addressA)
                    else -> transform(value)
                }
            }
            node
        }
        is JSONArray -> {
            for (i in 0 until node.length()) transform(node.opt(i))
            node
        }
        else -> node
    }

    private fun mapProfile(profile: JSONObject) {
        val keyId = profile.opt("keyID")
        if (keyId is String) keyIdMap[keyId]?.let { profile.put("keyID", it) }
        val armor = profile.opt("privateKeyArmor")
        if (armor is String) armorMap[armor]?.let { profile.put("privateKeyArmor", it) }
    }
}
