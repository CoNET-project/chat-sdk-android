package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * W5 chatRouteRegister against chat-route-register-vectors.v1.json (spec 25.28.3 to 25.28.5; PM R2085 segment f). PV-1 to PV-4 are checked
 * byte for byte: the message, the backup, both hashes and the EIP-191 signature. The request-shape negatives NR-01 to NR-12 are checked at
 * the core (NR-13 to NR-16 are gate answers and are tested with the bridge).
 */
class ChatRouteRegisterVectorsTest {
    private fun resource(name: String): JSONObject =
        JSONObject(javaClass.classLoader!!.getResource(name)!!.readText(Charsets.UTF_8))

    private fun bytesOf(hex: String): ByteArray {
        val clean = hex.removePrefix("0x")
        return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    /** The PGP armor of a positive, found in the backup-compat vector by its SHA-256 (the route vector names only the hash). */
    private fun armorBySha(sha: String): ByteArray? {
        val backup = resource("pgp-backup-compat-vectors.v1.json")
        val list = backup.getJSONArray("positives")
        for (i in 0 until list.length()) {
            val armor = list.getJSONObject(i).optJSONObject("pgp")?.optString("privateArmor", "") ?: continue
            if (armor.isNotEmpty() && MessageDigest.getInstance("SHA-256").digest(armor.toByteArray(Charsets.UTF_8))
                    .joinToString("") { "%02x".format(it) } == sha) return armor.toByteArray(Charsets.UTF_8)
        }
        return null
    }

    private fun requestOf(input: JSONObject): JSONObject = JSONObject()
        .put("type", "chatRouteRegister").put("reqId", "r-1")
        .put("keyID", input.getString("keyID"))
        .put("publicKeyArmored", input.getString("publicKeyArmoredBase64"))
        .put("routeKeyID", input.getString("routeKeyID"))

    @Test
    fun positivesMatchTheVectorByteForByte() {
        val vectors = resource("chat-route-register-vectors.v1.json").getJSONArray("positives")
        assertTrue(vectors.length() >= 4)
        for (i in 0 until vectors.length()) {
            val p = vectors.getJSONObject(i)
            val input = p.getJSONObject("input")
            val parsed = ChatRouteRegister.parse(requestOf(input))
            assertTrue("${p.getString("id")} request", parsed is ChatRouteRegister.Parsed.Ok)
            val armor = armorBySha(input.getString("pgpPrivateArmorSha256"))
            assertTrue("${p.getString("id")} armor", armor != null)
            val built = ChatRouteRegister.build(
                request = (parsed as ChatRouteRegister.Parsed.Ok).request,
                wallet = input.getString("wallet"),
                eoaPrivateKey = bytesOf(input.getString("eoaPrivateKeyString")),
                pgpPrivateArmor = armor,
                timestampMs = input.getLong("timestampMs"),
                nonce = input.getString("nonce"),
                iv = bytesOf(input.getString("backupIvHex")),
            )
            assertTrue("${p.getString("id")} built", built is ChatRouteRegister.Built.Ok)
            val ok = built as ChatRouteRegister.Built.Ok
            assertEquals(p.getString("id"), p.getString("message"), ok.message)
            assertEquals(p.getString("id"), p.getString("encrypKeyArmoredBase64"), ok.encrypKeyArmored)
            assertEquals(p.getString("id"), p.getString("encrypKeyArmoredHash"), ConetChatCryptoUtil.keccakUtf8Hex(ok.encrypKeyArmored))
            assertEquals(p.getString("id"), p.getString("publicKeyArmoredHash"), ConetChatCryptoUtil.keccakUtf8Hex(input.getString("publicKeyArmoredBase64")))
            assertEquals(p.getString("id"), p.getString("signature"), ok.signature)
            assertEquals(p.getString("id"), p.getString("recoveredAddress"), input.getString("wallet").lowercase())
        }
    }

    /** NR-01 to NR-10 are request-shape refusals (bad_request, before any state); NR-11 is sig_rejected; NR-12 no_pgp_key. */
    @Test
    fun requestNegativesAreRefusedAtTheCore() {
        val negatives = resource("chat-route-register-vectors.v1.json").getJSONArray("nativeRequestNegatives")
        val seen = mutableMapOf<String, String>()
        for (i in 0 until negatives.length()) {
            val n: JSONObject = negatives.getJSONObject(i)
            val id = n.getString("id")
            val expected = n.getJSONObject("expect").getString("code")
            if (id !in setOf("NR-01", "NR-02", "NR-03", "NR-04", "NR-05", "NR-06", "NR-07", "NR-08", "NR-09", "NR-10", "NR-11", "NR-12")) continue
            val req = n.getJSONObject("request")
            val actual = when (id) {
                "NR-12" -> {
                    val parsed = ChatRouteRegister.parse(req) as ChatRouteRegister.Parsed.Ok
                    val built = ChatRouteRegister.build(parsed.request, "0x9858effd232b4033e47d90003d41ec34ecaeda94",
                        bytesOf("0x" + "11".repeat(32)), null, 1L, "0x" + "00".repeat(16), ByteArray(12))
                    (built as ChatRouteRegister.Built.Refused).code
                }
                "NR-11" -> {
                    // The page's public key belongs to P-2; the vault is P-1 (PV-1's armor and EOA key): the fingerprints differ.
                    val pv1 = resource("chat-route-register-vectors.v1.json").getJSONArray("positives").getJSONObject(0).getJSONObject("input")
                    val parsed = ChatRouteRegister.parse(req) as ChatRouteRegister.Parsed.Ok
                    val built = ChatRouteRegister.build(parsed.request, pv1.getString("wallet"), bytesOf(pv1.getString("eoaPrivateKeyString")),
                        armorBySha(pv1.getString("pgpPrivateArmorSha256")), pv1.getLong("timestampMs"), pv1.getString("nonce"), bytesOf(pv1.getString("backupIvHex")))
                    (built as ChatRouteRegister.Built.Refused).code
                }
                else -> when (val parsed = ChatRouteRegister.parse(req)) {
                    is ChatRouteRegister.Parsed.Refused -> parsed.code
                    is ChatRouteRegister.Parsed.Ok -> "parsed"
                }
            }
            seen[id] = actual
            assertEquals(id, expected, actual)
        }
        assertEquals(12, seen.size)
    }

    @Test
    fun theForbiddenFieldListIsTheSpecList() {
        // spec 25.28.3: wallet, message, signature, timestamp, nonce, encrypKeyArmored, privateKeyHex, pgpPrivateKeyArmored are refused.
        for (name in listOf("wallet", "message", "signature", "timestamp", "nonce", "encrypKeyArmored", "privateKeyHex", "pgpPrivateKeyArmored")) {
            val req = JSONObject().put("type", "chatRouteRegister").put("reqId", "r").put("keyID", "6629DED57B806861")
                .put("publicKeyArmored", "AAAA").put("routeKeyID", "R").put(name, "x")
            assertEquals(name, "bad_request", (ChatRouteRegister.parse(req) as ChatRouteRegister.Parsed.Refused).code)
        }
        assertEquals(JSONArray::class.java, JSONArray::class.java)
    }
}
