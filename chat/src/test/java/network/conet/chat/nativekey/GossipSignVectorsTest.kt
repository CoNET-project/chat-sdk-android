package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * C2 `gossipSign` and the envelope/group cross-purpose rule, against `spec/gossip-sign-vectors.v1.json`
 * (sha256 de5e5d34…, spec §25.23.3). Every ok case must reproduce its `signature` byte for byte. Every
 * rejected case must return its `code`. The vector file is not edited to fit the implementation.
 */
class GossipSignVectorsTest {
    private val bytes = File(System.getenv("GOSSIP_SIGN_VECTORS") ?: "../spec/gossip-sign-vectors.v1.json").readBytes()
    private val v = JSONObject(String(bytes, Charsets.UTF_8))
    private val cases = v.getJSONArray("cases")

    private fun vaultWithTestKey(): NativeWalletVault {
        val vault = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val key = ConetChatCryptoUtil.hexToBytes(v.getString("privateKeyHex"))!!
        assertEquals(NativeWalletVault.Import.OK, vault.importKey(v.getString("eoa"), key))
        return vault
    }

    private fun caseById(id: String): JSONObject {
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("id") == id) return c
        }
        throw AssertionError("no case $id")
    }

    private fun messageOf(c: JSONObject): ByteArray = ConetChatCryptoUtil.hexToBytes(c.getString("messageUtf8Hex"))!!

    @Test
    fun vectorFileIsTheCanonicalOne() {
        val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("de5e5d34284db8bc8903879a0ec633fd5d537aa89fdca1e8144cce329c9d4705", sha)
    }

    @Test
    fun caseCountsMatchTheVector() {
        assertEquals(33, cases.length())
        val ok = (0 until cases.length()).count { cases.getJSONObject(it).getString("expect") == "ok" }
        assertEquals(13, ok)
        assertEquals(20, cases.length() - ok)
    }

    @Test
    fun everyCaseMatchesTheVector() {
        val vault = vaultWithTestKey()
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            // FX.1, FY.1 (R-1 to R-10): the request fields are checked before any signature, as the command does.
            val request = c.optJSONObject("request") ?: JSONObject()
            val pageDeferAck = c.optJSONObject("context")?.optBoolean("pageDeferAck", false) ?: false
            val refusal = SignRequestRule.check(c.getString("kind"), request, pageDeferAck)
            if (refusal != null) {
                assertEquals("$id code", c.getString("code"), refusal)
                continue
            }
            val out = NativeMessageSigner.sign(vault, c.getString("kind"), messageOf(c))
            if (c.getString("expect") == "ok") {
                assertEquals("$id code", "ok", out.code)
                assertEquals("$id signature", c.getString("signature"), out.value)
                assertEquals("$id recoveredAddress", c.getString("recoveredAddress"), out.address)
            } else {
                assertEquals("$id code", c.getString("code"), out.code)
                assertNull("$id must not return a signature", out.value)
            }
        }
    }

    @Test
    fun everyOkSignatureRecoversToTheVectorAddress() {
        val vault = vaultWithTestKey()
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("expect") != "ok") continue
            val sig = NativeMessageSigner.sign(vault, c.getString("kind"), messageOf(c)).value!!
            val raw = ConetChatCryptoUtil.hexToBytes(sig.removePrefix("0x"))!!
            val recovered = Eip191Signer.recoverPublicKey(
                Eip191Signer.hashMessage(messageOf(c)),
                java.math.BigInteger(1, raw.copyOfRange(0, 32)),
                java.math.BigInteger(1, raw.copyOfRange(32, 64)),
                raw[64].toInt() - 27,
            )!!
            val address = "0x" + ConetChatCryptoUtil.toHex(
                ConetChatCryptoUtil.keccak256(recovered.copyOfRange(1, recovered.size)).copyOfRange(12, 32),
            )
            assertEquals(c.getString("id"), c.getString("recoveredAddress"), address)
        }
    }

    @Test
    fun nfcAndNfdSignDifferently() {
        val nfc = caseById("U-1").getString("signature")
        val nfd = caseById("U-2").getString("signature")
        assertNotEquals("control: NFC and NFD must not share a signature", nfc, nfd)
    }

    @Test
    fun reorderedAckSignsDifferently() {
        // Control from the vector file: rebuilding the ack with other key order changes the signature,
        // so the caller's bytes must be signed exactly as given (no re-serialisation).
        val g1 = caseById("G-1")
        val original = String(messageOf(g1), Charsets.UTF_8)
        val o = JSONObject(original)
        val reordered = JSONObject()
            .put("walletAddress", o.getString("walletAddress"))
            .put("command", o.getString("command"))
            .put("armorHash", o.getString("armorHash"))
            .put("timestamp", o.getLong("timestamp"))
            .toString()
        assertNotEquals(original, reordered)
        val vault = vaultWithTestKey()
        val out = NativeMessageSigner.sign(vault, "gossip", reordered.toByteArray(Charsets.UTF_8))
        assertEquals("ok", out.code)
        assertNotEquals(g1.getString("signature"), out.value)
    }

    @Test
    fun withoutANativeKeyNothingIsSigned() {
        val empty = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        val out = NativeMessageSigner.sign(empty, "gossip", messageOf(caseById("G-1")))
        assertEquals("no_key", out.code)
        assertNull(out.value)
    }

    @Test
    fun aRecordThatCannotBeUnlockedSignsNothing() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = NativeWalletVault(wrap, files)
        assertEquals(NativeWalletVault.Import.OK, vault.importKey(v.getString("eoa"), ConetChatCryptoUtil.hexToBytes(v.getString("privateKeyHex"))!!))
        wrap.deleteKey()
        val out = NativeMessageSigner.sign(vault, "gossip", messageOf(caseById("G-1")))
        assertEquals("locked", out.code)
        assertNull(out.value)
        assertTrue(files.map.containsKey(NativeWalletVault.REC))
    }

    @Test
    fun signingKindsOutsideTheEnumerationIsRefused() {
        val vault = vaultWithTestKey()
        assertEquals("kind", NativeMessageSigner.sign(vault, "selfAuth", "x".toByteArray()).code)
        assertEquals("kind", NativeMessageSigner.sign(vault, "voice", "x".toByteArray()).code)
    }
}
