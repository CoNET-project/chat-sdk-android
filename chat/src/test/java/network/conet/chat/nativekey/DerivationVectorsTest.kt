package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import network.conet.chat.localread.LocalChatIds
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * `spec/derivation-vectors.v1.json` (spec r3v §25.43): D-01 to D-10, W-01 and the negative cases N-01 to N-04. Every expected value
 * is read from the file. The inputs are the public BIP-39 test account (P, eoa) and the synthetic tk, sid, wk.
 */
class DerivationVectorsTest {
    private val raw = File(System.getenv("DERIVATION_VECTORS") ?: "../spec/derivation-vectors.v1.json").readBytes()
    private val doc = JSONObject(String(raw, Charsets.UTF_8))
    private val inputs = doc.getJSONObject("inputs")
    private val p = unhex(inputs.getString("P"))
    private val eoa = inputs.getString("eoa")
    private val workspace = inputs.getString("workspace")
    private val cases: Map<String, JSONObject> = doc.getJSONArray("cases").let { arr ->
        (0 until arr.length()).associate { arr.getJSONObject(it).getString("id") to arr.getJSONObject(it) }
    }

    private fun expectOf(id: String): JSONObject = cases.getValue(id).getJSONObject("expect")

    private fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun hex(b: ByteArray): String = NativeDerivation.hex(b)

    private fun rProto(): ByteArray = NativeDerivation.protocolRoot(NativeDerivation.historySignature(p, eoa)!!)

    /** EIP-55 checksum of a lower-case address, to form the mixed-case input of D-08. */
    private fun checksumAddress(lower: String): String {
        val body = lower.removePrefix("0x")
        val hash = ConetChatCryptoUtil.keccak256(body.toByteArray(Charsets.US_ASCII)).joinToString("") { "%02x".format(it) }
        val out = StringBuilder("0x")
        for ((i, ch) in body.withIndex()) {
            out.append(if (ch in '0'..'9' || hash[i].digitToInt(16) < 8) ch else ch.uppercaseChar())
        }
        return out.toString()
    }

    @Test
    fun vectorFileIsPinned() {
        val sha = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it) }
        // The r3cb copy (spec r3cb, 14 cases, D-11 to D-13 added). Previously 6b51f6f9… (11 cases).
        assertEquals("0c055b817026813b3a6cae38f8b4218a3b0655a22f2fa0352cdeec2be01d4d51", sha)
    }

    @Test
    fun d01HistoryDomainSignatureAndRoot() {
        val e = expectOf("D-01")
        assertEquals(e.getString("domain"), NativeDerivation.historyDomain(eoa))
        val s = NativeDerivation.historySignature(p, eoa)!!
        assertEquals(e.getString("S"), s)
        assertEquals(e.getInt("sUtf8Bytes"), s.toByteArray(Charsets.UTF_8).size)
        assertEquals(e.getString("RPROTO"), hex(NativeDerivation.protocolRoot(s)))
    }

    @Test
    fun d02IndexEncKey() {
        assertEquals(expectOf("D-02").getString("indexEncKey"), hex(NativeDerivation.indexEncKey(rProto())))
    }

    @Test
    fun d03GenesisCid() {
        val e = expectOf("D-03")
        assertEquals(e.getString("genesisCid"), NativeDerivation.genesisCid(rProto()))
        assertEquals(e.getString("genesisBytes"), NativeDerivation.genesisCid(rProto()).removePrefix("0x"))
    }

    @Test
    fun d04FragmentKeyZero() {
        val e = expectOf("D-04")
        assertEquals(e.getString("fragKey"), hex(NativeDerivation.fragmentKey(rProto(), e.getInt("seq"), e.getString("prevCid"))))
    }

    @Test
    fun d05FragmentKeyOne() {
        val e = expectOf("D-05")
        assertEquals(e.getString("fragKey"), hex(NativeDerivation.fragmentKey(rProto(), e.getInt("seq"), e.getString("prevCid"))))
    }

    @Test
    fun d06LocalRootIsTheVectorRoot() {
        // R_db is the root only: the test reads it through LocalChatIds, because C5 never returns it.
        val rDb = LocalChatIds.rootDbFromPrivateKey(p, eoa, workspace)
        assertEquals(expectOf("D-06").getString("RDB"), hex(rDb))
    }

    @Test
    fun d07SubkeysAreTheVectorChildren() {
        val e = expectOf("D-07")
        val k = NativeDerivation.subkeys(p, eoa, workspace)
        assertEquals(e.getString("kId"), hex(k.kId))
        assertEquals(e.getString("kIdx"), hex(k.kIdx))
        assertEquals(e.getString("dek"), hex(k.dek))
        assertEquals(e.getString("kcv"), k.kcv)
    }

    @Test
    fun d08MixedCaseAddressGivesADifferentDekFromTheSameRoot() {
        // The vector's negative: with the mixed-case address the DEK differs (dekMixedCaseWouldBe).
        val e = expectOf("D-08")
        val rDb = LocalChatIds.rootDbFromPrivateKey(p, eoa, workspace)
        val mixed = checksumAddress(eoa)
        assertNotEquals(mixed, eoa)
        val mixedDek = hex(LocalChatIds.dekFromRootDb(rDb, mixed, workspace))
        assertEquals(e.getString("dekMixedCaseWouldBe"), mixedDek)
        assertNotEquals(e.getString("dekLowercase"), mixedDek)
        // The SDK lower-cases the account before deriving, so the mixed-case input still gives the lower-case DEK.
        assertEquals(e.getString("dekLowercase"), hex(NativeDerivation.subkeys(p, mixed, workspace).dek))
    }

    @Test
    fun d09StableId() {
        val e = expectOf("D-09")
        val k = NativeDerivation.subkeys(p, eoa, workspace)
        assertEquals(e.getString("stableId"), LocalChatIds.stableIdOf(k.kIdx, e.getString("sendKey")))
    }

    @Test
    fun d10ConvBlind() {
        val e = expectOf("D-10")
        val k = NativeDerivation.subkeys(p, eoa, workspace)
        assertEquals(e.getString("convBlind"), LocalChatIds.convBlind(k.kIdx, e.getString("convKey")))
    }

    @Test
    fun w01VoiceListenTextAndTemporarySignature() {
        val e = expectOf("W-01")
        val tk = unhex(inputs.getString("tk").removePrefix("0x"))
        val text = NativeDerivation.voiceListenText(
            inputs.getString("sid"),
            inputs.getString("wk"),
            inputs.getString("relayKeyId"),
            inputs.getLong("timestamp"),
        )
        assertEquals(e.getString("text"), text)
        assertEquals(e.getString("temp"), WalletAddress.fromPrivateKey(tk))
        assertEquals(e.getString("tempSig"), NativeDerivation.voiceListenSignature(tk, text!!))
    }

    @Test
    fun n01C5ResultHoldsOnlyTheFourChildren() {
        // No R_db, R_proto or P in the result: the result type has four fields, and none of them is a root or the key.
        assertEquals(4, NativeDerivation.Subkeys::class.java.declaredFields.size)
        val rDb = LocalChatIds.rootDbFromPrivateKey(p, eoa, workspace)
        val k = NativeDerivation.subkeys(p, eoa, workspace)
        for (value in listOf(k.kId, k.kIdx, k.dek)) {
            assertFalse(hex(value) == hex(rDb))
            assertFalse(hex(value) == hex(p))
            assertFalse(hex(value) == hex(rProto()))
        }
    }

    @Test
    fun n02W7IsOnlyTheVoiceListenPurpose() {
        // A voicePay text (conet.voice.sse.pay.v3) is signed by the account under W5, never here: W7 builds only the listen text.
        val text = NativeDerivation.voiceListenText(inputs.getString("sid"), inputs.getString("wk"), "k", 1L)!!
        assertTrue(text.startsWith("conet.voice.sse.listen.v3|"))
        assertFalse(text.contains("conet.voice.sse.pay"))
    }

    @Test
    fun n03BadSidIsRefused() {
        val wk = inputs.getString("wk")
        assertNull(NativeDerivation.voiceListenText("0123456789ABCDEF0123456789ABCDEF", wk, "k", 1L))
        assertNull(NativeDerivation.voiceListenText("0123456789abcdef0123456789abcde", wk, "k", 1L))
        assertNull(NativeDerivation.voiceListenText("0123456789abcdef0123456789abcdeff", wk, "k", 1L))
    }

    @Test
    fun n04RelayKeyIdIsUpperCaseInTheText() {
        val text = NativeDerivation.voiceListenText(inputs.getString("sid"), inputs.getString("wk"), "syn-pgpkeyid-a-0001", 1762992000L)!!
        assertTrue(text.contains("|SYN-PGPKEYID-A-0001|"))
        assertFalse(text.contains("syn-pgpkeyid"))
    }
}
