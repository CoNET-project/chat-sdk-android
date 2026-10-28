package network.conet.chat

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ConetChatCryptoUtilTest {
    @Test
    fun keccak256EmptyMatchesEthereumVector() {
        assertEquals(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256(ByteArray(0))),
        )
    }

    @Test
    fun keccak256AbcMatchesVector() {
        assertEquals(
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
            ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256("abc".toByteArray())),
        )
    }

    @Test
    fun keccak256CrossesRateBoundary() {
        // 200 bytes forces >1 absorb block (rate = 136). Length-stable and deterministic.
        val data = ByteArray(200) { (it * 7).toByte() }
        val a = ConetChatCryptoUtil.keccak256(data)
        val b = ConetChatCryptoUtil.keccak256(data.copyOf())
        assertEquals(32, a.size)
        assertArrayEquals(a, b)
        assertTrue(!a.contentEquals(ConetChatCryptoUtil.keccak256(data.copyOf(199))))
    }

    @Test
    fun registrySelectorsMatchKeccak() {
        fun sel(sig: String) = "0x" + ConetChatCryptoUtil.toHex(
            ConetChatCryptoUtil.keccak256(sig.toByteArray()).copyOf(4),
        )
        assertEquals(BeamioConetChatHistoryStore.SEL_GET_POINTER, sel("getPointer(address)"))
        assertEquals(BeamioConetChatHistoryStore.SEL_NONCE_OF, sel("nonceOf(address)"))
    }

    @Test
    fun hkdfMatchesRfc5869Case3() {
        // RFC 5869 test case 3 (empty salt/info) uses IKM = 22 x 0x0b, L = 42.
        val ikm = ByteArray(22) { 0x0b }
        val okm = ConetChatCryptoUtil.hkdf(ikm, "", 42)
        assertEquals(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            ConetChatCryptoUtil.toHex(okm),
        )
    }

    @Test
    fun aesGcmRoundTrip() {
        val key = ConetChatCryptoUtil.hkdf("master".toByteArray(), "frag|0|0x00", 32)
        val cipher = ConetChatCryptoUtil.aesGcmEncrypt(key, "héllo 世界".toByteArray())
        assertEquals("héllo 世界", String(ConetChatCryptoUtil.aesGcmDecrypt(key, cipher), Charsets.UTF_8))
    }

    @Test
    fun base64RoundTripAndRfcVectors() {
        assertEquals("Zm9vYmFy", ConetChatCryptoUtil.base64Encode("foobar".toByteArray()))
        assertEquals("Zm9vYg==", ConetChatCryptoUtil.base64Encode("foob".toByteArray()))
        assertEquals("Zm9vYmE=", ConetChatCryptoUtil.base64Encode("fooba".toByteArray()))
        assertEquals("foobar", String(ConetChatCryptoUtil.base64Decode("Zm9vYmFy")))
        assertEquals("foob", String(ConetChatCryptoUtil.base64Decode("Zm9vYg==")))
    }

    @Test
    fun inboundArmorIsReadFromJsonFrame() {
        val armor = "-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----"
        val frame = """{"data":"-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----"}"""
        val found = BeamioConetChatListenSession.findInboundArmor(frame)
        assertNotNull(found)
        assertEquals(armor, found)
    }

    @Test
    fun inboundPlaintextBase64IsUnwrapped() {
        val json = """{"text":"hi"}"""
        val b64 = ConetChatCryptoUtil.base64Encode(json.toByteArray())
        assertEquals(json, BeamioConetChatListenSession.normalizeInboundPlaintext(b64))
        assertEquals(json, BeamioConetChatListenSession.normalizeInboundPlaintext(json))
    }

    @Test
    fun ipNormalization() {
        assertEquals("1.2.3.4", BeamioSiCipherPost.normalizeIp(" 1.2.3.4 "))
        assertEquals(null, BeamioSiCipherPost.normalizeIp("01.2.3.4"))
        assertEquals(null, BeamioSiCipherPost.normalizeIp("example.com"))
        assertEquals("http://1.2.3.4/post", BeamioSiCipherPost.postUrl("1.2.3.4"))
    }
}
