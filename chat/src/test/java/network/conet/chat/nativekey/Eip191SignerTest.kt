package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.math.BigInteger

/**
 * EIP-191 signing against ethers 6 (the known answers were computed with `Wallet.signMessage` in the
 * repository's node_modules), plus a check that every signature recovers to the signing address.
 */
class Eip191SignerTest {
    private fun key(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        val n = minOf(raw.size, 32)
        System.arraycopy(raw, raw.size - n, out, 32 - n, n)
        return out
    }

    private fun addressOf(publicKeyUncompressed: ByteArray): String {
        val digest = ConetChatCryptoUtil.keccak256(publicKeyUncompressed.copyOfRange(1, publicKeyUncompressed.size))
        return "0x" + ConetChatCryptoUtil.toHex(digest.copyOfRange(12, 32))
    }

    private fun recoverAddress(message: ByteArray, signature: String): String {
        val raw = ConetChatCryptoUtil.hexToBytes(signature.removePrefix("0x"))!!
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        val recid = raw[64].toInt() - 27
        val pub = Eip191Signer.recoverPublicKey(Eip191Signer.hashMessage(message), r, s, recid)
        assertNotNull("no public key for recid $recid", pub)
        return addressOf(pub!!)
    }

    @Test
    fun hashOfHelloMatchesEthers() {
        assertEquals(
            "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750",
            ConetChatCryptoUtil.toHex(Eip191Signer.hashMessage("hello".toByteArray(Charsets.UTF_8))),
        )
    }

    @Test
    fun keyOneSigningHelloMatchesEthers() {
        val sig = Eip191Signer.sign(key(BigInteger.ONE), "hello".toByteArray(Charsets.UTF_8))
        assertEquals(
            "0xe5ddc160e4c8f92de507c7db9b982d4f9b7197bfa421864aeadc586bc96b09ae0ba0c5b131650ae4994cff1839341d00f3735ef5abc62ac8fe2cf50f65208e2a1b",
            sig,
        )
    }

    @Test
    fun everySignatureIsLowSAndRecoversToTheSigner() {
        for (k in listOf(BigInteger.ONE, BigInteger.TWO, BigInteger("11".repeat(32), 16))) {
            for (msg in listOf("", "a", "hello", "x".repeat(300))) {
                val bytes = msg.toByteArray(Charsets.UTF_8)
                val sig = Eip191Signer.sign(key(k), bytes)
                assertNotNull(sig)
                val raw = ConetChatCryptoUtil.hexToBytes(sig!!.removePrefix("0x"))!!
                val s = BigInteger(1, raw.copyOfRange(32, 64))
                assertEquals("low-s", true, s <= BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16))
                assertEquals(WalletAddress.fromPrivateKey(key(k)), recoverAddress(bytes, sig))
            }
        }
    }

    @Test
    fun invalidKeysAreNotSigned() {
        assertNull(Eip191Signer.sign(ByteArray(32), "x".toByteArray()))
        assertNull(Eip191Signer.sign(ByteArray(31) { 1 }, "x".toByteArray()))
    }
}
