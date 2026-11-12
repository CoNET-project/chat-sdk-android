package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.math.BigInteger

/**
 * secp256k1 private key to EOA. Expected addresses are public known-answer values; the last one was
 * also computed with ethers 6 (`new Wallet(key).address`) in the repository's node_modules.
 */
class WalletAddressTest {
    private fun key(hex64: String): ByteArray {
        val b = BigInteger(hex64, 16).toByteArray()
        // BigInteger may add a sign byte; keep the low 32 bytes.
        return b.copyOfRange(b.size - 32, b.size).also { require(it.size == 32) }
    }

    private fun scalar(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        val n = minOf(raw.size, 32)
        System.arraycopy(raw, raw.size - n, out, 32 - n, n)
        return out
    }

    @Test
    fun keyOneMapsToTheKnownAddress() {
        assertEquals("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", WalletAddress.fromPrivateKey(scalar(BigInteger.ONE)))
    }

    @Test
    fun keyTwoMapsToTheKnownAddress() {
        assertEquals("0x2b5ad5c4795c026514f8317c7a215e218dccd6cf", WalletAddress.fromPrivateKey(scalar(BigInteger.TWO)))
    }

    @Test
    fun repeatedElevenMapsToTheAddressEthersComputes() {
        assertEquals(
            "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a",
            WalletAddress.fromPrivateKey(key("11".repeat(32))),
        )
    }

    @Test
    fun outOfRangeAndWrongLengthAreRejected() {
        val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
        assertNull(WalletAddress.fromPrivateKey(scalar(BigInteger.ZERO)))
        assertNull(WalletAddress.fromPrivateKey(scalar(n)))
        assertNull(WalletAddress.fromPrivateKey(scalar(n.add(BigInteger.ONE))))
        assertEquals(
            "highest valid scalar is accepted",
            true,
            WalletAddress.fromPrivateKey(scalar(n.subtract(BigInteger.ONE)))?.startsWith("0x"),
        )
        assertNull(WalletAddress.fromPrivateKey(ByteArray(31) { 1 }))
        assertNull(WalletAddress.fromPrivateKey(ByteArray(33) { 1 }))
    }
}
