package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.bouncycastle.asn1.sec.SECNamedCurves
import java.math.BigInteger

/**
 * EOA address from a secp256k1 private key (lightweight BouncyCastle API, bcprov already in the build;
 * no JCE provider is registered, so the Android provider conflict does not apply).
 * Address = last 20 bytes of keccak256(X || Y) of the uncompressed public key.
 */
object WalletAddress {
    private val CURVE = SECNamedCurves.getByName("secp256k1")
    private val N: BigInteger = CURVE.n

    /** Lower-case `0x` + 40 hex, or `null` when [key] is not 32 bytes in the range 1 .. n-1. */
    fun fromPrivateKey(key: ByteArray): String? {
        if (key.size != 32) return null
        val d = BigInteger(1, key)
        if (d.signum() <= 0 || d >= N) return null
        val encoded = CURVE.g.multiply(d).normalize().getEncoded(false) // 0x04 || X || Y
        val digest = ConetChatCryptoUtil.keccak256(encoded.copyOfRange(1, encoded.size))
        return "0x" + ConetChatCryptoUtil.toHex(digest.copyOfRange(12, 32))
    }
}
