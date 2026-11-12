package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import java.math.BigInteger

/**
 * EIP-191 `personal_sign` over raw bytes, the same bytes `ethers.Wallet.signMessage` signs: deterministic
 * k (RFC 6979, HMAC-SHA256), low-s, and `v` = 27 + recovery id. Lightweight BouncyCastle API only.
 */
object Eip191Signer {
    private val CURVE = SECNamedCurves.getByName("secp256k1")
    private val N: BigInteger = CURVE.n
    private val HALF_N: BigInteger = N.shiftRight(1)
    private val P: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    private val DOMAIN = ECDomainParameters(CURVE.curve, CURVE.g, N, CURVE.h)

    /** keccak256("\x19Ethereum Signed Message:\n" + len + message), len in bytes. */
    fun hashMessage(message: ByteArray): ByteArray {
        val prefix = "\u0019Ethereum Signed Message:\n${message.size}".toByteArray(Charsets.US_ASCII)
        return ConetChatCryptoUtil.keccak256(prefix + message)
    }

    /** `0x` + r || s || v (65 bytes, lower case), or `null` when [privateKey] is not a valid scalar. */
    fun sign(privateKey: ByteArray, message: ByteArray): String? {
        if (privateKey.size != 32) return null
        val d = BigInteger(1, privateKey)
        if (d.signum() <= 0 || d >= N) return null
        val hash = hashMessage(message)
        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        signer.init(true, ECPrivateKeyParameters(d, DOMAIN))
        val rs = signer.generateSignature(hash)
        val r = rs[0]
        var s = rs[1]
        if (s > HALF_N) s = N.subtract(s)
        val pub = CURVE.g.multiply(d).normalize().getEncoded(false)
        val recid = recoveryId(hash, r, s, pub) ?: return null
        val out = ByteArray(65)
        System.arraycopy(fixed32(r), 0, out, 0, 32)
        System.arraycopy(fixed32(s), 0, out, 32, 32)
        out[64] = (27 + recid).toByte()
        return "0x" + ConetChatCryptoUtil.toHex(out)
    }

    /** Uncompressed public key recovered from (hash, r, s, recid), or `null` when no point exists. */
    fun recoverPublicKey(hash: ByteArray, r: BigInteger, s: BigInteger, recid: Int): ByteArray? {
        if (r.signum() <= 0 || r >= N || s.signum() <= 0 || s >= N) return null
        val x = if (recid and 2 != 0) r.add(N) else r
        if (x >= P) return null
        val compressed = ByteArray(33)
        compressed[0] = if (recid and 1 == 0) 2 else 3
        System.arraycopy(fixed32(x), 0, compressed, 1, 32)
        val rPoint = try {
            CURVE.curve.decodePoint(compressed)
        } catch (e: IllegalArgumentException) {
            return null
        }
        val e = BigInteger(1, hash).mod(N)
        val rInv = r.modInverse(N)
        val eNeg = N.subtract(e).mod(N)
        val q = rPoint.multiply(s).add(CURVE.g.multiply(eNeg)).multiply(rInv).normalize()
        if (q.isInfinity) return null
        return q.getEncoded(false)
    }

    private fun recoveryId(hash: ByteArray, r: BigInteger, s: BigInteger, pub: ByteArray): Int? {
        for (recid in 0..3) {
            val q = recoverPublicKey(hash, r, s, recid) ?: continue
            if (q.contentEquals(pub)) return recid
        }
        return null
    }

    private fun fixed32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        val n = minOf(raw.size, 32)
        System.arraycopy(raw, raw.size - n, out, 32 - n, n)
        return out
    }
}
