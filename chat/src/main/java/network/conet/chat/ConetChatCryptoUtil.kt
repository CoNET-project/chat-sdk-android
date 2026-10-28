package network.conet.chat

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Pure-JVM helpers for the encrypted history ratchet. No key material is logged
 * and none of these functions touches the EOA private key.
 */
internal object ConetChatCryptoUtil {
    private val random = SecureRandom()

    // ---- keccak256 (Ethereum, original 0x01 padding — not SHA3-256) ---------------

    private val RC = longArrayOf(
        0x0000000000000001UL.toLong(), 0x0000000000008082UL.toLong(),
        0x800000000000808AUL.toLong(), 0x8000000080008000UL.toLong(),
        0x000000000000808BUL.toLong(), 0x0000000080000001UL.toLong(),
        0x8000000080008081UL.toLong(), 0x8000000000008009UL.toLong(),
        0x000000000000008AUL.toLong(), 0x0000000000000088UL.toLong(),
        0x0000000080008009UL.toLong(), 0x000000008000000AUL.toLong(),
        0x000000008000808BUL.toLong(), 0x800000000000008BUL.toLong(),
        0x8000000000008089UL.toLong(), 0x8000000000008003UL.toLong(),
        0x8000000000008002UL.toLong(), 0x8000000000000080UL.toLong(),
        0x000000000000800AUL.toLong(), 0x800000008000000AUL.toLong(),
        0x8000000080008081UL.toLong(), 0x8000000000008080UL.toLong(),
        0x0000000080000001UL.toLong(), 0x8000000080008008UL.toLong(),
    )
    private val ROTC = intArrayOf(
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    )
    private val PILN = intArrayOf(
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    )

    private fun keccakF(st: LongArray) {
        val bc = LongArray(5)
        for (round in 0 until 24) {
            for (i in 0 until 5) {
                bc[i] = st[i] xor st[i + 5] xor st[i + 10] xor st[i + 15] xor st[i + 20]
            }
            for (i in 0 until 5) {
                val t = bc[(i + 4) % 5] xor java.lang.Long.rotateLeft(bc[(i + 1) % 5], 1)
                var j = 0
                while (j < 25) {
                    st[j + i] = st[j + i] xor t
                    j += 5
                }
            }
            var t = st[1]
            for (i in 0 until 24) {
                val j = PILN[i]
                val b = st[j]
                st[j] = java.lang.Long.rotateLeft(t, ROTC[i])
                t = b
            }
            var j = 0
            while (j < 25) {
                for (i in 0 until 5) bc[i] = st[j + i]
                for (i in 0 until 5) {
                    st[j + i] = st[j + i] xor (bc[(i + 1) % 5].inv() and bc[(i + 2) % 5])
                }
                j += 5
            }
            st[0] = st[0] xor RC[round]
        }
    }

    private fun absorb(st: LongArray, block: ByteArray, off: Int, rate: Int) {
        for (i in 0 until rate / 8) {
            var lane = 0L
            for (b in 0 until 8) {
                lane = lane or ((block[off + i * 8 + b].toLong() and 0xFFL) shl (8 * b))
            }
            st[i] = st[i] xor lane
        }
    }

    fun keccak256(data: ByteArray): ByteArray {
        val rate = 136
        val st = LongArray(25)
        var off = 0
        while (data.size - off >= rate) {
            absorb(st, data, off, rate)
            keccakF(st)
            off += rate
        }
        val last = ByteArray(rate)
        System.arraycopy(data, off, last, 0, data.size - off)
        last[data.size - off] = (last[data.size - off].toInt() xor 0x01).toByte()
        last[rate - 1] = (last[rate - 1].toInt() xor 0x80).toByte()
        absorb(st, last, 0, rate)
        keccakF(st)
        val out = ByteArray(32)
        for (i in 0 until 32) {
            out[i] = ((st[i / 8] ushr (8 * (i % 8))) and 0xFFL).toByte()
        }
        return out
    }

    /** `0x…` keccak256 of the UTF-8 bytes (matches `ethers.keccak256(ethers.toUtf8Bytes(s))`). */
    fun keccakUtf8Hex(text: String): String = "0x" + toHex(keccak256(text.toByteArray(Charsets.UTF_8)))

    // ---- HKDF-SHA256 (RFC 5869, empty salt) ------------------------------------

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // Mac rejects zero-length keys on some providers; RFC 5869 zero-fills them anyway.
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun hkdf(master: ByteArray, info: String, length: Int = 32): ByteArray {
        val prk = hmacSha256(ByteArray(32), master)
        val infoBytes = info.toByteArray(Charsets.UTF_8)
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var produced = 0
        var counter = 1
        while (produced < length) {
            previous = hmacSha256(prk, previous + infoBytes + byteArrayOf(counter.toByte()))
            val n = minOf(previous.size, length - produced)
            System.arraycopy(previous, 0, out, produced, n)
            produced += n
            counter++
        }
        return out
    }

    // ---- base64 (no android.util / java.util.Base64 so minSdk 24 + JVM tests both work) ----

    private const val B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun base64Encode(data: ByteArray): String {
        val sb = StringBuilder((data.size + 2) / 3 * 4)
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xFF
            val b1 = if (i + 1 < data.size) data[i + 1].toInt() and 0xFF else -1
            val b2 = if (i + 2 < data.size) data[i + 2].toInt() and 0xFF else -1
            sb.append(B64[b0 shr 2])
            sb.append(B64[((b0 and 0x03) shl 4) or (if (b1 >= 0) b1 shr 4 else 0)])
            sb.append(if (b1 >= 0) B64[((b1 and 0x0F) shl 2) or (if (b2 >= 0) b2 shr 6 else 0)] else '=')
            sb.append(if (b2 >= 0) B64[b2 and 0x3F] else '=')
            i += 3
        }
        return sb.toString()
    }

    fun base64Decode(text: String): ByteArray {
        val clean = text.filter { !it.isWhitespace() }.trimEnd('=')
        val out = java.io.ByteArrayOutputStream(clean.length * 3 / 4)
        var buffer = 0
        var bits = 0
        for (ch in clean) {
            val v = B64.indexOf(ch)
            require(v >= 0) { "bad_base64" }
            buffer = (buffer shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((buffer shr bits) and 0xFF)
            }
        }
        return out.toByteArray()
    }

    // ---- AES-256-GCM: base64(nonce(12) || ciphertext || tag(16)) --------------

    fun aesGcmEncrypt(key: ByteArray, plaintext: ByteArray): String {
        val nonce = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        val sealed = cipher.doFinal(plaintext)
        return base64Encode(nonce + sealed)
    }

    fun aesGcmDecrypt(key: ByteArray, b64: String): ByteArray {
        val combined = base64Decode(b64)
        require(combined.size > 12 + 16) { "ciphertext_too_short" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(128, combined, 0, 12),
        )
        return cipher.doFinal(combined, 12, combined.size - 12)
    }

    // ---- hex --------------------------------------------------------------------

    fun toHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) sb.append(String.format("%02x", b.toInt() and 0xFF))
        return sb.toString()
    }

    fun hexToBytes(hex: String): ByteArray? {
        var h = hex.trim().lowercase()
        if (h.startsWith("0x")) h = h.substring(2)
        if (h.length % 2 != 0) return null
        val out = ByteArray(h.length / 2)
        for (i in out.indices) {
            val v = h.substring(i * 2, i * 2 + 2).toIntOrNull(16) ?: return null
            out[i] = v.toByte()
        }
        return out
    }
}
