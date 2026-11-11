package network.conet.chat.localread

import network.conet.chat.ConetChatCryptoUtil
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Stable message id and sort order, interface spec v1.0 sections 3–5.
 * Pure JVM code (no Android types) so it runs in JVM unit tests.
 */
object LocalChatIds {
    private const val SEP: Byte = 0x1f
    private const val ID_KEY_INFO = "chat-local-id-v1"

    /** K_id = HKDF-SHA256(master, "chat-local-id-v1", 32). */
    fun idKey(master: ByteArray): ByteArray = ConetChatCryptoUtil.hkdf(master, ID_KEY_INFO, 32)

    /**
     * stable_id (spec 4.1): `sendId` when non-empty; otherwise
     * `"h:" + base64url(HMAC-SHA256(K_id, conv ‖ 0x1f ‖ dir ‖ 0x1f ‖ decimal(sortTs) ‖ 0x1f ‖ SHA256(body)))`.
     */
    fun stableId(idKey: ByteArray, convKey: String, dir: String, sortTs: Long, body: String, sendId: String?): String {
        if (!sendId.isNullOrEmpty()) return sendId
        val bodyHash = MessageDigest.getInstance("SHA-256").digest(body.toByteArray(Charsets.UTF_8))
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(idKey, "HmacSHA256"))
        mac.update(convKey.toByteArray(Charsets.UTF_8))
        mac.update(SEP)
        mac.update(dir.toByteArray(Charsets.UTF_8))
        mac.update(SEP)
        mac.update(sortTs.toString().toByteArray(Charsets.US_ASCII))
        mac.update(SEP)
        mac.update(bodyHash)
        return "h:" + base64Url(mac.doFinal())
    }

    /** Sort key comparison (spec 3): sort_ts numeric, then stable_id by UTF-8 bytes. */
    fun compareKey(aTs: Long, aId: String, bTs: Long, bId: String): Int {
        if (aTs != bTs) return if (aTs < bTs) -1 else 1
        return compareUtf8(aId, bId)
    }

    /** Unsigned byte-wise comparison of the UTF-8 encodings. */
    fun compareUtf8(a: String, b: String): Int {
        val x = a.toByteArray(Charsets.UTF_8)
        val y = b.toByteArray(Charsets.UTF_8)
        val n = minOf(x.size, y.size)
        for (i in 0 until n) {
            val c = (x[i].toInt() and 0xff) - (y[i].toInt() and 0xff)
            if (c != 0) return c
        }
        return x.size - y.size
    }

    private const val B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    /** Unpadded base64url. Written by hand: java.util.Base64 is not available below API 26 (minSdk 24). */
    fun base64Url(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size + 2) / 3 * 4)
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xff
            val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xff else 0
            val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xff else 0
            out.append(B64URL[b0 shr 2])
            out.append(B64URL[((b0 and 3) shl 4) or (b1 shr 4)])
            if (i + 1 < bytes.size) out.append(B64URL[((b1 and 15) shl 2) or (b2 shr 6)])
            if (i + 2 < bytes.size) out.append(B64URL[b2 and 63])
            i += 3
        }
        return out.toString()
    }
}
