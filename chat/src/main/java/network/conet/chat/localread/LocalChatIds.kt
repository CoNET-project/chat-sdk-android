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
    private const val IDX_KEY_INFO = "chat-local-idx-v1"

    private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOption.IGNORE_CASE)

    /** K_id = HKDF-SHA256(master, "chat-local-id-v1", 32): sendKey derivation (spec v1.1 4.1). */
    fun idKey(master: ByteArray): ByteArray = ConetChatCryptoUtil.hkdf(master, ID_KEY_INFO, 32)

    /** K_idx from the protocol root: superseded by [idxKeyFromRootDb] (spec v1.1-r1); kept for compatibility tests. */
    fun idxKey(master: ByteArray): ByteArray = ConetChatCryptoUtil.hkdf(master, IDX_KEY_INFO, 32)

    /** RFC 5869 HKDF-SHA256 with an explicit salt (empty salt = HashLen zero bytes). */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        val out = java.io.ByteArrayOutputStream()
        var t = ByteArray(0)
        var i = 1
        while (out.size() < length) {
            t = hmacSha256(prk, t + info + byteArrayOf(i.toByte()))
            out.write(t)
            i++
        }
        return out.toByteArray().copyOf(length)
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /**
     * R_db = HKDF(ikm = P (32-byte private key), salt "beamio-chat-local-root|salt|v1",
     * info "beamio-chat-local-root|v1|" + eoa + "|" + workspace) (spec v1.1-r1 vectors, roots.R_db_from).
     * Only the wallet boundary may call this; P itself is never returned.
     */
    fun rootDbFromPrivateKey(privateKey: ByteArray, eoa: String, workspace: String): ByteArray =
        hkdfSha256(
            privateKey,
            "beamio-chat-local-root|salt|v1".toByteArray(Charsets.UTF_8),
            "beamio-chat-local-root|v1|$eoa|$workspace".toByteArray(Charsets.UTF_8),
            32,
        )

    /** DEK = HKDF(ikm = R_db, salt "beamio-chat-local-db|salt|v1", info "beamio-chat-local-db|v1|" + eoa + "|" + workspace). */
    fun dekFromRootDb(rootDb: ByteArray, eoa: String, workspace: String): ByteArray =
        hkdfSha256(
            rootDb,
            "beamio-chat-local-db|salt|v1".toByteArray(Charsets.UTF_8),
            "beamio-chat-local-db|v1|$eoa|$workspace".toByteArray(Charsets.UTF_8),
            32,
        )

    /** K_id = HKDF(R_db, "chat-local-id-v1") (spec v1.1-r1: new derivations use R_db). */
    fun idKeyFromRootDb(rootDb: ByteArray): ByteArray = ConetChatCryptoUtil.hkdf(rootDb, ID_KEY_INFO, 32)

    /** K_idx = HKDF(R_db, "chat-local-idx-v1") (spec v1.1-r1: local-DB root, not the protocol root). */
    fun idxKeyFromRootDb(rootDb: ByteArray): ByteArray = ConetChatCryptoUtil.hkdf(rootDb, IDX_KEY_INFO, 32)

    /** conv_blind = base64url(HMAC-SHA256(K_idx, UTF8(convKey))) (spec v1.1-r1 vectors). */
    fun convBlind(idxKey: ByteArray, convKey: String): String = base64Url(hmacSha256(idxKey, convKey.toByteArray(Charsets.UTF_8)))

    /** UUID format. Real and legacy UUIDs are both kept as sendKey (spec v1.1-r1 4.1); kept for diagnostics. */
    fun isLegacyUuid(sendId: String): Boolean = UUID_RE.matches(sendId)

    /** Content digest for collapsing (spec v1.1-r1 4.5): SHA256(peer | dir | ts | SHA256(body)) as hex. */
    fun contentDigest(peer: String, dir: String, ts: Long, body: String): String {
        val bodyHash = MessageDigest.getInstance("SHA-256").digest(body.toByteArray(Charsets.UTF_8))
        val msg = peer.toByteArray(Charsets.UTF_8) + byteArrayOf(SEP) + dir.toByteArray(Charsets.UTF_8) +
            byteArrayOf(SEP) + ts.toString().toByteArray(Charsets.US_ASCII) + byteArrayOf(SEP) + bodyHash
        return ConetChatCryptoUtil.toHex(MessageDigest.getInstance("SHA-256").digest(msg))
    }

    /**
     * sendKey (spec v1.1 4.1). A non-empty, non-UUID sendId is the sendKey. Otherwise the key is
     * "x" + base64url(HMAC(K_id, peer ‖ 0x1f ‖ dir ‖ 0x1f ‖ decimal(ts) ‖ 0x1f ‖ SHA256(body))).
     * Needs the body when derived; returns null when it is missing.
     */
    fun sendKey(idKey: ByteArray, peer: String, sendId: String?, dir: String, ts: Long, body: String?): String? {
        if (!sendId.isNullOrEmpty()) return sendId
        if (body == null) return null
        return sendKeyDerived(idKey, peer, dir, ts, body)
    }

    /** The derived sendKey, regardless of any sendId (also what the append path writes as sendId). */
    fun sendKeyDerived(idKey: ByteArray, peer: String, dir: String, ts: Long, body: String): String {
        val bodyHash = MessageDigest.getInstance("SHA-256").digest(body.toByteArray(Charsets.UTF_8))
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(idKey, "HmacSHA256"))
        mac.update(peer.toByteArray(Charsets.UTF_8))
        mac.update(SEP)
        mac.update(dir.toByteArray(Charsets.UTF_8))
        mac.update(SEP)
        mac.update(ts.toString().toByteArray(Charsets.US_ASCII))
        mac.update(SEP)
        mac.update(bodyHash)
        return "x" + base64Url(mac.doFinal())
    }

    /** stable_id = base64url(HMAC-SHA256(K_idx, UTF8(sendKey))), 43 ASCII characters (spec v1.1 4.3). */
    fun stableIdOf(idxKey: ByteArray, sendKey: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(idxKey, "HmacSHA256"))
        return base64Url(mac.doFinal(sendKey.toByteArray(Charsets.UTF_8)))
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
