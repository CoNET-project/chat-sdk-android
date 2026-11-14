package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import network.conet.chat.localread.LocalChatIds
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The derivation details of spec §25.43 (r3v): C1 `historySign`, W3 protocol keys, W4 fragment keys, C5 `deriveSubkeys` and the
 * W7 voice temporary signature. These are pure functions over key bytes that the native layer supplies. None of them logs a key.
 *
 * What may leave the native process is fixed by the spec: the C1 root is used in-process and never returned (§25.43.3); C5
 * returns the four children only (kId, kIdx, dek, kcv), never R_db, R_proto or P (§25.43.6); W7 returns the temporary key's
 * address and the signature only (§25.43.7). Output is lower-case hex without `0x` unless the spec says otherwise.
 */
internal object NativeDerivation {
    /** The chain id of the history domain (§25.43.3). */
    const val CHAIN_ID = 224422L

    private val SID_RE = Regex("^[0-9a-f]{32}$")

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    /** The C1 domain `beamio.chat.history.v1|224422|<eoa>` with the lower-case account (§25.43.3). */
    fun historyDomain(eoa: String): String = "beamio.chat.history.v1|$CHAIN_ID|${eoa.lowercase()}"

    /**
     * C1 `historySign` (§25.43.3): S = EIP-191(P, domain). Deterministic (RFC 6979) with low s, `v` 27 or 28, `0x` + 130 hex.
     * In-process only: the caller keeps S inside the native layer. `null` when [privateKey] is not a valid scalar.
     */
    fun historySignature(privateKey: ByteArray, eoa: String): String? =
        Eip191Signer.sign(privateKey, historyDomain(eoa).toByteArray(Charsets.UTF_8))

    /** R_proto = keccak256(utf8(S)), 32 bytes (§25.43.3). */
    fun protocolRoot(signature: String): ByteArray =
        ConetChatCryptoUtil.keccak256(signature.toByteArray(Charsets.UTF_8))

    /** W3 `indexEncKey` = HKDF(R_proto, "index-enc", 32) (§25.43.4). */
    fun indexEncKey(rProto: ByteArray): ByteArray = ConetChatCryptoUtil.hkdf(rProto, "index-enc", 32)

    /** W3 `genesisCid` = "0x" + hex(HKDF(R_proto, "frag-genesis", 32)), 66 characters (§25.43.4). */
    fun genesisCid(rProto: ByteArray): String = "0x" + hex(ConetChatCryptoUtil.hkdf(rProto, "frag-genesis", 32))

    /** W4 fragment key = HKDF(R_proto, "frag|" + decimal(seq) + "|" + prevCid, 32), with prevCid used as given (§25.43.5). */
    fun fragmentKey(rProto: ByteArray, seq: Int, prevCid: String): ByteArray =
        ConetChatCryptoUtil.fragmentKey(rProto, seq, prevCid)

    /** The C5 result: the four children only (§25.43.6). The root is not part of it. */
    class Subkeys(val kId: ByteArray, val kIdx: ByteArray, val dek: ByteArray, val kcv: String)

    /**
     * C5 `deriveSubkeys` (§25.43.6). The account is lower-cased before use, because the DEK differs with the case of the
     * address (D-08). The intermediate R_db is cleared before this returns.
     */
    fun subkeys(privateKey: ByteArray, eoa: String, workspace: String): Subkeys {
        val account = eoa.lowercase()
        val rDb = LocalChatIds.rootDbFromPrivateKey(privateKey, account, workspace)
        try {
            val dek = LocalChatIds.dekFromRootDb(rDb, account, workspace)
            val kcv = hex(hmac(dek, "kcv".toByteArray(Charsets.UTF_8)))
            return Subkeys(
                kId = LocalChatIds.idKeyFromRootDb(rDb),
                kIdx = LocalChatIds.idxKeyFromRootDb(rDb),
                dek = dek,
                kcv = kcv,
            )
        } finally {
            rDb.fill(0)
        }
    }

    /**
     * The W7 text for `voiceListen` (§25.43.7): `conet.voice.sse.listen.v3|<sid>|<wk>|<UPPER relayKeyId>|<decimal timestamp>`.
     * Only this one purpose exists here. `null` (bad_request) when sid is not 32 lower-case hex, wk is not base64 of 32 bytes,
     * or the timestamp is negative.
     */
    fun voiceListenText(sid: String, wk: String, relayKeyId: String, timestamp: Long): String? {
        if (!SID_RE.matches(sid)) return null
        val wkBytes = runCatching { Base64.getDecoder().decode(wk) }.getOrNull() ?: return null
        if (wkBytes.size != 32 || timestamp < 0) return null
        return "conet.voice.sse.listen.v3|$sid|$wk|${relayKeyId.uppercase()}|$timestamp"
    }

    /** W7 signature (§25.43.7): EIP-191 of [text] by the temporary key T. `null` when T is not a valid scalar. */
    fun voiceListenSignature(temporaryKey: ByteArray, text: String): String? =
        Eip191Signer.sign(temporaryKey, text.toByteArray(Charsets.UTF_8))

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}
