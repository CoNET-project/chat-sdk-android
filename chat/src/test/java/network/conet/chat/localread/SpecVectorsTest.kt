package network.conet.chat.localread

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assume
import network.conet.chat.localread.ApplyResult
import network.conet.chat.localread.IncomingRecord
import network.conet.chat.localread.LocalChatStore
import network.conet.chat.localread.LocalMediaKind
import network.conet.chat.localread.LocalViewport
import network.conet.chat.localread.UnlockResult
import org.junit.Test
import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * spec v1.1-r1 section 23 (T-34): recomputes every value in `sendkey-vectors.json` with the
 * production functions. Input: `CHAT_VECTORS` = path to the file. Skipped when unset.
 * The vectors use public test material only (not any account key).
 */
class SpecVectorsTest {

    private fun hex(bytes: ByteArray): String = ConetChatCryptoUtil.toHex(bytes)
    private fun unhex(s: String): ByteArray = ConetChatCryptoUtil.hexToBytes(s)!!

    @Test
    fun recomputesEveryVector() {
        val path = System.getenv("CHAT_VECTORS")
        Assume.assumeTrue("CHAT_VECTORS not set", path != null)
        val v = JSONObject(File(path!!).readText(Charsets.UTF_8))
        val inputs = v.getJSONObject("inputs")
        val eoa = inputs.getString("eoa")
        val workspace = inputs.getString("workspace")
        val roots = v.getJSONObject("roots")
        val der = v.getJSONObject("derivations")

        // Roots: R_db from the private key P (inside the boundary), R_proto given (= keccak of the signature).
        val p = unhex(inputs.getString("P"))
        val rDb = LocalChatIds.rootDbFromPrivateKey(p, eoa, workspace)
        assertEquals(roots.getString("R_db"), hex(rDb))
        val rProto = unhex(roots.getString("R_proto"))

        // Keys.
        val kId = LocalChatIds.idKeyFromRootDb(rDb)
        assertEquals(der.getJSONObject("K_id").getString("hex"), hex(kId))
        val kIdx = LocalChatIds.idxKeyFromRootDb(rDb)
        assertEquals(der.getJSONObject("K_idx").getString("hex"), hex(kIdx))
        val dek = LocalChatIds.dekFromRootDb(rDb, eoa, workspace)
        assertEquals(der.getJSONObject("DEK").getString("hex"), hex(dek))
        val kcv = javax.crypto.Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(dek, "HmacSHA256")) }.doFinal("kcv".toByteArray())
        assertEquals(der.getJSONObject("kcv").getString("hex"), hex(kcv))

        // Blind index.
        val cb = v.getJSONObject("blindIndexes").getJSONObject("conv_blind")
        assertEquals(cb.getString("value"), LocalChatIds.convBlind(kIdx, cb.getString("convKey")))

        // sendKey and stable_id per case (spec 4.2, 4.3, 23.1).
        val cases = v.getJSONArray("sendKeyCases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val input = c.getJSONObject("input")
            val sendId = if (input.isNull("sendId")) null else input.getString("sendId")
            val body = input.getString("bodyUtf8")
            val sendKey = LocalChatIds.sendKey(kId, input.getString("peer"), sendId, input.getString("dir"),
                input.getString("ts").toLong(), body)!!
            assertEquals("sendKey ${c.getString("name")}", c.getString("sendKey"), sendKey)
            assertEquals("stable_id ${c.getString("name")}", c.getString("stableId"), LocalChatIds.stableIdOf(kIdx, sendKey))
        }

        // AES-GCM record format (spec 7.2 / 23.2): nonce ‖ ciphertext ‖ tag, AAD as given.
        val g = v.getJSONObject("aesGcm")
        val sealed = java.util.Base64.getDecoder().decode(g.getString("sealedBase64"))
        val nonce = unhex(g.getString("nonceHex"))
        val aad = unhex(g.getString("aadHex"))
        assertEquals(String(aad, Charsets.UTF_8), g.getString("aadUtf8"))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(dek, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        assertEquals(g.getString("plaintextUtf8"), String(cipher.doFinal(sealed.copyOfRange(12, sealed.size)), Charsets.UTF_8))
        // Content collapse (spec r1 4.5): two legacy mirrors fold to the earliest; the alias resolves to the survivor.
        val col = v.getJSONObject("collapse")
        fun caseNamed(name: String): JSONObject =
            (0 until cases.length()).map { cases.getJSONObject(it) }.first { it.getString("name") == name }
        val first = caseNamed(col.getString("first"))
        val second = caseNamed(col.getString("second"))
        assertEquals(col.getString("first"), first.getString("name"))
        assertEquals(col.getString("second"), second.getString("name"))
        assertEquals(col.getString("aliasBlindOfSecond"), LocalChatIds.stableIdOf(kIdx, second.getString("sendKey")))
        assertEquals(col.getString("survivorStableId"), LocalChatIds.stableIdOf(kIdx, first.getString("sendKey")))
        val store = LocalChatStore("$eoa:$workspace")
        assertEquals(UnlockResult.OK, store.unlock(rProto, rDb, null))
        val ts = first.getJSONObject("input").getString("ts").toLong()
        val body = first.getJSONObject("input").getString("bodyUtf8")
        val dir = first.getJSONObject("input").getString("dir")
        val peer = first.getJSONObject("input").getString("peer")
        assertEquals(ApplyResult.INSERTED, store.applyRecord(peer, IncomingRecord(dir, ts, LocalMediaKind.TEXT,
            first.getJSONObject("input").getString("sendId"), body, "cid-a")))
        assertEquals(ApplyResult.COLLAPSED, store.applyRecord(peer, IncomingRecord(dir, ts, LocalMediaKind.TEXT,
            second.getJSONObject("input").getString("sendId"), body, "cid-b")))
        assertEquals(1, store.openConversation(peer, LocalViewport(390.0, 844.0, "portrait", 1.0, 1)).items.size)
        println("LOCALREAD_VECTORS cases=${cases.length()} collapse=PASS result=PASS env=jvm-host")
    }
}
