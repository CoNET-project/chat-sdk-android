package network.conet.chat.nativekey

import network.conet.chat.nativekey.MnemonicPreread.Answer
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Review (X5, 2026-11-17): a wrap failure other than an authentication failure (a keystore operation that throws a RuntimeException)
 * is transient, unknown, never Absent. A malformed record stays deterministic and is ignored when it is listed.
 */
class TransientVsDeterministicX5Test {
    private val phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val wrap = NativeTestWrap()
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p)))

    private val presentWrap: KeyWrap = object : KeyWrap by wrap {
        override fun presence(): WrapKeyPresence = WrapKeyPresence.PRESENT
    }

    /** The wrap's keystore operation throws a runtime exception (not an authentication failure). */
    private val throwingWrap: KeyWrap = object : KeyWrap by wrap {
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = throw IllegalStateException("keystore operation failed")
        override fun presence(): WrapKeyPresence = WrapKeyPresence.PRESENT
    }

    private fun markedFiles(mnem: ByteArray?): NativeTestFiles {
        val files = NativeTestFiles()
        files.map[NativeWalletVault.PENDING] = JSONObject().put("v", 1).put("utc", "2026-11-17T00:00:00Z").put("eoa", eoaOf(phraseA))
            .put("preWriteAliasAbsent", false).put("newRecordSha", JSONObject.NULL)
            .put("items", JSONArray().put(JSONObject().put("name", NativeWalletVault.MNEM).put("isolated", "${NativeWalletVault.MNEM}.isolated.20261117T000000Z.00000000")
                .put("oldSha", "00".repeat(32))))
            .toString().toByteArray(Charsets.UTF_8)
        if (mnem != null) files.map[NativeWalletVault.MNEM] = mnem
        return files
    }

    private fun validRecord(): ByteArray {
        val eoa = eoaOf(phraseA)
        val sealed = network.conet.chat.ConetChatCryptoUtil.toHex(wrap.seal(NativeWalletVault.mnemAad(eoa), phraseA.toByteArray(Charsets.UTF_8)))
        return JSONObject().put("record", NativeWalletVault.RECORD_VERSION).put("eoa", eoa).put("sealed", sealed).toString().toByteArray(Charsets.UTF_8)
    }

    @Test fun x5AWrapRuntimeFailureIsUnknownNotAbsent() {
        val files = markedFiles(validRecord())
        assertTrue("unknown, never Absent", MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(throwingWrap, files)) is Answer.Unknown)
    }

    /** Control: a malformed listed record (not JSON) is deterministic and ignored: with no other position, the answer is Absent (onboarding). */
    @Test fun aMalformedListedRecordIsIgnoredAsDeterministic() {
        val files = markedFiles("not json at all".toByteArray(Charsets.UTF_8))
        assertEquals(Answer.Absent, MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(presentWrap, files)))
    }
}
