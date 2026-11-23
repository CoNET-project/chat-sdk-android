package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The empty-store pre-read of a Ready vault without a verified phrase (protocol keyonly-onboarding):
 * key-only (the key record is read, the phrase position is empty, no intent) answers confirmed_missing; a phrase that is unreadable or invalid, or
 * an unknown read, answers read_error. The read changes nothing in the vault or the store; the signature, the no-page listen and the ShellRecord
 * source rule are not touched by this.
 */
class PrereadKeyOnlyTest {

    private val wrap = NativeTestWrap()
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val key = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private val eoa = checkNotNull(WalletAddress.fromPrivateKey(key))

    private fun snapshot(files: NativeTestFiles): Map<String, ByteArray> = files.map.mapValues { it.value.copyOf() }

    /** Positive: an empty store with a key-only vault answers confirmed_missing, and the vault and the files stay as they were. */
    @Test
    fun keyOnlyWithAnEmptyStoreIsConfirmedMissing() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, key))
        val vault = NativeWalletVault(wrap, files)
        assertEquals("the verdict is missing (key only)", NativeWalletVault.PhraseVerdict.MISSING, vault.phraseVerdict())
        val before = snapshot(files)
        val p = NativeSyncAck.prereadStorePayload("np", trusted(), vault = {
            PrereadStoreAnswer.VaultSource.Ready(eoa, { null }, { vault.phraseVerdict() == NativeWalletVault.PhraseVerdict.MISSING })
        }, current = { MnemonicSetStore.Current.Absent })
        assertEquals("confirmed_missing", p.getJSONObject("result").getString("code"))
        assertFalse(p.toString().contains(phrase))
        assertEquals("vault and store bytes are unchanged", before.keys, snapshot(files).keys)
        before.forEach { (k, v) -> assertTrue(k, v.contentEquals(files.map.getValue(k))) }
    }

    /** Negative: a phrase that cannot be verified (INVALID or UNKNOWN, keyOnly false) answers read_error. */
    @Test
    fun anUnverifiedPhraseIsReadError() {
        val p = PrereadStoreAnswer.answerWithVault(MnemonicSetStore.Current.Absent) {
            PrereadStoreAnswer.VaultSource.Ready(eoa, { null }, { false })
        }
        assertEquals("read_error", p.answer.getString("code"))
    }

    /** Negative: a Ready vault whose phrase read fails and which is not key-only is read_error, never confirmed_missing. */
    @Test
    fun aFailedPhraseReadIsReadErrorNotMissing() {
        val p = PrereadStoreAnswer.answerWithVault(MnemonicSetStore.Current.Absent) {
            PrereadStoreAnswer.VaultSource.Ready(eoa, { null })
        }
        assertEquals("read_error", p.answer.getString("code"))
    }

    /** Negative: a read fault of the key record with an empty phrase position is unknown, never confirmed_missing. */
    @Test
    fun aKeyRecordReadFaultWithAnEmptyStoreIsReadErrorNotMissing() {
        val files = NativeTestFiles()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, key))
        files.failRead = { name -> name == NativeWalletVault.REC }
        val vault = NativeWalletVault(wrap, files)
        assertFalse("a REC read fault is never key-only", vault.keyOnlyPreread())
        val p = NativeSyncAck.prereadStorePayload("np", trusted(), vault = {
            PrereadStoreAnswer.VaultSource.Ready(eoa, { null }, { vault.keyOnlyPreread() })
        }, current = { MnemonicSetStore.Current.Absent })
        assertEquals("read_error", p.getJSONObject("result").getString("code"))
    }

    /** Regression: the source rule for signing and the record layer is unchanged for an absent store with a Ready vault. */
    @Test
    fun theAbsentStoreStillFallsBackToTheVaultForSigningAndRecords() {
        val source = NativeSource.decide(NativeWalletVault.State.Ready(eoa), MnemonicSetStore.Current.Absent, null)
        assertTrue(source is NativeSource.Source.Vault)
        assertEquals(eoa.lowercase(), NativeSource.accountOf(source))
        assertNotNull(NativeSource.accountOf(source))
    }

    private fun trusted(): JSONObject = JSONObject().put("type", "nativeMnemonicPreread").put("reqId", "np").put("seq", 1).put("trustedOrigin", true)
}
