package network.conet.chat.nativekey

import network.conet.chat.nativekey.PrereadStoreAnswer.VaultSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The empty-store fallback of nativeMnemonicPreread. Synthetic data. The five
 * situations for an empty store: NoKey → confirmed_missing; Ready with a verified phrase → ok with the mnemonic; a null (unreadable) vault,
 * Locked (any reason), and a read that throws → read_error. Plus the mismatch rule: a current set whose EOA differs from the Ready vault account
 * is returned as it is, with the diagnostic code, and nothing changes in the vault.
 */
class PrereadStoreFallbackTest {

    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val other = "0x2222222222222222222222222222222222222222"

    /** Positive 1 (empty store, vault NoKey): confirmed_missing. */
    @Test
    fun emptyStoreAndNoKeyIsConfirmedMissing() {
        val r = PrereadStoreAnswer.answerWithVault(MnemonicSetStore.Current.Absent) { VaultSource.NoKey }
        assertEquals("confirmed_missing", r.answer.getString("code"))
        assertNull(r.diag)
    }

    /** Positive 2 (empty store, vault Ready with a verified phrase): ok with the mnemonic. */
    @Test
    fun emptyStoreAndReadyVaultWithPhraseIsOkWithTheMnemonic() {
        val r = PrereadStoreAnswer.answerWithVault(MnemonicSetStore.Current.Absent) { VaultSource.Ready(eoa, { phrase }) }
        assertEquals("ok", r.answer.getString("code"))
        assertEquals(phrase, r.answer.getString("mnemonic"))
    }

    /** Negative 3 (empty store, vault null/unreadable): read_error, never confirmed_missing. */
    @Test
    fun emptyStoreAndUnreadableVaultIsReadError() {
        val r = PrereadStoreAnswer.answerWithVault(MnemonicSetStore.Current.Absent) { VaultSource.Unreadable }
        assertEquals("read_error", r.answer.getString("code"))
    }

    /** Negative 4 (empty store, vault Locked): read_error (a Locked vault is mapped to Unreadable by the module), never confirmed_missing. */
    @Test
    fun emptyStoreAndLockedVaultIsReadError() {
        val r = PrereadStoreAnswer.answerWithVault(MnemonicSetStore.Current.Absent) { VaultSource.Unreadable }
        assertEquals("read_error", r.answer.getString("code"))
        assertFalse(r.answer.toString().contains("confirmed_missing"))
    }

    /** Negative 5 (empty store, the vault read throws): read_error. The throwing read is turned into Unreadable by the caller. */
    @Test
    fun emptyStoreAndThrowingVaultReadIsReadError() {
        val r = PrereadStoreAnswer.answerWithVault(MnemonicSetStore.Current.Absent) { throw IllegalStateException("injected") }
        assertEquals("read_error", r.answer.getString("code"))
    }

    /** Negative: a Ready vault with no verified phrase (key only) is read_error, never ok and never confirmed_missing. */
    @Test
    fun readyVaultWithoutAPhraseIsReadError() {
        val r = PrereadStoreAnswer.answerWithVault(MnemonicSetStore.Current.Absent) { VaultSource.Ready(eoa, { null }) }
        assertEquals("read_error", r.answer.getString("code"))
    }

    /** Positive 6 (mismatch): the store's current set is returned as it is, and the diagnostic code is reported; the vault is not changed. */
    @Test
    fun aStoreSetOfAnotherEoaIsReturnedWithTheDiagnosticOnly() {
        val current = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, phrase, 0)
        val r = PrereadStoreAnswer.answerWithVault(current) { VaultSource.Ready(other, { phrase }) }
        assertEquals("ok", r.answer.getString("code"))
        assertEquals(phrase, r.answer.getString("mnemonic"))
        assertEquals(PrereadStoreAnswer.DIAG_STORE_VAULT_EOA_MISMATCH, r.diag)
    }

    /** Positive: the same EOA gives no diagnostic; a store set with no vault key gives no diagnostic either. */
    @Test
    fun noDiagnosticForTheSameEoaOrWithoutAVaultAccount() {
        val current = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, phrase, 0)
        assertNull(PrereadStoreAnswer.answerWithVault(current) { VaultSource.Ready(eoa, { phrase }) }.diag)
        assertNull(PrereadStoreAnswer.answerWithVault(current) { VaultSource.NoKey }.diag)
        assertTrue(PrereadStoreAnswer.answerWithVault(current) { VaultSource.Unreadable }.answer.getString("code") == "ok")
    }

    /** Positive: a current set with a Ready vault reads only the account's EOA; the vault's phrase is never read. */
    @Test
    fun aCurrentSetNeverReadsTheVaultPhrase() {
        val current = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, phrase, 0)
        var phraseReads = 0
        val r = PrereadStoreAnswer.answerWithVault(current) {
            VaultSource.Ready(other, { phraseReads++; phrase })
        }
        assertEquals(0, phraseReads)
        assertEquals(PrereadStoreAnswer.DIAG_STORE_VAULT_EOA_MISMATCH, r.diag)
        assertEquals(phrase, r.answer.getString("mnemonic"))
    }
}
