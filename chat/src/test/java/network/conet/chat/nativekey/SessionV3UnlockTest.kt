package network.conet.chat.nativekey

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The in-session v3 unlock (design-in-session-passcode-v3). Synthetic phrase and passcode only. The held key lives in
 * process memory; it is found only for its own account; a reset or another account clears it; a v3 set answers signing and the no-page listen only
 * while the session is ready for its account; a wrong passcode leaves every set as it was.
 */
class SessionV3UnlockTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val other = "0x1111111111111111111111111111111111111111"
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val passcode = "123456"
    private val keyBytes = ByteArray(32) { (it + 1).toByte() }

    @Before
    fun clean() {
        NativeSessionState.reset()
    }

    @After
    fun done() {
        NativeSessionState.reset()
    }

    private fun store() = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))

    private fun v3Current() = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.V3, "{}", 1)

    /** Positive: the held key is returned only for its account (case-insensitive); a copy is returned, not the held array. */
    @Test
    fun theHeldKeyIsReturnedOnlyForItsAccount() {
        SessionKeyHolder.put(eoa, keyBytes)
        val copy = SessionKeyHolder.keyFor(eoa.uppercase().replaceFirst("0X", "0x"))!!
        assertArrayEquals(keyBytes, copy)
        assertFalse(copy === keyBytes)
        assertNull(SessionKeyHolder.keyFor(other))
    }

    /** Positive: clear empties the holder; another account's put replaces the held key. */
    @Test
    fun clearAndReplaceWork() {
        SessionKeyHolder.put(eoa, keyBytes)
        SessionKeyHolder.put(other, ByteArray(32) { 9 })
        assertNull(SessionKeyHolder.keyFor(eoa))
        SessionKeyHolder.clear()
        assertNull(SessionKeyHolder.keyFor(other))
    }

    /** Regression: X is ready; unlocking Y through the unlock entry keeps Y's key and clears X's. */
    @Test
    fun unlockingAnotherAccountKeepsItsKey() {
        val keyX = ByteArray(32) { 3 }
        val keyY = ByteArray(32) { 5 }
        NativeSessionState.unlockWith(eoa, keyX)
        NativeSessionState.unlockWith(other, keyY)
        assertTrue(NativeSessionState.isReadyFor(other))
        assertArrayEquals(keyY, SessionKeyHolder.keyFor(other))
        assertNull(SessionKeyHolder.keyFor(eoa))
    }

    /** Positive: a reset clears the holder and the ready state; a switch to another ready account clears the old key. */
    @Test
    fun resetAndAccountSwitchClearTheKey() {
        NativeSessionState.markReady(eoa)
        SessionKeyHolder.put(eoa, keyBytes)
        NativeSessionState.markReady(other)
        assertNull(SessionKeyHolder.keyFor(eoa))
        SessionKeyHolder.put(other, keyBytes)
        NativeSessionState.reset()
        assertFalse(NativeSessionState.isReady())
        assertNull(SessionKeyHolder.keyFor(other))
    }

    /** Negative: a v3 set does not answer through the store unless the session is ready for its account. */
    @Test
    fun aV3SetAnswersOnlyWhenTheSessionIsReady() {
        assertFalse(NativeMessageSigner.storeMayAnswer(v3Current()))
        NativeSessionState.markReady(eoa)
        assertTrue(NativeMessageSigner.storeMayAnswer(v3Current()))
        NativeSessionState.markReady(other)
        assertFalse(NativeMessageSigner.storeMayAnswer(v3Current()))
    }

    /** Positive: the no-page listen starts a v3 set only when the session is ready for its account (source STORE_SESSION). */
    @Test
    fun theNoPageListenStartsAV3SetOnlyWithTheSession() {
        val cur = v3Current()
        val waits = NoPageListenPolicy.decide(NativeWalletVault.State.NoKey, cur, pgpVaultReady = false, pgpStoreHasPrivate = true, pgpStoreEoa = eoa)
        assertEquals("v3_waits_passphrase", (waits as NoPageListenPolicy.Decision.Refuse).diag)
        val started = NoPageListenPolicy.decide(
            NativeWalletVault.State.NoKey, cur, pgpVaultReady = false, pgpStoreHasPrivate = true, pgpStoreEoa = eoa, sessionReadyEoa = eoa,
        ) as NoPageListenPolicy.Decision.Start
        assertEquals(NoPageListenPolicy.WalletSource.STORE_SESSION, started.source)
        val mismatch = NoPageListenPolicy.decide(
            NativeWalletVault.State.NoKey, cur, pgpVaultReady = false, pgpStoreHasPrivate = true, pgpStoreEoa = eoa, sessionReadyEoa = other,
        )
        assertEquals("v3_waits_passphrase", (mismatch as NoPageListenPolicy.Decision.Refuse).diag)
    }

    /** Positive: the sign path takes the held key for a v3 set of its account and returns a signature; without the key it does not sign. */
    @Test
    fun signingUsesTheHeldKeyForTheV3Account() {
        val key = MnemonicDerivation.deriveKey(phrase)!!
        val account = WalletAddress.fromPrivateKey(key)!!
        SessionKeyHolder.put(account, key)
        NativeSessionState.markReady(account)
        val cur = MnemonicSetStore.Current.Found(account, MnemonicSetStore.Kind.V3, "{}", 1)
        val signed = NativeMessageSigner.signFromStore(cur, NativeMessageSigner.KIND_ENVELOPE, "hello".toByteArray())
        assertEquals("ok", signed?.code)
        NativeSessionState.reset()
        assertNull(NativeMessageSigner.signFromStore(cur, NativeMessageSigner.KIND_ENVELOPE, "hello".toByteArray()))
    }

    /** Positive: the correct passcode opens the envelope in memory and yields the phrase (for the in-session key); no passcode yields none. */
    @Test
    fun theCorrectPasscodeYieldsThePhraseOnlyInMemory() {
        val s = store()
        val env = MnemonicCipherV3.seal(eoa, passcode, phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        val ok = PwaSyncCipher.run(env, passcode) { e, v -> s.stageEnvelope(e, v) } as PwaSyncCipher.Outcome.Ok
        assertEquals(phrase, ok.phrase)
        val none = PwaSyncCipher.run(env, null) { e, v -> s.stageEnvelope(e, v) } as PwaSyncCipher.Outcome.Ok
        assertNull(none.phrase)
    }

    /** Negative: a wrong passcode is unlock_failed, writes no set, and the session is not ready. */
    @Test
    fun aWrongPasscodeWritesNothingAndLeavesTheSessionLocked() {
        val s = store()
        val env = MnemonicCipherV3.seal(eoa, passcode, phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        val out = PwaSyncCipher.run(env, "000000") { e, v -> s.stageEnvelope(e, v) }
        assertEquals("unlock_failed", (out as PwaSyncCipher.Outcome.Fail).code)
        assertTrue(s.current() is MnemonicSetStore.Current.Absent)
        assertFalse(NativeSessionState.isReady())
        assertNull(SessionKeyHolder.keyFor(eoa))
    }

    /** Source guard: the holder and the decision never log, and the holder is cleared by reset. */
    @Test
    fun theSessionCodeNeverLogsAndTheResetClearsTheHolder() {
        val holder = File("src/main/java/network/conet/chat/nativekey/SessionKeyHolder.kt").readText(Charsets.UTF_8)
        assertFalse(holder.contains("Log."))
        assertFalse(holder.contains("println"))
        val state = File("src/main/java/network/conet/chat/nativekey/NativeSessionState.kt").readText(Charsets.UTF_8)
        assertTrue(state.contains("SessionKeyHolder.clear()"))
    }
}
