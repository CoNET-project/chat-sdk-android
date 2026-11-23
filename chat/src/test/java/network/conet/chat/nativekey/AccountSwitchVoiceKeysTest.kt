package network.conet.chat.nativekey

import network.conet.chat.BeamioConetChatSignBroker
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Lock and account-switch rules for the voice temporary keys ( and the r3 series): a lock keeps the voice keys (incoming
 * calls are answered while locked) and does not refuse the listen; an account change at the pointer's unique exit clears them; a payer
 * (wallet-key) signature is refused while the wallet is locked.
 */
class AccountSwitchVoiceKeysTest {
    private val sid = "sid-lock-test"
    private val tk = ByteArray(32) { (it + 1).toByte() }

    private fun pointer(): DeviceFlagFiles = DeviceFlagFiles(NativeTestFiles())

    @Test
    fun aLockKeepsTheVoiceTemporaryKeyForAnIncomingCall() {
        VoiceChannelKeys.register(sid, tk)
        BeamioConetChatSignBroker.clearNativeSigner() // what a lock does to the wallet key
        val kept = VoiceChannelKeys.lookup(sid)
        assertArrayEquals("the temporary key T stays for the incoming call", tk, kept)
        VoiceChannelKeys.clear()
    }

    @Test
    fun aPayerSignatureIsRefusedWhileLocked() {
        BeamioConetChatSignBroker.clearNativeSigner()
        var failed = false
        BeamioConetChatSignBroker.requestEip191("payer message") { result -> failed = result.isFailure }
        assertTrue("a payer signature with no wallet key is refused", failed)
    }

    @Test
    fun anAccountChangeAtThePointerClearsTheVoiceKeys() {
        val flags = pointer()
        flags.setAccountAddress("0x1111111111111111111111111111111111111111")
        VoiceChannelKeys.register(sid, tk)
        flags.setAccountAddress("0x2222222222222222222222222222222222222222")
        assertNull("another account ends the voice keys", VoiceChannelKeys.lookup(sid))
    }

    @Test
    fun theSameAccountWrittenAgainKeepsTheVoiceKeys() {
        val flags = pointer()
        flags.setAccountAddress("0x1111111111111111111111111111111111111111")
        VoiceChannelKeys.register(sid, tk)
        flags.setAccountAddress("0x1111111111111111111111111111111111111111")
        assertArrayEquals("the same account keeps them", tk, VoiceChannelKeys.lookup(sid))
        VoiceChannelKeys.clear()
    }

    @Test
    fun aFirstAccountFromEmptyEndsAnyStaleVoiceKeys() {
        VoiceChannelKeys.register(sid, tk)
        pointer().setAccountAddress("0x3333333333333333333333333333333333333333")
        assertFalse("from empty to an account is an account switch", VoiceChannelKeys.lookup(sid) != null)
    }

    /**
     *  (the page destroy is a lock): destroy keeps the voice temporary keys; only the identity clear clears them.
     * Source guard: the real page path (command "destroy") needs a running module and is covered in the passcode batch, not here.
     */
    @Test
    fun aPageDestroyLockKeepsTheVoiceKeysAndTheIdentityClearEndsThem() {
        val src = java.io.File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        val destroy = src.substringAfter("private fun destroy() {").substringBefore("\n    }\n")
        assertFalse("destroy (a lock) does not clear the voice keys", destroy.contains("VoiceChannelKeys.clear()"))
        assertFalse("destroy (a lock) keeps the incoming-call listen running", destroy.contains("listen.stop()"))
        val finish = src.substringAfter("private fun finishClearIdentity(").substringBefore("\n    }\n")
        assertTrue("the identity clear clears the voice keys", finish.contains("VoiceChannelKeys.clear()"))
        assertTrue("the identity clear stops the listen", finish.contains("listen.stop()"))
    }

    /** Account switch ends the incoming-call listen through the hook; the same account and a lock do not. */
    @Test
    fun anAccountChangeNotifiesTheListenHookButTheSameAccountDoesNot() {
        val flags = pointer()
        flags.setAccountAddress("0x4444444444444444444444444444444444444444")
        var notified = 0
        AccountPointerEvents.onChange = { notified++ }
        try {
            flags.setAccountAddress("0x4444444444444444444444444444444444444444")
            assertTrue("the same account does not notify", notified == 0)
            flags.setAccountAddress("0x5555555555555555555555555555555555555555")
            assertTrue("another account notifies once", notified == 1)
            BeamioConetChatSignBroker.clearNativeSigner() // a lock: no notification
            assertTrue("a lock does not notify", notified == 1)
        } finally {
            AccountPointerEvents.onChange = null
        }
    }

    /** A failing listener is not silent: its failure class is kept; a later success clears it. */
    @Test
    fun aFailingListenerIsRecordedNotSwallowed() {
        val flags = pointer()
        flags.setAccountAddress("0x6666666666666666666666666666666666666666")
        AccountPointerEvents.onChange = { throw IllegalStateException("stop failed") }
        try {
            flags.setAccountAddress("0x7777777777777777777777777777777777777777")
            assertTrue("the failure class is kept", AccountPointerEvents.lastFailure == "IllegalStateException")
            AccountPointerEvents.onChange = { }
            flags.setAccountAddress("0x8888888888888888888888888888888888888888")
            assertNull("a later success clears it", AccountPointerEvents.lastFailure)
        } finally {
            AccountPointerEvents.onChange = null
        }
    }
}
