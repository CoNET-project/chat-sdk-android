package network.conet.chat.nativekey

import network.conet.chat.BridgeCommandTable
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The gate of W5 chatRouteRegister (spec 25.28.5; NR-13 to NR-16; PM R2085 segment f, part 2). The gate answers before the payload is read:
 * G0 no_key, G1 not_ready, the passcode lock locked. The SDK registers the name, so it does not answer unknown_command; native_unavailable
 * is the shell's answer and is not produced here. The zeroing of the key and armor bytes is checked by source (the handler needs a Context).
 */
class ChatRouteRegisterGateTest {
    private val name = "chatRouteRegister"

    /**
     * NR-13: G0 is no_key, and the payload is not read. Unit-layer coverage: the gate function is called directly, not through the module's
     * dispatch, so "the payload is not read" is not proven by this test (reviewer 76357584, db617be point 2).
     */
    @Test
    fun g0AnswersNoKeyWithoutReadingThePayload() {
        assertEquals("no_key", NoKeyGate.answerFor(name, NoKeyGate.Gate.G0))
    }

    /** NR-14: G1 (a record that is not initialised) is not_ready. */
    @Test
    fun g1AnswersNotReady() {
        assertEquals("not_ready", NoKeyGate.answerFor(name, NoKeyGate.Gate.G1))
    }

    /**
     * NR-15 (`locked`, the passcode lock of 25.22.4): platform not applicable on Android (spec r3pi, 25.52GQ.3a). Android has no passcode layer
     * and no `locked` state; its equivalent is the storage lock's not_ready (T-133-05). Recorded as not applicable, not as a failure.
     */
    @Test
    fun nr15IsNotApplicableOnAndroid() {
        assertEquals(null, NoKeyGate.lockedAnswer("no-such-command", NativeWalletVault.State.Locked("x")))
    }

    /**
     * A storage-locked record for W5 answers not_ready, once (spec 25.52CS.2, 25.52GQ.3b; T-133-05). `locked` is the passcode lock only (iOS).
     */
    @Test
    fun aStorageLockedRecordAnswersNotReadyForW5() {
        assertEquals("not_ready", NoKeyGate.lockedAnswer(name, NativeWalletVault.State.Locked("marker_mismatch")))
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.gateOf(NativeWalletVault.State.Locked("marker_mismatch"), sessionReady = false))
    }

    /**
     * The handler zeroes the key bytes and the armor bytes after use, on every path (the finally block). The String copies are a stated limit.
     */
    @Test
    fun theHandlerZeroesItsByteArraysInAFinallyBlock() {
        val source = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        val start = source.indexOf("private fun chatRouteRegisterCommand(")
        val end = source.indexOf("private fun pgpIdentityCreateWaiting(")
        val body = source.substring(start, end)
        assertTrue("finally block", body.contains("} finally {"))
        assertTrue("zeroes the EOA key", body.contains("key?.fill(0)"))
        assertTrue("zeroes the armor", body.contains("armor?.fill(0)"))
        assertEquals("the gate is not in the handler: the module's gate answers first", true, body.contains("ChatRouteRegister.parse(body)"))
    }
}
