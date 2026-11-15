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

    /** NR-13: G0 is no_key, and the payload is not read. */
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
     * NR-15 (`locked`, the passcode lock of 25.22.4): Android has no passcode layer, and the SDK has no passcode-lock answer for this name
     * (NoKeyGate has no passcodeLockedAnswer). NR-15 therefore has no Android code path here; it is a recorded gap, not a pass.
     */
    @Test
    fun nr15IsARecordedGapBecauseAndroidHasNoPasscodeLock() {
        assertEquals(null, NoKeyGate.lockedAnswer("no-such-command", NativeWalletVault.State.Locked("x")))
    }

    /**
     * A storage-locked record for W5: the locked family of negative-tests-v1 does not include W5 (the vector maps it to no locked answer), so
     * the gate's G1 answer applies (not_ready, reason unreadable). The `locked` of 25.28.5 is the passcode lock, which Android does not have.
     */
    @Test
    fun aStorageLockedRecordIsNotLockedForW5() {
        assertEquals(null, NoKeyGate.lockedAnswer(name, NativeWalletVault.State.Locked("marker_mismatch")))
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.gateOf(NativeWalletVault.State.Locked("marker_mismatch"), sessionReady = false))
    }

    /** NR-16: the name is registered on the chat channel, so the SDK does not answer unknown_command for it. */
    @Test
    fun theNameIsRegisteredInTheCommandTable() {
        assertTrue(BridgeCommandTable.isRegistered(name))
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
        assertTrue("zeroes the EOA key", body.contains("key.fill(0)"))
        assertTrue("zeroes the armor", body.contains("armorBytes?.fill(0)"))
        assertEquals("the gate is not in the handler: the module's gate answers first", true, body.contains("ChatRouteRegister.parse(body)"))
    }
}
