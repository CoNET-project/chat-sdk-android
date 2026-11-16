package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * rc2.2-qa item 6 (25.52Y.89, vectors TS-01 to TS-06; 25.52Y.90 for kPresent). Each case composes the real native answers: the walletStatus
 * from [NoKeyGate.walletStatusFor] and [NoKeyGate.walletStatusUnreadable], and the kPresent from the identityPublic G0 `no_key` payload.
 */
class NativeMnemonicTriStateTest {
    private class KSource(private val k: Boolean?) : IdentityPublic.Source {
        override fun eoa(): String? = "0x" + "a".repeat(40)
        override fun pgp(): IdentityPublic.PgpRecord = IdentityPublic.PgpRecord.NotRead
        override fun kPresent(): Boolean? = k
    }

    private val record = NativeWalletVault.State.Ready("0x" + "a".repeat(40))
    private val locked = NativeWalletVault.State.Locked("unreadable")

    /** The kPresent as the page sees it: the boolean of the G0 `no_key` payload, or null when it is absent or not a boolean. */
    private fun kPresentOnTheWire(k: Boolean?): Boolean? {
        val reply = IdentityPublic.answer(NoKeyGate.Gate.G0, { emptyList() }, "r", KSource(k))
        val p = IdentityPublic.ackPayload("r", reply)
        return if (p.has("kPresent") && p.get("kPresent") is Boolean) p.getBoolean("kPresent") else null
    }

    /** TS-01: G0 no_key and kPresent false, with the snapshot known: confirmed_none. */
    @Test
    fun ts01_confirmedNone() {
        val ws = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G0, NativeWalletVault.State.NoKey)
        assertEquals(
            NativeMnemonicTriState.CONFIRMED_NONE,
            NativeMnemonicTriState.classify(false, ws.getString("status"), null, kPresentOnTheWire(false)),
        )
    }

    /** TS-02: G1 not_ready with g1_uninitialized (a readable record): has. */
    @Test
    fun ts02_g1UninitializedIsHas() {
        val ws = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G1, record)
        assertEquals("g1_uninitialized", ws.getString("notReadyReason"))
        assertEquals(
            NativeMnemonicTriState.HAS,
            NativeMnemonicTriState.classify(false, ws.getString("status"), ws.getString("notReadyReason"), null),
        )
    }

    /** TS-03: G2 unlocked (with accountKey): has. */
    @Test
    fun ts03_g2UnlockedIsHas() {
        val ws = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G2, record)
        assertEquals("unlocked", ws.getString("status"))
        assertEquals(
            NativeMnemonicTriState.HAS,
            NativeMnemonicTriState.classify(false, ws.getString("status"), null, null),
        )
    }

    /** TS-04: a record that cannot be read: not_ready with unreadable: unknown, never none. */
    @Test
    fun ts04_unreadableIsUnknown() {
        val ws = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G1, locked)
        assertEquals("unreadable", ws.getString("notReadyReason"))
        assertEquals(
            NativeMnemonicTriState.UNKNOWN,
            NativeMnemonicTriState.classify(false, ws.getString("status"), ws.getString("notReadyReason"), null),
        )
    }

    /** TS-05: the snapshot is unknown (not_ready with unreadable, the unknown branch): unknown, retry, no onboarding. */
    @Test
    fun ts05_unknownSnapshotIsUnknown() {
        val ws = NoKeyGate.walletStatusUnreadable()
        assertEquals(
            NativeMnemonicTriState.UNKNOWN,
            NativeMnemonicTriState.classify(true, ws.getString("status"), ws.getString("notReadyReason"), null),
        )
    }

    /** TS-06: G0 no_key but a K is on the device (kPresent true): unknown, never confirmed none. A missing kPresent is unknown too. */
    @Test
    fun ts06_keyPresentWithoutAKeyIsUnknown() {
        val ws = NoKeyGate.walletStatusFor(NoKeyGate.Gate.G0, NativeWalletVault.State.NoKey)
        assertEquals(
            NativeMnemonicTriState.UNKNOWN,
            NativeMnemonicTriState.classify(false, ws.getString("status"), null, kPresentOnTheWire(true)),
        )
        assertEquals(
            NativeMnemonicTriState.UNKNOWN,
            NativeMnemonicTriState.classify(false, ws.getString("status"), null, kPresentOnTheWire(null)),
        )
    }
}
