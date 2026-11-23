package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 *  (裁定 1): key_only is confirmed none (the record confirms no valid phrase); g1_uninitialized is has; an unreadable record is unknown.
 */
class MnemonicTriStateKeyOnlyTest {
    @Test fun keyOnlyIsConfirmedNone() {
        assertEquals(NativeMnemonicTriState.CONFIRMED_NONE,
            NativeMnemonicTriState.classify(false, "not_ready", NoKeyGate.NOT_READY_KEY_ONLY, null))
    }

    @Test fun g1UninitialisedIsHas() {
        assertEquals(NativeMnemonicTriState.HAS,
            NativeMnemonicTriState.classify(false, "not_ready", NoKeyGate.NOT_READY_G1_UNINITIALIZED, null))
    }

    @Test fun unreadableIsUnknown() {
        assertEquals(NativeMnemonicTriState.UNKNOWN,
            NativeMnemonicTriState.classify(false, "not_ready", NoKeyGate.NOT_READY_UNREADABLE, null))
        assertEquals(NativeMnemonicTriState.UNKNOWN,
            NativeMnemonicTriState.classify(false, "not_ready", null, null))
    }
}
