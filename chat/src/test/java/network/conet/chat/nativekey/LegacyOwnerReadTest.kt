package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.IOException

/**
 * The stored legacy PGP owner read by the migration. An unreadable value is unknown (null): the migration adopts nothing
 * and writes nothing. An absent value is the empty owner, which is a known state.
 */
class LegacyOwnerReadTest {

    @Test
    fun anUnreadableStoredOwnerIsUnknownNotAbsent() {
        assertNull(readLegacyOwnerEoa { throw IOException("stored owner unreadable") })
    }

    @Test
    fun anAbsentStoredOwnerIsTheEmptyOwner() {
        assertEquals("", readLegacyOwnerEoa { null })
    }

    @Test
    fun aStoredOwnerIsTrimmedAndLowercased() {
        assertEquals("0xabc", readLegacyOwnerEoa { "  0xABC " })
    }
}
