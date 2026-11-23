package network.conet.chat.passcode

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The passcode directory is named by the protocol and is not a target of account cleanup (protocol section 8). */
class PasscodeDirectoryExclusionTest {
    @Test
    fun theDirectoryNameIsTheFrozenOne() {
        assertEquals("native_passcode_v1", PasscodeRecordStore.DIRECTORY)
        assertEquals(File("/nobackup/native_passcode_v1"), PasscodeRecordStore.directoryUnder(File("/nobackup")))
    }

    /**
     * the passcode directory is a registered cleanup target, but only by exact owner name (PasscodeDirCleanup). The wiring names it
     * through that adapter, and no whole-directory removal exists.
     */
    @Test
    fun accountCleanupTargetsTheDirectoryOnlyThroughTheExactOwnerAdapter() {
        val wiring = File("src/main/java/network/conet/chat/nativekey/AccountCleanupWiring.kt").readText(Charsets.UTF_8)
        val stores = File("src/main/java/network/conet/chat/nativekey/AccountCleanupStores.kt").readText(Charsets.UTF_8)
        assertTrue("the wiring registers the passcode adapter", wiring.contains("PasscodeDirCleanup("))
        assertFalse("no whole-directory removal in the passcode adapter", stores.substringAfter("class PasscodeDirCleanup").contains("deleteRecursively"))
    }
}
