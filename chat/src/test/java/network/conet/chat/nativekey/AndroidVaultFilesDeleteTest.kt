package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

/**
 * The platform file store (rc2.2-qa, review of eaab00f). A removal that does not take effect must be reported: it throws, and [exists] tells
 * the truth. Runs only in a temporary directory.
 */
class AndroidVaultFilesDeleteTest {
    @get:Rule
    val tmp = TemporaryFolder()

    @Test
    fun aRemovedFileIsGoneAndRemovingAnAbsentNameIsNoOp() {
        val files = AndroidVaultFiles(tmp.newFolder("vault"))
        files.write("wallet.v1.rec", byteArrayOf(1, 2, 3))
        assertTrue(files.exists("wallet.v1.rec"))

        files.delete("wallet.v1.rec")
        assertFalse(files.exists("wallet.v1.rec"))
        assertNull(files.read("wallet.v1.rec"))

        files.delete("wallet.v1.rec") // absent: nothing to do, nothing thrown
        assertFalse(files.exists("wallet.v1.rec"))
    }

    @Test
    fun aTempLeftoverOfTheNameIsRemovedWithIt() {
        val dir = tmp.newFolder("vault")
        val files = AndroidVaultFiles(dir)
        File(dir, "wallet.v1.mark.tmp").writeBytes(byteArrayOf(9))

        files.delete("wallet.v1.mark")
        assertFalse(File(dir, "wallet.v1.mark.tmp").exists())
    }

    /**
     * A non-empty directory at the name cannot be removed by File.delete, and read does not return it as a file. The removal must throw, and
     * exists must still report it: nothing may take the name for gone.
     */
    @Test
    fun aNameThatCannotBeRemovedThrowsAndStillExists() {
        val dir = tmp.newFolder("vault")
        val files = AndroidVaultFiles(dir)
        val blocker = File(dir, "wallet.v1.rec")
        blocker.mkdirs()
        File(blocker, "child").writeBytes(byteArrayOf(7))

        assertThrows(IOException::class.java) { files.delete("wallet.v1.rec") }
        assertTrue("the name is still present", files.exists("wallet.v1.rec"))
        assertThrows("a read of a name that is not a regular file is a read failure, never absent", IOException::class.java) { files.read("wallet.v1.rec") }
        assertArrayEquals(byteArrayOf(7), File(blocker, "child").readBytes())
    }

    @Test
    fun aWrittenFileIsReadBackUnchanged() {
        val files = AndroidVaultFiles(tmp.newFolder("vault"))
        files.write("wallet.v1.commit", byteArrayOf(4, 5))
        assertArrayEquals(byteArrayOf(4, 5), files.read("wallet.v1.commit"))
    }
}
