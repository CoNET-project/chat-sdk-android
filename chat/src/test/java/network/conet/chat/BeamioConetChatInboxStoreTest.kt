package network.conet.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

/**
 * Inbox store file logic without an Android Context. An inbox file that cannot be read is unknown: it is never read as
 * empty and never written over. A failed replace keeps the previous file and its temporary copy.
 * Synthetic armor only; no key material.
 */
class BeamioConetChatInboxStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val armor = "-----BEGIN PGP MESSAGE-----\nSYNTHETIC-INBOX-ENTRY\n-----END PGP MESSAGE-----"

    private fun inboxFile(name: String): File = File(tmp.newFolder(name), "conet_chat_inbox_v1.json")

    @Test
    fun missingFileIsAnEmptyInbox() {
        val f = inboxFile("missing")
        assertTrue(BeamioConetChatInboxStore.readEntries(f).isEmpty())
    }

    @Test
    fun putStoresOnceAndListReturnsIt() {
        val f = inboxFile("roundtrip")
        BeamioConetChatInboxStore.putAt(f, "0xaa", armor, "domain.test")
        BeamioConetChatInboxStore.putAt(f, "0xaa", armor, "domain.test")
        val list = BeamioConetChatInboxStore.readEntries(f)
        assertEquals(1, list.size)
        assertEquals("0xaa", list[0].armorHash)
        assertEquals("domain.test", list[0].viaDomain)
    }

    @Test
    fun unreadableInboxThrowsAndIsNeverWrittenBack() {
        val f = inboxFile("unreadable")
        val garbage = "{not an inbox"
        f.writeText(garbage)
        try {
            BeamioConetChatInboxStore.readEntries(f)
            fail("an unreadable inbox must not read as empty")
        } catch (expected: IOException) {
            // expected
        }
        BeamioConetChatInboxStore.putAt(f, "0xbb", armor, "domain.test")
        BeamioConetChatInboxStore.removeAt(f, listOf("0xbb"))
        assertEquals(garbage, f.readText())
    }

    @Test
    fun failedReplaceKeepsThePreviousFileAndTheTemporaryCopy() {
        val f = inboxFile("replace")
        BeamioConetChatInboxStore.putAt(f, "0xcc", armor, "domain.test")
        val before = f.readText()
        BeamioConetChatInboxStore.putAt(f, "0xdd", armor, "domain.test") { _, _ -> false }
        BeamioConetChatInboxStore.removeAt(f, listOf("0xcc")) { _, _ -> false }
        assertEquals(before, f.readText())
        assertTrue(File(f.parentFile, "conet_chat_inbox_v1.json.tmp").exists())
        assertEquals(listOf("0xcc"), BeamioConetChatInboxStore.readEntries(f).map { it.armorHash })
    }
}
