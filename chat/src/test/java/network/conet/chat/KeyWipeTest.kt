package network.conet.chat

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/** T-49: a wiped buffer is all zero; the history store's teardown wipes its four key buffers and drops them. */
class KeyWipeTest {
    @Test
    fun wipeZeroesEveryBufferInPlace() {
        val a = ByteArray(32) { 0x5a }
        val b = ByteArray(16) { 0x7f }
        KeyWipe.wipe(a, b, null)
        assertTrue("every byte of a is zero", a.all { it == 0.toByte() })
        assertTrue("every byte of b is zero", b.all { it == 0.toByte() })
    }

    @Test
    fun theHistoryStoreDestroyWipesMasterIndexPendingAndIdKeys() {
        val src = File("src/main/java/network/conet/chat/BeamioConetChatHistoryStore.kt").readText(Charsets.UTF_8)
        val destroy = src.substringAfter("fun destroy() {").substringBefore("private fun publishSnapshot")
        assertTrue("destroy wipes master, indexKey, pendingKey and kIdDb", destroy.contains("KeyWipe.wipe(master, indexKey, pendingKey, kIdDb)"))
        assertTrue("destroy drops pendingKey and kIdDb too", destroy.contains("pendingKey = null") && destroy.contains("kIdDb = null"))
    }
}
