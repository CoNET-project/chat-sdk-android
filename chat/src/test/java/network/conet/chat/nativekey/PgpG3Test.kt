package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * G3 of the review of the restore path: the restore machine's entry points run one at a time. The probe failed on the unfixed code
 * (two keygen calls generated two keys); it passes with the single in-flight lock.
 */
class PgpG3Test {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    /** An empty chain that counts its writes and keeps what was written (the record is visible to later reads). */
    private class RecordingChain : PgpRestoreChain {
        var id: PgpIdentity? = null
        var text: String = ""
        var writes = 0
        override fun chainReadable(): Boolean = true
        override fun backupReadable(): Boolean = true
        override fun version(): Long = writes.toLong()
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = text
        override fun write(identity: PgpIdentity, backupText: String) {
            id = identity
            text = backupText
            writes++
        }
    }

    private fun machine(chain: PgpRestoreChain, files: NativeTestFiles, newKey: (String) -> PgpNewKey): PgpRestoreMachine {
        val wrap = NativeTestWrap()
        return PgpRestoreMachine(
            chain = chain,
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = password
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = newKey(deviceId)
            },
            ivFor = { ByteArray(12) { 1 } },
            devices = mapOf("A" to PgpRestoreDevice("A", account, wrap, files)),
        )
    }

    /** G3: two keygen calls at the same time; the second must wait for the first (one key generated). */
    @Test
    fun g3ConcurrentKeygenGeneratesOneKey() {
        val files = NativeTestFiles()
        val entered = CountDownLatch(1)
        val chain = RecordingChain()
        val m = machine(chain, files) { _ ->
            entered.countDown()
            Thread.sleep(400)
            PgpNewKey(armorOf("P4"), identityOf("P4"))
        }
        m.restore("A")
        m.tapEntry("A")
        val t1 = Thread { m.keygen("A", "idem-1", nativeConfirmed = true) }
        val t2 = Thread {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            m.keygen("A", "idem-2", nativeConfirmed = true)
        }
        t1.start(); t2.start(); t1.join(); t2.join()
        assertEquals("one key generated", 1, m.counters.keygen)
    }

    /** A chain whose write takes time, so a second commit can arrive while the first is in its write. */
    private class SlowChain : PgpRestoreChain {
        var id: PgpIdentity? = null
        var text: String = ""
        var writes = 0
        val entered = CountDownLatch(1)
        override fun chainReadable(): Boolean = true
        override fun backupReadable(): Boolean = true
        override fun version(): Long = writes.toLong()
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = text
        override fun write(identity: PgpIdentity, backupText: String) {
            entered.countDown()
            Thread.sleep(400)
            id = identity
            text = backupText
            writes++
        }
    }

    /** Process-level domain (review, G3): two machine instances over the same files do not run side by side. */
    @Test
    fun g3TwoMachineInstancesShareOneInFlightDomain() {
        val files = NativeTestFiles()
        val calls = java.util.concurrent.atomic.AtomicInteger(0)
        val entered = CountDownLatch(1)
        val chain = RecordingChain()
        fun newMachine(): PgpRestoreMachine = machine(chain, files) { _ ->
            calls.incrementAndGet()
            entered.countDown()
            Thread.sleep(400)
            PgpNewKey(armorOf("P4"), identityOf("P4"))
        }
        val a = newMachine()
        val b = newMachine()
        a.restore("A")
        a.tapEntry("A")
        val t1 = Thread { a.keygen("A", "idem-1", nativeConfirmed = true) }
        val t2 = Thread {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            b.keygen("A", "idem-2", nativeConfirmed = true)
        }
        t1.start(); t2.start(); t1.join(); t2.join()
        assertEquals("one key generated across instances", 1, calls.get())
    }

    /**
     * Mutation M8 (commit not locked): a second commit arriving during the first commit's chain write must wait. The second then sees the
     * completed key and writes nothing; unlocked, it writes again.
     */
    @Test
    fun g3ConcurrentCommitsWriteOnce() {
        val files = NativeTestFiles()
        val dev = PgpRestoreDevice("A", account, NativeTestWrap(), files)
        val chain = SlowChain()
        val m = PgpRestoreMachine(
            chain = chain,
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = password
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = PgpNewKey(armorOf("P4"), identityOf("P4"))
            },
            ivFor = { ByteArray(12) { 1 } },
            devices = mapOf("A" to dev),
        )
        m.restore("A")
        m.tapEntry("A")
        m.keygen("A", "idem-1", nativeConfirmed = true)
        val t1 = Thread { m.commit("A") }
        val t2 = Thread {
            assertTrue(chain.entered.await(5, TimeUnit.SECONDS))
            m.commit("A")
        }
        t1.start(); t2.start(); t1.join(); t2.join()
        assertEquals("one chain write", 1, chain.writes)
    }
}
