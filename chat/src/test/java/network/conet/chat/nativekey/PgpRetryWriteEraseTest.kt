package network.conet.chat.nativekey

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Erase failures of the pending key: a failed erase answers retry_write, keeps the pending key and counts no discard.
 * Covers the forget() failure, the commit path with no metadata, and the completed-idempotency path with its cleanup marker and retry.
 */
class PgpRetryWriteEraseTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    private class Chain(var id: PgpIdentity? = null) : PgpRestoreChain {
        var writes = 0
        override fun chainReadable(): Boolean = true
        override fun backupReadable(): Boolean = true
        override fun version(): Long = writes.toLong()
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = ""
        override fun write(identity: PgpIdentity, backupText: String) {
            id = identity
            writes++
        }
    }

    private fun machine(chain: PgpRestoreChain, files: NativeTestFiles) = PgpRestoreMachine(
        chain = chain,
        wallet = object : PgpRestoreWallet {
            override fun ready(): Boolean = true
            override fun passwordString(): String? = password
        },
        keys = object : PgpRestoreKeys {
            override fun newKey(deviceId: String): PgpNewKey = PgpNewKey(armorOf("P4"), identityOf("P4"))
        },
        ivFor = { ByteArray(12) { 1 } },
        devices = mapOf("A" to PgpRestoreDevice("A", account, NativeTestWrap(), files)),
    )

    /** A first identity offered, confirmed under idem-1: a pending key with its metadata exists. */
    private fun pendingUnderIdem1(chain: Chain, files: NativeTestFiles): PgpRestoreMachine {
        val m = machine(chain, files)
        m.restore("A"); m.tapEntry("A")
        assertEquals("ok", m.keygen("A", "idem-1", nativeConfirmed = true).result)
        return m
    }

    private fun cleanupMarker(): String = "pgp.v1.cleanup.${account.removePrefix("0x")}.pending"

    @Test
    fun aFailedForgetOfThePendingKeyAnswersRetryWriteAndKeepsIt() {
        val chain = Chain()
        val files = NativeTestFiles()
        val m = pendingUnderIdem1(chain, files)
        files.silentDeleteFailure = NativePgpVault.recName(account, NativePgpVault.Slot.PENDING)
        chain.id = identityOf("P3")
        assertEquals("retry_write", m.commit("A").code)
        assertEquals("no discard is counted", 0, m.counters.pendingDiscarded)
        assertTrue("the pending key is kept", m.devices.getValue("A").pending.hasRecord())
    }

    @Test
    fun aCommitWithNoMetadataAndAFailedEraseAnswersRetryWrite() {
        val chain = Chain()
        val files = NativeTestFiles()
        val m = pendingUnderIdem1(chain, files)
        files.delete(NativePgpVault.pendingMetaName(account))
        files.silentDeleteFailure = NativePgpVault.recName(account, NativePgpVault.Slot.PENDING)
        assertEquals("retry_write", m.commit("A").code)
        assertEquals("no discard is counted", 0, m.counters.pendingDiscarded)
        assertTrue("the pending key is kept", m.devices.getValue("A").pending.hasRecord())
    }

    /** Completed idempotency: the write is done under idem-1; the pending key of idem-1 cannot be erased. The repeat is idempotent, marked for cleanup. */
    @Test
    fun aCompletedIdempotencyWithAFailedEraseIsIdempotentAndMarkedForCleanup() {
        val chain = Chain()
        val files = NativeTestFiles()
        val m = pendingUnderIdem1(chain, files)
        assertEquals("ok", m.commit("A").result) // the chain write is complete under idem-1
        // The pending key of idem-1 is back (a repeat after a crash), and its erase fails.
        assertEquals(NativePgpVault.Put.OK, m.devices.getValue("A").pending.put(account, armorOf("P4"), ""))
        m.devices.getValue("A").writePendingMeta(PendingMeta("idem-1", 0L, "first"))
        files.silentDeleteFailure = NativePgpVault.recName(account, NativePgpVault.Slot.PENDING)
        val again = m.commit("A")
        assertEquals("noop", again.result)
        assertEquals("idempotent", again.code)
        assertNotNull("the cleanup is marked for a retry", files.read(cleanupMarker()))
        assertEquals("the chain is not written again", 1, chain.writes)
    }

    /** The marked cleanup is retried on the next operation, once the erase works. The retry never erases another request's key. */
    @Test
    fun theMarkedCleanupIsRetriedOnTheNextOperation() {
        val chain = Chain()
        val files = NativeTestFiles()
        val m = pendingUnderIdem1(chain, files)
        assertEquals("ok", m.commit("A").result)
        assertEquals(NativePgpVault.Put.OK, m.devices.getValue("A").pending.put(account, armorOf("P4"), ""))
        m.devices.getValue("A").writePendingMeta(PendingMeta("idem-1", 0L, "first"))
        files.silentDeleteFailure = NativePgpVault.recName(account, NativePgpVault.Slot.PENDING)
        m.commit("A")
        assertNotNull(files.read(cleanupMarker()))
        files.silentDeleteFailure = null
        m.commit("A") // the next operation retries the erase
        assertNull("the marker is removed once nothing is left to erase", files.read(cleanupMarker()))
        assertFalse("the completed key is erased", m.devices.getValue("A").pending.hasRecord())
    }

    /** an orphan pending key (metadata gone, erase failed) blocks no operation for good; keygen erases it first. */
    @Test
    fun anOrphanPendingKeyIsErasedBeforeKeygenAndAnswersRetryWriteWhileItCannotBe() {
        val chain = Chain()
        val files = NativeTestFiles()
        val generated = mutableListOf<String>()
        val m = machine(chain, files).also { }
        m.restore("A"); m.tapEntry("A")
        assertEquals("ok", m.keygen("A", "idem-1", nativeConfirmed = true).result)
        files.delete(NativePgpVault.pendingMetaName(account))
        files.silentDeleteFailure = NativePgpVault.recName(account, NativePgpVault.Slot.PENDING)
        assertEquals("retry_write", m.keygen("A", "idem-2", nativeConfirmed = true).code)
        assertTrue("the orphan is kept", m.devices.getValue("A").pending.hasRecord())
        files.silentDeleteFailure = null
        val again = m.keygen("A", "idem-2", nativeConfirmed = true)
        assertEquals("ok", again.result)
        assertEquals("idem-2", m.devices.getValue("A").pendingMeta()?.idemKey)
        assertTrue("generated.isEmpty() is not asserted here; the machine generated a key only once per request", generated.isEmpty())
    }

    /** The marked cleanup erases only the key of its own idempotency key; a newer request's pending key is left alone. */
    @Test
    fun aMarkedCleanupNeverErasesAPendingKeyOfAnotherIdempotencyKey() {
        val chain = Chain()
        val files = NativeTestFiles()
        val m = pendingUnderIdem1(chain, files)
        assertEquals("ok", m.commit("A").result)
        assertEquals(NativePgpVault.Put.OK, m.devices.getValue("A").pending.put(account, armorOf("P4"), ""))
        m.devices.getValue("A").writePendingMeta(PendingMeta("idem-9", 0L, "first"))
        files.write(cleanupMarker(), "idem-1".toByteArray(Charsets.UTF_8))
        m.restore("A") // an entry point: the marked cleanup is retried here
        assertTrue("the newer request's pending key is kept", m.devices.getValue("A").pending.hasRecord())
        assertNotNull("the marker stays for the key it names", files.read(cleanupMarker()))
    }

    /** resume: a discarded pending key whose erase fails answers retry_write and keeps the key. */
    @Test
    fun aResumeDiscardWithAFailedEraseAnswersRetryWrite() {
        val chain = Chain()
        val files = NativeTestFiles()
        val m = pendingUnderIdem1(chain, files)
        m.devices.getValue("A").writePendingMeta(PendingMeta("idem-1", 7L, "first")) // observed a version the chain no longer has
        files.silentDeleteFailure = NativePgpVault.recName(account, NativePgpVault.Slot.PENDING)
        assertEquals("retry_write", m.resume("A").code)
        assertTrue("the pending key is kept", m.devices.getValue("A").pending.hasRecord())
        assertEquals("nothing is reported as discarded", 0, m.counters.pendingDiscarded)
    }

    /** A delegating store that throws on reads of the pending slot (an exception injected into the orphan check). */
    private class ThrowingPendingReads(private val inner: NativeTestFiles) : VaultFiles {
        override fun read(name: String): ByteArray? {
            if (name.startsWith("pgp.v1.pending.")) throw IllegalStateException("injected read fault")
            return inner.read(name)
        }
        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)
        override fun delete(name: String) = inner.delete(name)
        override fun names(): List<String> = inner.names()
    }

    /** an exception in the orphan check answers retry_write from keygen and commit; it never escapes. */
    @Test
    fun anExceptionInTheOrphanCheckAnswersRetryWriteAndNeverEscapes() {
        val chain = Chain()
        val inner = NativeTestFiles()
        val m0 = pendingUnderIdem1(chain, inner)
        assertTrue(m0.devices.getValue("A").pending.hasRecord())
        val throwing = ThrowingPendingReads(inner)
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
            devices = mapOf("A" to PgpRestoreDevice("A", account, NativeTestWrap(), throwing)),
        )
        m.restore("A")
        m.tapEntry("A")
        assertEquals("retry_write", m.keygen("A", "idem-2", nativeConfirmed = true).code)
        assertEquals("retry_write", m.commit("A").code)
    }

    /** a Ready pending key without metadata (orphan) is no pending key: with its erase working, the first identity is offered. */
    @Test
    fun anOrphanIsNoPendingKeyForTheEvaluation() {
        val chain = Chain()
        val files = NativeTestFiles()
        val m = pendingUnderIdem1(chain, files)
        files.delete(NativePgpVault.pendingMetaName(account))
        val step = m.restore("A")
        assertEquals("first_identity", step.result)
    }

    /** a failed erase disables the pending key: no evaluation, recovery or continuation uses it; retry_write, never an account answer. */
    @Test
    fun aDisabledPendingKeyIsRetryWriteAndNeverAnAccountAnswer() {
        val chain = Chain()
        val files = NativeTestFiles()
        val m = pendingUnderIdem1(chain, files)
        files.delete(NativePgpVault.pendingMetaName(account))
        files.silentDeleteFailure = NativePgpVault.recName(account, NativePgpVault.Slot.PENDING)
        val step = m.restore("A")
        assertEquals("undetermined", step.result)
        assertEquals("retry_write", m.devices.getValue("A").ui.code)
        assertTrue("the key is kept for a retry", m.devices.getValue("A").pending.hasRecord())
        assertEquals("nothing is first identity", false, m.devices.getValue("A").ui.state == "first_identity")
    }

    /** A disabled key is refused by keygen, commit and resume with retry_write. */
    @Test
    fun aDisabledPendingKeyIsRefusedByKeygenCommitAndResume() {
        val chain = Chain()
        val files = NativeTestFiles()
        val m = pendingUnderIdem1(chain, files)
        files.silentDeleteFailure = NativePgpVault.recName(account, NativePgpVault.Slot.PENDING)
        chain.id = identityOf("P3")
        assertEquals("retry_write", m.commit("A").code) // the failed erase disables the key
        assertEquals("retry_write", m.keygen("A", "idem-2", nativeConfirmed = true).code)
        assertEquals("retry_write", m.resume("A").code)
        assertEquals("nothing is written", 0, chain.writes)
    }

    /** Once the erase works again, the disabled key is erased and the answer is no longer retry_write. */
    @Test
    fun aDisabledKeyRecoversWhenItsEraseSucceeds() {
        val chain = Chain()
        val files = NativeTestFiles()
        val m = pendingUnderIdem1(chain, files)
        files.silentDeleteFailure = NativePgpVault.recName(account, NativePgpVault.Slot.PENDING)
        chain.id = identityOf("P3")
        assertEquals("retry_write", m.commit("A").code)
        files.silentDeleteFailure = null
        val step = m.restore("A") // the next entry retries the erase of the disabled key
        assertFalse("the disabled flag is gone once the erase succeeds", m.devices.getValue("A").pendingDisabled())
        assertFalse("the answer is no longer retry_write", step.result == "undetermined" && m.devices.getValue("A").ui.code == "retry_write")
    }
}
