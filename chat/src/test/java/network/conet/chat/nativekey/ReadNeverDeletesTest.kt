package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * rc2.2-qa item 5: five classes of positive and negative tests for "a read never deletes user data" (25.52Y.80 第 1 項, 第 4 項).
 * All stores are in memory (NativeTestFiles); no device and no real directory is touched.
 */
class ReadNeverDeletesTest {
    private val eoa = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    /** The scalar 1 (32 bytes, big-endian), which is the key of [eoa] (the same pair as NativeWalletVaultTest keyA and eoaA). */
    private val key = ByteArray(32).also { it[31] = 1 }

    /** A readable store with one account, written through the vault's own import. */
    private fun storeWithAccount(): Pair<NativeTestFiles, NativeTestWrap> {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa, key))
        return files to wrap
    }

    private fun sizes(files: NativeTestFiles): Map<String, Int> = files.map.mapValues { it.value.size }

    /** Wraps [inner] and makes the read of [failName] throw. Deletes are counted. */
    private class ReadFailsFor(private val inner: NativeTestFiles, private val failName: String) : VaultFiles {
        var deletes = 0
        override fun read(name: String): ByteArray? {
            if (name == failName) throw IOException("unreadable")
            return inner.read(name)
        }

        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)

        override fun delete(name: String) {
            deletes++
            inner.delete(name)
        }
    }

    /** (1) A record with no marker: the record is kept, the answer is locked (unreadable on the wire), and nothing is created. */
    @Test
    fun class1_recordWithoutMarkerIsKeptAndUnreadable() {
        // A record with a recovery phrase (the marker rule applies). A key-only record with no marker is the legacy rule of 25.52Y.42 第 4 項 (g)
        // and is not covered here; see the receipt (conflict with 25.52Y.80 第 2 項, for the coordinator).
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val phraseEoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(phraseEoa, MnemonicDerivation.deriveKey(phrase)!!, phrase))
        files.map.remove(NativeWalletVault.MARK)
        val before = files.map.mapValues { it.value.copyOf() }

        val s = NativeWalletVault(wrap, files).state()

        assertTrue("record without marker is locked", s is NativeWalletVault.State.Locked)
        assertEquals("marker_missing", (s as NativeWalletVault.State.Locked).reason)
        assertEquals("the record is kept", before.keys, files.map.keys)
        for ((name, bytes) in before) assertArrayEquals("$name unchanged", bytes, files.map[name])
        assertFalse("no new marker is generated", files.map.containsKey(NativeWalletVault.MARK))
    }

    /** (2) A marker with no record: the marker is kept, the answer is locked, and no key is generated. */
    @Test
    fun class2_markerWithoutRecordIsKeptAndUnreadable() {
        val (files, wrap) = storeWithAccount()
        files.map.remove(NativeWalletVault.REC)
        val mark = files.map[NativeWalletVault.MARK]!!.copyOf()

        val s = NativeWalletVault(wrap, files).state()

        assertEquals("record_missing", (s as NativeWalletVault.State.Locked).reason)
        assertArrayEquals("the marker is kept", mark, files.map[NativeWalletVault.MARK])
        assertFalse("no record is generated", files.map.containsKey(NativeWalletVault.REC))
    }

    /** (3) A read that throws deletes nothing: the reading vault reports, and the stored names and bytes are unchanged. */
    @Test
    fun class3_readFailureDeletesNothing() {
        val (inner, wrap) = storeWithAccount()
        val before = inner.map.mapValues { it.value.copyOf() }
        val files = ReadFailsFor(inner, NativeWalletVault.REC)

        runCatching { NativeWalletVault(wrap, files).state() }

        assertEquals("no delete was issued by a read", 0, files.deletes)
        assertEquals("no name removed", before.keys, inner.map.keys)
        for ((name, bytes) in before) assertArrayEquals("$name unchanged", bytes, inner.map[name])
    }

    /** (4) Repeated reads and a simulated cold start leave the directory's names and sizes unchanged. */
    @Test
    fun class4_repeatedReadsAndColdStartLeaveTheDirectoryUnchanged() {
        val (files, wrap) = storeWithAccount()
        val namesBefore = files.map.keys.toSet()
        val sizesBefore = sizes(files)

        val v = NativeWalletVault(wrap, files)
        repeat(3) { assertTrue(v.state() is NativeWalletVault.State.Ready) }
        val cold = NativeWalletVault(wrap, files)
        repeat(2) { assertTrue(cold.state() is NativeWalletVault.State.Ready) }

        assertEquals("names unchanged", namesBefore, files.map.keys.toSet())
        assertEquals("sizes unchanged", sizesBefore, sizes(files))
        assertNotEquals("the store is not empty", 0, files.map.size)
    }

    /**
     * (5) A failed write rolls back only what that write created. An unrelated name that was already there stays.
     * The marker write fails after the record was written: the record (created here) goes, the unrelated name stays.
     */
    @Test
    fun class5_failedWriteRollsBackOnlyWhatThisWriteCreated() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        files.map["unrelated.item"] = byteArrayOf(4, 2)
        files.failWrite = NativeWalletVault.MARK

        val r = NativeWalletVault(wrap, files).importKey(eoa, key)

        assertFalse("the import failed", r == NativeWalletVault.Import.OK)
        assertEquals("only the pre-existing name remains", setOf("unrelated.item"), files.map.keys)
        assertArrayEquals(byteArrayOf(4, 2), files.map["unrelated.item"])
    }
}
