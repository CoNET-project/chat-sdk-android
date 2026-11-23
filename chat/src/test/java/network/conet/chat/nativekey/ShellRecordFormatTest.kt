package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The file format of the page record (spec r3bh §25.52L.2; vectors FM-01 to FM-05): the AAD, the layout (29 + n bytes), and the reads that
 * must fail closed as `record_unreadable`, never as `absent`, and never overwrite the file.
 */
class ShellRecordFormatTest {
    private val eoa = "0xAbC0000000000000000000000000000000000001"
    private val accountKey = eoa.lowercase() + ":default"

    @Test
    fun fm01TheAadIsTheLowerCaseAccountKeyPlusTheVersionByte() {
        // The example of §25.52L.2: the lower-case EOA, a colon, the workspace `default`, then 0x01.
        val wrap = CapturingWrap()
        SealedPageRecordStore(wrap, NativeTestFiles(), accountKey).write(JSONObject().put("rev", 1).put("schemaVersion", 2))
        assertArrayEquals(
            hex("3078616263303030303030303030303030303030303030303030303030303030303030303030303030313a64656661756c7401"),
            wrap.sealAads.single(),
        )
    }

    @Test
    fun fm02TheFileIsVersionNonceCiphertextAndTagAndHasLength29PlusN() {
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, accountKey)
        val record = JSONObject().put("rev", 1).put("schemaVersion", 2)
        store.write(record)
        val bytes = files.map.values.single()
        val n = CanonicalJson.encode(record).toByteArray(Charsets.UTF_8).size
        assertEquals(29 + n, bytes.size)
        assertEquals(1, bytes[0].toInt())
        assertEquals(1, store.read()!!.getInt("rev"))
    }

    @Test
    fun fm03AVersionByteOtherThanOneIsRecordUnreadable() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        SealedPageRecordStore(wrap, files, accountKey).write(JSONObject().put("rev", 1).put("schemaVersion", 2))
        val name = fileName(accountKey)
        files.map[name]!![0] = 2
        assertUnreadableAndKept(wrap, files, name)
    }

    @Test
    fun fm04AFileOfAnotherAccountIsRecordUnreadableNotAbsent() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val other = "0x3333333333333333333333333333333333333333:default"
        SealedPageRecordStore(wrap, files, other).write(JSONObject().put("rev", 1).put("schemaVersion", 2))
        // The other account's file is placed under this account's name: the AAD does not match.
        val name = fileName(accountKey)
        files.write(name, files.map[fileName(other)]!!)
        assertUnreadableAndKept(wrap, files, name)
    }

    @Test
    fun fm05AFileShorterThan29BytesIsRecordUnreadable() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val name = fileName(accountKey)
        files.write(name, ByteArray(28) { 1 })
        assertUnreadableAndKept(wrap, files, name)
    }

    /** The bridge answers `record_unreadable` (never `absent`), and a write does not replace the file. */
    private fun assertUnreadableAndKept(wrap: KeyWrap, files: NativeTestFiles, name: String) {
        val before = files.map[name]!!.copyOf()
        val store = SealedPageRecordStore(wrap, files, accountKey)
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store, eoa.lowercase()) },
            migrating = { false },
            // Even with a confirmed-absent legacy store, the unreadable record must not turn into `absent`.
            outcome = { ImportOutcome.ABSENT },
        )
        val read = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "f1"), 40)
        assertEquals("error", read.v().getString("code"))
        assertEquals("record_unreadable", read.v().getString("sub"))
        assertFalse(read.v().has("record"))

        val write = bridge.handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject()
                .put("type", "shellRecordWrite")
                .put("reqId", "f2")
                .put("record", JSONObject().put("rev", 0).put("schemaVersion", 2).put("profiles", org.json.JSONArray())),
            200,
        )
        // 25.52CK.8 (r3ek): a write whose pre-write read fails is write_failed, once; record_unreadable is for reads.
        // SRP-04 (option A): the write fault is the envelope {ok:false, error:"write_failed"}.
        assertEquals(false, write.getBoolean("ok"))
        assertEquals("write_failed", write.getString("error"))
        assertTrue("the unreadable file is kept", before.contentEquals(files.map[name]!!))
    }

    private fun fileName(account: String): String {
        val bare = account.substringBefore(':').removePrefix("0x")
        return "page.v1.$bare.${account.substringAfter(':')}.rec"
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    /** Records the AAD of every seal, and delegates the sealing to the test wrap. */
    private class CapturingWrap : KeyWrap {
        private val inner = NativeTestWrap()
        val sealAads = mutableListOf<ByteArray>()

        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray {
            sealAads += aad
            return inner.seal(aad, plain)
        }

        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = inner.open(aad, sealed)

        override fun deleteKey() = inner.deleteKey()
    }
}
