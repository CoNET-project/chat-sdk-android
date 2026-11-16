package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/** `pageCopyState` (§25.52PY.15 第 15 项, §25.52PY.17). Each state of the page copy, and the three-way EOA match. */
class PageCopyStateTest {
    private val account = VectorSidecar.ACCOUNT
    private val other = VectorSidecar.OTHER

    /** A wrapping key that is gone: the stored record cannot be opened, so the copy is unreadable. */
    private object GoneWrap : KeyWrap {
        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray = throw IllegalStateException("gone")
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = null
        override fun deleteKey(): Boolean = false
    }

    /** A copy holding the account's own key under its own keyID (the normal, readable form). */
    private fun copyOf(keyId: String, armor: String?): JSONObject {
        val profile = JSONObject().put("keyID", keyId)
        if (armor != null) profile.put("privateKeyArmor", armor)
        return JSONObject().put("rev", 1).put("schemaVersion", 2).put("profiles", JSONArray().put(profile))
    }

    private fun storeWith(record: JSONObject?): Pair<SealedPageRecordStore, NativeTestFiles> {
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$account:default")
        if (record != null) store.write(record)
        return store to files
    }

    @Test
    fun noCopyIsAbsent() {
        val (store, _) = storeWith(null)
        assertEquals(PageCopyState.Result.Absent, PageCopyState.of(account, store, account))
    }

    @Test
    fun aCopyThatCannotBeOpenedIsUnreadable() {
        val (_, files) = storeWith(copyOf(account, VectorSidecar.ARMOR_OF_ACCOUNT))
        val locked = SealedPageRecordStore(GoneWrap, files, "$account:default")
        assertEquals(PageCopyState.Result.Unreadable, PageCopyState.of(account, locked, account))
    }

    @Test
    fun aReadableCopyMatchesWhenTheThreeEoasAreEqual() {
        val (store, _) = storeWith(copyOf(account, VectorSidecar.ARMOR_OF_ACCOUNT))
        assertEquals(PageCopyState.Result.Readable(true), PageCopyState.of(account, store, account))
    }

    @Test
    fun aKeychainOfAnotherAccountDoesNotMatch() {
        val (store, _) = storeWith(copyOf(account, VectorSidecar.ARMOR_OF_ACCOUNT))
        assertEquals(PageCopyState.Result.Readable(false), PageCopyState.of(account, store, other))
        assertEquals(PageCopyState.Result.Readable(false), PageCopyState.of(account, store, null))
    }

    @Test
    fun anInputEoaOfAnotherAccountDoesNotMatch() {
        val (store, _) = storeWith(copyOf(account, VectorSidecar.ARMOR_OF_ACCOUNT))
        assertEquals(PageCopyState.Result.Readable(false), PageCopyState.of(other, store, other))
    }

    @Test
    fun aCopyWithoutAKeyIsReadableButNotAMatch() {
        val (store, _) = storeWith(copyOf(account, null))
        assertEquals(PageCopyState.Result.Readable(false), PageCopyState.of(account, store, account))
    }

    @Test
    fun aKeyThatDoesNotDeriveItsProfileIsNotAMatch() {
        // The profile names the other account, but the key is the account's: the decoded EOA is the account, not the profile, so no match.
        val (store, _) = storeWith(copyOf(other, VectorSidecar.ARMOR_OF_ACCOUNT))
        assertEquals(PageCopyState.Result.Readable(false), PageCopyState.of(other, store, other))
    }
}
