package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

/**
 * The production adapters of `accountCleanupOld` (Y.100, 2026-11-16): for each store, the new account's items are kept, an old account's items are
 * removed, an item with no owner is kept and does not block ok, and one removal that does not take effect is clear_incomplete. Every store is run
 * through [AccountCleanupRun] in a temporary directory with in-memory key items; no device data and no key is touched.
 */
class AccountCleanupStoresTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val newEoa = "0x1111111111111111111111111111111111111111"
    private val oldEoa = "0x2222222222222222222222222222222222222222"
    private val newKey = "$newEoa:default"

    private fun run(adapters: List<CleanupAdapter>, confirmed: Boolean = true): AccountCleanupOld.Outcome {
        val state = AndroidVaultFiles(tmp.root.resolve("state").apply { mkdirs() })
        val confirmation = CleanupConfirmation(state)
        if (confirmed) confirmation.record(newKey, 1L)
        return AccountCleanupRun(CleanupJournal(state), confirmation, adapters).run(
            payloadFields = listOf("accountKey", "idempotencyKey"),
            accountKey = newKey,
            idempotencyKey = "idem-" + System.nanoTime(),
            gateNotReady = false,
            newAccountKey = newKey,
            newAccountReadable = true,
        )
    }

    /** Fails the removal of one item, as a removal that does not take effect does. */
    private class FailingRemoval(private val inner: CleanupAdapter, private val fails: (String) -> Boolean) : CleanupAdapter {
        override fun scan(newAccountKey: String) = inner.scan(newAccountKey)

        override fun remove(item: AccountCleanupOld.Item): Boolean = if (fails(item.name)) false else inner.remove(item)
    }

    private fun envelope(eoa: String?): String {
        val o = JSONObject().put("v", 1).put("kind", "rec").put("sealed", "AAAA")
        if (eoa != null) o.put("eoa", eoa)
        return o.toString()
    }

    private fun nativeDir(): File = tmp.root.resolve("native_wallet_v1").apply { mkdirs() }

    private fun walletAdapters(dir: File, fail: ((String) -> Boolean)? = null): List<CleanupAdapter> {
        val wallet = FileDirCleanup(dir, "wallet", { it.startsWith("wallet.v1.") }, { d, _ -> CleanupOwners.walletVaultOwner(d) })
        return listOf(if (fail == null) wallet else FailingRemoval(wallet, fail))
    }

    // ---- a. native vault (wallet.v1.*), by the vault's EOA ----

    @Test
    fun aNativeVaultOfTheNewAccountIsKept() {
        val dir = nativeDir()
        File(dir, "wallet.v1.rec").writeText(envelope(newEoa))
        File(dir, "wallet.v1.ok").writeText("digest")

        assertEquals(AccountCleanupOld.OK, run(walletAdapters(dir)).code)
        assertTrue(File(dir, "wallet.v1.rec").exists())
        assertTrue(File(dir, "wallet.v1.ok").exists())
    }

    @Test
    fun aNativeVaultOfAnOldAccountIsRemoved() {
        val dir = nativeDir()
        File(dir, "wallet.v1.rec").writeText(envelope(oldEoa))
        File(dir, "wallet.v1.ok").writeText("digest")

        assertEquals(AccountCleanupOld.OK, run(walletAdapters(dir)).code)
        assertFalse(File(dir, "wallet.v1.rec").exists())
        assertFalse(File(dir, "wallet.v1.ok").exists())
    }

    @Test
    fun aNativeVaultWithNoReadableOwnerIsKeptAndDoesNotBlockOk() {
        val dir = nativeDir()
        File(dir, "wallet.v1.rec").writeText(envelope(null))

        assertEquals(AccountCleanupOld.OK, run(walletAdapters(dir)).code)
        assertTrue(File(dir, "wallet.v1.rec").exists())
    }

    @Test
    fun aNativeVaultRemovalThatFailsIsClearIncomplete() {
        val dir = nativeDir()
        File(dir, "wallet.v1.rec").writeText(envelope(oldEoa))
        File(dir, "wallet.v1.ok").writeText("digest")

        val out = run(walletAdapters(dir) { it.endsWith("wallet.v1.ok") })

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
        assertTrue("the failed item stays", File(dir, "wallet.v1.ok").exists())
        assertFalse("the others are removed, not rolled back", File(dir, "wallet.v1.rec").exists())
    }

    // ---- c. native PGP files (pgp.v1.*), by the name's EOA ----

    private fun pgpAdapters(dir: File, fail: ((String) -> Boolean)? = null): List<CleanupAdapter> {
        val pgp = FileDirCleanup(dir, "pgp", { it.startsWith("pgp.v1.") }, { _, name -> CleanupOwners.pgpOwner(name) })
        return listOf(if (fail == null) pgp else FailingRemoval(pgp, fail))
    }

    private val newHex = newEoa.removePrefix("0x")

    private val oldHex = oldEoa.removePrefix("0x")

    @Test
    fun aPgpFileOfTheNewAccountIsKept() {
        val dir = nativeDir()
        File(dir, "pgp.v1.$newHex.rec").writeText("x")

        assertEquals(AccountCleanupOld.OK, run(pgpAdapters(dir)).code)
        assertTrue(File(dir, "pgp.v1.$newHex.rec").exists())
    }

    @Test
    fun aPgpFileOfAnOldAccountIsRemovedIncludingTheMigrationFiles() {
        val dir = nativeDir()
        File(dir, "pgp.v1.$oldHex.rec").writeText("x")
        File(dir, "pgp.v1.pending.$oldHex.meta").writeText("x")
        File(dir, "pgp.v1.mig.$oldHex.default.n").writeText("x")

        assertEquals(AccountCleanupOld.OK, run(pgpAdapters(dir)).code)
        assertEquals(emptyList<String>(), dir.list()!!.toList())
    }

    @Test
    fun aPgpFileWithNoOwnerIsKept() {
        val dir = nativeDir()
        File(dir, "pgp.v1.garbage.rec").writeText("x")
        File(dir, "pgp.v1.mig.$oldHex.n").writeText("x")

        assertEquals(AccountCleanupOld.OK, run(pgpAdapters(dir)).code)
        assertTrue("no owner: kept", File(dir, "pgp.v1.garbage.rec").exists())
        assertTrue("a migration file without its workspace has no owner: kept", File(dir, "pgp.v1.mig.$oldHex.n").exists())
    }

    @Test
    fun aPgpRemovalThatFailsIsClearIncomplete() {
        val dir = nativeDir()
        File(dir, "pgp.v1.$oldHex.rec").writeText("x")
        File(dir, "pgp.v1.pending.$oldHex.meta").writeText("x")

        val out = run(pgpAdapters(dir) { it.endsWith("pending.$oldHex.meta") })

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(File(dir, "pgp.v1.pending.$oldHex.meta").exists())
        assertFalse(File(dir, "pgp.v1.$oldHex.rec").exists())
    }

    // ---- b. page copies (page.v1.*), by the name ----

    private fun pageAdapters(dir: File, fail: ((String) -> Boolean)? = null): List<CleanupAdapter> {
        val page = FileDirCleanup(dir, "page", { it.startsWith("page.v1.") }, { _, name -> CleanupOwners.pageOwner(name) })
        return listOf(if (fail == null) page else FailingRemoval(page, fail))
    }

    @Test
    fun aPageCopyOfTheNewAccountIsKeptAndTheFlagIsNotAccountKeyed() {
        val dir = tmp.root.resolve("page_record_v1").apply { mkdirs() }
        File(dir, "page.v1.$newHex.default.rec").writeText("x")
        File(dir, "account_pointer.v1").writeText("1")

        assertEquals(AccountCleanupOld.OK, run(pageAdapters(dir)).code)
        assertTrue(File(dir, "page.v1.$newHex.default.rec").exists())
        assertTrue("a device flag is not an account's item", File(dir, "account_pointer.v1").exists())
    }

    @Test
    fun aPageCopyOfAnOldAccountIsRemoved() {
        val dir = tmp.root.resolve("page_record_v1").apply { mkdirs() }
        File(dir, "page.v1.$oldHex.default.rec").writeText("x")

        assertEquals(AccountCleanupOld.OK, run(pageAdapters(dir)).code)
        assertFalse(File(dir, "page.v1.$oldHex.default.rec").exists())
    }

    @Test
    fun aPageCopyWithAnUnknownNameIsKept() {
        val dir = tmp.root.resolve("page_record_v1").apply { mkdirs() }
        File(dir, "page.v1.unknown.rec").writeText("x")

        assertEquals(AccountCleanupOld.OK, run(pageAdapters(dir)).code)
        assertTrue(File(dir, "page.v1.unknown.rec").exists())
    }

    @Test
    fun aPageCopyRemovalThatFailsIsClearIncomplete() {
        val dir = tmp.root.resolve("page_record_v1").apply { mkdirs() }
        File(dir, "page.v1.$oldHex.default.rec").writeText("x")

        val out = run(pageAdapters(dir) { it.endsWith("page.v1.$oldHex.default.rec") })

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(File(dir, "page.v1.$oldHex.default.rec").exists())
    }

    // ---- e. K items (K.v1|eoa|workspace) ----

    private class FailingKBackend(private val inner: AccountPgpKBackend, private val failName: String) : AccountPgpKBackend {
        override fun get(name: String): String? = inner.get(name)

        override fun put(name: String, value: String): Boolean = inner.put(name, value)

        override fun names(): Set<String> = inner.names()

        override fun remove(name: String): Boolean = if (name == failName) false else inner.remove(name)
    }

    @Test
    fun aKItemOfTheNewAccountIsKeptOfAnOldAccountRemovedAndAnotherNameIsUntouched() {
        val backend = MemoryAccountPgpKBackend()
        backend.put("K.v1|$newEoa|default", "k-new")
        backend.put("K.v1|$oldEoa|default", "k-old")
        backend.put("unrelated", "x")

        assertEquals(AccountCleanupOld.OK, run(listOf(KPgpCleanup(backend))).code)
        assertEquals(setOf("K.v1|$newEoa|default", "unrelated"), backend.names())
    }

    @Test
    fun aKItemWithNoOwnerIsKeptAndDoesNotBlockOk() {
        val backend = MemoryAccountPgpKBackend()
        backend.put("K.v1|garbage", "x")

        assertEquals(AccountCleanupOld.OK, run(listOf(KPgpCleanup(backend))).code)
        assertTrue(backend.names().contains("K.v1|garbage"))
    }

    @Test
    fun aKRemovalThatFailsIsClearIncompleteAndTheOthersAreRemoved() {
        val inner = MemoryAccountPgpKBackend()
        inner.put("K.v1|$oldEoa|default", "k-old")
        inner.put("K.v1|$oldEoa|other", "k-old-2")
        val backend = FailingKBackend(inner, "K.v1|$oldEoa|other")

        val out = run(listOf(KPgpCleanup(backend)))

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertEquals(setOf("K.v1|$oldEoa|other"), inner.names())
    }

    // ---- d. legacy records: the legacy PGP record L and the legacy wallet copy, by the EOA each names ----

    @Test
    fun aLegacyRecordOfTheNewAccountIsKept() {
        var cleared = false
        val out = run(listOf(SingleRecordCleanup("legacy_pgp", { newEoa }, { cleared = true; true })))

        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(cleared)
    }

    @Test
    fun aLegacyRecordOfAnOldAccountIsRemoved() {
        var cleared = false
        val out = run(listOf(SingleRecordCleanup("wallet_copy", { oldEoa }, { cleared = true; true })))

        assertEquals(AccountCleanupOld.OK, out.code)
        assertTrue(cleared)
    }

    @Test
    fun aLegacyRecordWithNoEoaIsNotAnItem() {
        val out = run(listOf(SingleRecordCleanup("legacy_pgp", { null }, { error("must not run") })))

        assertEquals(AccountCleanupOld.OK, out.code)
    }

    @Test
    fun aLegacyRecordThatCannotBeClearedIsClearIncomplete() {
        val out = run(listOf(SingleRecordCleanup("wallet_copy", { oldEoa }, { false })))

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
    }

    @Test
    fun aStoreThatCannotBeReadIsClearIncomplete() {
        val out = run(listOf(SingleRecordCleanup("legacy_pgp", { throw java.io.IOException("unreadable") }, { true })))

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
    }

    // ---- Y.103 blocker: a read failure is unknown and retryable (clear_incomplete, nothing removed); a parse failure is unowned (kept, ok) ----

    /** The wallet vault: a readable old envelope next to a vault name that cannot be read: the owner is unknown, nothing is removed. */
    @Test
    fun aWalletVaultFileThatCannotBeReadIsClearIncompleteAndNothingOfTheVaultIsRemoved() {
        val dir = nativeDir()
        File(dir, "wallet.v1.rec").writeText(envelope(oldEoa))
        File(dir, "wallet.v1.ok").mkdirs()

        val out = run(walletAdapters(dir))

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
        assertTrue("the readable old record is kept, not decided from a partial read", File(dir, "wallet.v1.rec").exists())
    }

    /** A wallet vault name that is present but is not a regular file is a read failure too. */
    @Test
    fun aWalletVaultNameThatIsNotAFileIsUnreadable() {
        val dir = nativeDir()
        File(dir, "wallet.v1.rec").mkdirs()

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, run(walletAdapters(dir)).code)
    }

    /** A wallet vault file that reads but is not a JSON envelope is a parse failure: unowned, kept, and ok. */
    @Test
    fun aWalletVaultFileThatDoesNotParseIsUnownedKeptAndOk() {
        val dir = nativeDir()
        File(dir, "wallet.v1.rec").writeText("not json")

        val out = run(walletAdapters(dir))

        assertEquals(AccountCleanupOld.OK, out.code)
        assertTrue(File(dir, "wallet.v1.rec").exists())
        assertEquals(1, out.retainedUnattributed)
    }

    /** The native vault directory that cannot be listed is an incomplete scan. */
    @Test
    fun aNativeDirectoryThatCannotBeListedIsClearIncomplete() {
        val dir = tmp.root.resolve("native_wallet_v1")
        dir.writeText("not a directory")

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, run(walletAdapters(dir)).code)
    }

    /** The page directory that cannot be listed is an incomplete scan. */
    @Test
    fun aPageDirectoryThatCannotBeListedIsClearIncomplete() {
        val dir = tmp.root.resolve("page_record_v1")
        dir.writeText("not a directory")

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, run(pageAdapters(dir)).code)
    }

    /** The K items whose names cannot be read are an incomplete scan; nothing is removed. */
    @Test
    fun aKStoreThatCannotBeReadIsClearIncomplete() {
        val unreadable = object : AccountPgpKBackend {
            override fun get(name: String): String? = null

            override fun put(name: String, value: String): Boolean = false

            override fun names(): Set<String> = throw IOException("unreadable")

            override fun remove(name: String): Boolean = false
        }

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, run(listOf(KPgpCleanup(unreadable))).code)
    }

    /** A K name whose EOA does not parse is unowned: kept, and ok. */
    @Test
    fun aKNameThatDoesNotParseIsUnownedKeptAndOk() {
        val backend = MemoryAccountPgpKBackend()
        backend.put("K.v1|not-an-address|default", "x")

        assertEquals(AccountCleanupOld.OK, run(listOf(KPgpCleanup(backend))).code)
        assertTrue(backend.names().contains("K.v1|not-an-address|default"))
    }

    /** A legacy wallet copy that cannot be read is an incomplete scan (the copy's EOA read throws). */
    @Test
    fun aLegacyWalletCopyThatCannotBeReadIsClearIncomplete() {
        val out = run(listOf(SingleRecordCleanup("wallet_copy", { throw IOException("prefs unreadable") }, { error("must not run") })))

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
    }

    /** A legacy record whose EOA does not parse is unowned: kept, and ok. */
    @Test
    fun aLegacyRecordWhoseEoaDoesNotParseIsUnownedKeptAndOk() {
        val out = run(listOf(SingleRecordCleanup("legacy_pgp", { "garbage" }, { error("must not run") })))

        assertEquals(AccountCleanupOld.OK, out.code)
        assertEquals(1, out.retainedUnattributed)
    }

    /** The history directory that cannot be listed is an incomplete scan. */
    @Test
    fun aHistoryDirectoryThatCannotBeListedIsClearIncomplete() {
        val file = tmp.root.resolve("conet-chat")
        file.writeText("not a directory")

        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, run(listOf(HistoryDirCleanup(file))).code)
    }

    // ---- Y.103: the inbox entries are retained and counted; an unreadable inbox is incomplete ----

    @Test
    fun theInboxEntriesAreRetainedAndCountedInTheOutcome() {
        val out = run(listOf(UnattributedInboxCleanup { 3 }))

        assertEquals(AccountCleanupOld.OK, out.code)
        assertEquals(3, out.retainedUnattributed)
    }

    @Test
    fun anUnreadableInboxIsClearIncomplete() {
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, run(listOf(UnattributedInboxCleanup { throw IOException("inbox unreadable") })).code)
    }
}
