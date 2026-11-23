package network.conet.chat.nativekey

import network.conet.chat.ChatHistoryFileNames
import network.conet.chat.passcode.PasscodeRecordStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The old accounts are every identifiable account on the device but the new one. This device holds two old accounts and one new account; the
 * cleanup, wired through the real enumeration and adapters, removes both old accounts' exact-owner items and keeps the new account intact.
 */
class AccountCleanupAllButNewTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val newEoa = "0x1111111111111111111111111111111111111111"
    private val old1 = "0x2222222222222222222222222222222222222222"
    private val old2 = "0x3333333333333333333333333333333333333333"
    private val newKey = "$newEoa:default"

    /** In-memory K store (the account PGP store's names). */
    private class FakeK(val map: MutableMap<String, String>) : AccountPgpKBackend {
        override fun get(name: String): String? = map[name]
        override fun put(name: String, value: String): Boolean { map[name] = value; return true }
        override fun names(): Set<String> = map.keys.toSet()
        override fun remove(name: String): Boolean { map.remove(name); return true }
    }

    private fun hex(eoa: String) = eoa.removePrefix("0x")

    @Test
    fun twoOldAccountsAreClearedAndTheNewAccountIsKeptIntact() {
        val files = tmp.newFolder("files")
        val noBackup = tmp.newFolder("nobackup")
        val native = File(files, "native_wallet_v1").apply { mkdirs() }
        // The vault holds the NEW account (after recovery): the current owner is not the old set.
        File(native, NativeWalletVault.REC).writeText("""{"v":1,"eoa":"$newEoa"}""")
        File(native, "pgp.v1.${hex(old1)}").writeText("pgp-old1")
        File(native, "pgp.v1.${hex(old2)}").writeText("pgp-old2")
        File(native, "pgp.v1.${hex(newEoa)}").writeText("pgp-new")
        val page = File(noBackup, "page_record_v1").apply { mkdirs() }
        File(page, "page.v1.${hex(old1)}.default.rec").writeText("page-old1")
        File(page, "page.v1.${hex(old2)}.default.rec").writeText("page-old2")
        File(page, "page.v1.${hex(newEoa)}.default.rec").writeText("page-new")
        val pass = File(noBackup, PasscodeRecordStore.DIRECTORY).apply { mkdirs() }
        File(pass, old1).writeText("pass-old1")
        File(pass, old2).writeText("pass-old2")
        File(pass, newEoa).writeText("pass-new")
        val history = File(files, "conet-chat").apply { mkdirs() }
        File(history, ChatHistoryFileNames.localName(old1)).writeText("h-old1")
        File(history, ChatHistoryFileNames.localName(old2)).writeText("h-old2")
        File(history, ChatHistoryFileNames.localName(newEoa)).writeText("h-new")
        val k = FakeK(mutableMapOf("K.v1|$old1|default" to "k-old1", "K.v1|$old2|default" to "k-old2", "K.v1|$newEoa|default" to "k-new"))

        val oldSet = AccountCleanupWiring.oldAccounts(files, noBackup, k, { null }, { null }, newEoa)!!
        assertEquals("both old accounts are identified, the new one is not", setOf(old1.lowercase(), old2.lowercase()), oldSet)

        val state = AndroidVaultFiles(tmp.newFolder("state"))
        val conf = CleanupConfirmation(state)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 1L)
        val adapters = AccountCleanupWiring.adapters(files, noBackup, k, oldSet, Any(), { newEoa })
        val out = AccountCleanupRun(CleanupJournal(state), conf, adapters).run(
            listOf("accountKey", "idempotencyKey"), newEoa, "idem-all-but-new", false, newKey, true, ReadBackCheck.Verdict.PASS,
        )

        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse("old pgp removed", File(native, "pgp.v1.${hex(old1)}").exists())
        assertFalse("old pgp removed", File(native, "pgp.v1.${hex(old2)}").exists())
        assertFalse("old page removed", File(page, "page.v1.${hex(old1)}.default.rec").exists())
        assertFalse("old page removed", File(page, "page.v1.${hex(old2)}.default.rec").exists())
        assertFalse("old passcode removed", File(pass, old1).exists())
        assertFalse("old passcode removed", File(pass, old2).exists())
        assertFalse("old history removed", File(history, ChatHistoryFileNames.localName(old1)).exists())
        assertFalse("old history removed", File(history, ChatHistoryFileNames.localName(old2)).exists())
        assertFalse("old K removed", k.map.containsKey("K.v1|$old1|default"))
        assertFalse("old K removed", k.map.containsKey("K.v1|$old2|default"))
        // The new account is intact.
        assertEquals("pgp-new", File(native, "pgp.v1.${hex(newEoa)}").readText())
        assertEquals("page-new", File(page, "page.v1.${hex(newEoa)}.default.rec").readText())
        assertEquals("pass-new", File(pass, newEoa).readText())
        assertEquals("h-new", File(history, ChatHistoryFileNames.localName(newEoa)).readText())
        assertEquals("k-new", k.map["K.v1|$newEoa|default"])
        assertEquals("""{"v":1,"eoa":"$newEoa"}""", File(native, NativeWalletVault.REC).readText())
        assertTrue(File(native, NativeWalletVault.REC).exists())
    }

    /**
     * every account identifiable on the device but the new one is old, so an identifiable stranger's page copy is cleared; a name that identifies no
     * account (not a 40-hex address) is never an owner and is kept.
     */
    @Test
    fun aStrangerIdentifiedOnTheDeviceIsOldAndAnUnidentifiableNameIsKept() {
        val noBackup = tmp.newFolder("nb2")
        val page = File(noBackup, "page_record_v1").apply { mkdirs() }
        val stranger = "0x4444444444444444444444444444444444444444"
        File(page, "page.v1.${hex(stranger)}.default.rec").writeText("stranger")
        File(page, "page.v1.not-an-address.default.rec").writeText("unidentifiable")
        val k = FakeK(mutableMapOf())
        val oldSet = AccountCleanupWiring.oldAccounts(tmp.newFolder("f2"), noBackup, k, { null }, { null }, newEoa)!!
        assertTrue("the identifiable stranger is an old account", oldSet.contains(stranger))
        val adapters = AccountCleanupWiring.adapters(tmp.newFolder("f3"), noBackup, k, oldSet, Any(), { newEoa })
        val pageAdapter = adapters.first { it.scan(newKey).items.any { i -> i.name.contains("page.v1.") } }
        val items = pageAdapter.scan(newKey).items
        assertEquals("the stranger's copy is owned by it", stranger.lowercase(), items.first { it.name.contains(hex(stranger)) }.accountKey?.substringBefore(':'))
        assertEquals("the unidentifiable name is kept, unattributed", null, items.first { it.name.contains("not-an-address") }.accountKey)
    }

    /** v220 240.4(5): an unreadable enumeration source makes the set unknown (null); it is never a smaller set. */
    @Test
    fun anUnreadableEnumerationSourceGivesNoSet() {
        val unreadableK = object : AccountPgpKBackend {
            override fun get(name: String): String? = null
            override fun put(name: String, value: String): Boolean = false
            override fun names(): Set<String> = throw IllegalStateException("unreadable")
            override fun remove(name: String): Boolean = false
        }
        assertEquals(null, AccountCleanupWiring.oldAccounts(tmp.newFolder("u1"), tmp.newFolder("u2"), unreadableK, { null }, { null }, newEoa))
    }

    /** Decision : an unknown active account is not_ready, deletes nothing, no keptUnattributed, no cleanupPending. */
    @Test
    fun anUnknownActiveAccountIsNotReadyAndDeletesNothing() {
        val files = tmp.newFolder("act-files")
        val noBackup = tmp.newFolder("act-nb")
        val native = File(files, "native_wallet_v1").apply { mkdirs() }
        File(native, "pgp.v1.${hex(old1)}").writeText("pgp-old1")
        val k = FakeK(mutableMapOf())
        val oldSet = AccountCleanupWiring.oldAccounts(files, noBackup, k, { null }, { null }, newEoa)!!
        val state = AndroidVaultFiles(tmp.newFolder("act-state"))
        val conf = CleanupConfirmation(state)
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 1L)
        val adapters = AccountCleanupWiring.adapters(files, noBackup, k, oldSet, Any(), { null })
        val out = AccountCleanupRun(CleanupJournal(state), conf, adapters).run(
            listOf("accountKey", "idempotencyKey"), newEoa, "idem-active", false, newKey, true, ReadBackCheck.Verdict.PASS, activeKnown = false,
        )
        assertEquals(AccountCleanupOld.NOT_READY, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(0, out.retainedUnattributed)
        assertTrue("nothing is deleted", File(native, "pgp.v1.${hex(old1)}").exists())
    }
}
