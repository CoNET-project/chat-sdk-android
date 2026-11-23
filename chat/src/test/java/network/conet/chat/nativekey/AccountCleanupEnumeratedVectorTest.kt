package network.conet.chat.nativekey

import network.conet.chat.ChatHistoryFileNames
import network.conet.chat.ConetChatCryptoUtil
import network.conet.chat.passcode.PasscodeRecordStore
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.MessageDigest

/**
 * Drives the enumerated-accounts vector v4 (spec/VECTOR-enumerated-accounts-v4-2026-11-21.json, EA-01..EA-14; v1-v3 are void) through the production
 * enumeration ([AccountCleanupWiring.oldAccounts]), the production adapters and [AccountCleanupRun]. The vector file is pinned by its SHA-256.
 *
 * Coverage limits (reported, not hidden): EA-11 (Secure Enclave key) is not applicable on Android: no SE alias store exists in this codebase, so no case is
 * driven for it. EA-14 is driven only for the wallet-raw residue kind (real isolated copies); the passcode H layer, the recovery backup flag and the wallet
 * credential block are not counted by any adapter yet (recorded as an open gap). EA-04 is a defensive branch and takes an explicit PASS read-back.
 */
class AccountCleanupEnumeratedVectorTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val newEoa = "0x1111111111111111111111111111111111111111"
    private val old1 = "0x2222222222222222222222222222222222222222"
    /** old2 is the address of a valid BIP39 phrase, so its sealed mnemonic record verifies (EA-01). */
    private val old2Phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val old2 = checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(old2Phrase)))).lowercase()

    /** One wrap seals the fixtures and verifies them: the production phrase check of the vault (phraseItemOf). */
    private val sharedWrap = NativeTestWrap()
    private val verify: (ByteArray) -> NativeWalletVault.PhraseItem = { NativeWalletVault(sharedWrap, NativeTestFiles()).phraseItemOf(it) }

    /** The sealed mnemonic envelope the vault writes (NativeWalletVault.encodeMnemonic layout) for [eoa] and [phrase]. */
    private fun sealedEnvelope(eoa: String, phrase: String): String {
        val sealed = sharedWrap.seal(NativeWalletVault.mnemAad(eoa), phrase.toByteArray(Charsets.UTF_8))
        return JSONObject().put("record", NativeWalletVault.RECORD_VERSION).put("eoa", eoa).put("sealed", ConetChatCryptoUtil.toHex(sealed)).toString()
    }

    /** A readable residue that does not verify (a wrong BIP39 checksum), with an envelope eoa of [eoa]: its owner is not proven (UNV-01..03). */
    private fun unverifiableResidue(fx: Fx, eoa: String) {
        val bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        File(fx.native, NativeWalletVault.MNEM).writeText(sealedEnvelope(eoa, bad))
    }
    private val newKey = "$newEoa:default"

    private class FakeK : AccountPgpKBackend {
        val map = mutableMapOf<String, String>()
        override fun get(name: String): String? = map[name]
        override fun put(name: String, value: String): Boolean { map[name] = value; return true }
        override fun names(): Set<String> = map.keys.toSet()
        override fun remove(name: String): Boolean { map.remove(name); return true }
    }

    /** One device's storage, filled per the vector's sources. */
    private inner class Fx(root: File) {
        val files = File(root, "files").apply { mkdirs() }
        val noBackup = File(root, "nobackup").apply { mkdirs() }
        val native = File(files, "native_wallet_v1").apply { mkdirs() }
        val pageDir = File(noBackup, "page_record_v1").apply { mkdirs() }
        val passDir = File(noBackup, PasscodeRecordStore.DIRECTORY)
        val history = File(files, "conet-chat").apply { mkdirs() }
        val k = FakeK()
        val state = File(files, "account_cleanup_v1").apply { mkdirs() }

        fun fill(
            keyVault: List<String> = emptyList(),
            mnemonic: List<String> = emptyList(),
            passcode: List<String> = emptyList(),
            page: List<String> = emptyList(),
            pgp: List<String> = emptyList(),
            chat: List<String> = emptyList(),
            kItem: List<String> = emptyList(),
            strays: List<String> = emptyList(),
            passcodeAsFile: Boolean = false,
        ) {
            keyVault.firstOrNull()?.let { File(native, NativeWalletVault.REC).writeText("""{"v":1,"eoa":"$it"}""") }
            mnemonic.firstOrNull()?.let { eoa -> File(native, NativeWalletVault.MNEM).writeText(sealedEnvelope(eoa, old2Phrase)) }
            // Non-account files of the vault directory: never in any adapter, never counted.
            File(native, "owner_v1.txt").writeText("owner")
            File(native, "inbox_v1.json").writeText("[]")
            File(native, "call_signals_v1.json").writeText("[]")
            if (passcodeAsFile) {
                // A passcode directory that cannot be listed: the enumeration source is unreadable (EA-05).
                passDir.writeText("not a directory")
            } else {
                passDir.mkdirs()
                passcode.forEach { File(passDir, it).writeText("pass") }
            }
            page.forEach { File(pageDir, "page.v1.${hex(it)}.default.rec").writeText("page") }
            pgp.forEach { File(native, "pgp.v1.${hex(it)}").writeText("pgp") }
            chat.forEach { File(history, ChatHistoryFileNames.localName(it)).writeText("chat") }
            kItem.forEach { k.map["K.v1|$it|default"] = "k" }
            strays.forEach { File(native, "pgp.v1.$it").writeText("stray") }
        }
    }

    private fun hex(eoa: String) = eoa.removePrefix("0x")

    /** A real isolated copy of the vault record, named as NativeWalletVault names them (name + ".isolated." + stamp + "." + hex). */
    private fun isolated(fx: Fx, tag: String) {
        File(fx.native, "${NativeWalletVault.REC}.isolated.20261121T000000Z.${tag.repeat(8)}").writeText("iso")
    }

    /**
     * The module's order: one snapshot of the active pointer for the run (SNAP-01), then the run. [pointer] is the live reader (a re-read takes a new snapshot);
     * [readBack] overrides the production read-back for the EA-04 defensive branch only.
     */
    private fun Fx.cleanup(
        activeEoa: String?,
        idem: String = "idem-ea",
        pointer: (() -> String?)? = null,
        readBack: ReadBackCheck.Verdict? = null,
        unsent: (File) -> UnsentRead = { UnsentRead.NONE },
        beforeRemoval: (() -> Unit)? = null,
    ): AccountCleanupOld.Outcome {
        val reader: () -> String? = pointer ?: { activeEoa }
        val snap = AccountCleanupWiring.takeSnapshot(reader)
        val oldSet = AccountCleanupWiring.oldAccounts(files, noBackup, k, { null }, { null }, newEoa, mnemPhrase = verify)
            ?: return AccountCleanupOld.Outcome(AccountCleanupOld.NOT_READY, emptyList(), emptyList(), cleanupPending = false)
        val conf = CleanupConfirmation(AndroidVaultFiles(state))
        AutoConfirmation.onPageConfirm(conf, newEoa, newEoa, newEoa, 1L)
        val adapters = AccountCleanupWiring.adapters(files, noBackup, k, oldSet, Any(), { snap.eoa }, unsent, mnemPhrase = verify)
        return AccountCleanupRun(CleanupJournal(AndroidVaultFiles(state)), conf, adapters).run(
            payloadFields = listOf("accountKey", "idempotencyKey"),
            accountKey = newEoa,
            idempotencyKey = idem,
            gateNotReady = false,
            newAccountKey = newKey,
            newAccountReadable = true,
            readBack = readBack ?: AccountCleanupWiring.readBackVerdict(newEoa, snap),
            activeKnown = snap.eoa != null,
            // The EA-04 defensive override covers the re-reads too; otherwise each re-read takes a fresh snapshot.
            rereadBack = {
                // Runs before each removal: the injection point of the removal-phase read failure (UNK-03).
                beforeRemoval?.invoke()
                readBack ?: AccountCleanupWiring.readBackVerdict(newEoa, AccountCleanupWiring.takeSnapshot(reader))
            },
        )
    }

    private fun assertRefused(out: AccountCleanupOld.Outcome, code: String) {
        assertEquals(code, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(0, out.retainedUnattributed)
    }

    @Test
    fun theVectorFileIsThePinnedV4() {
        val file = File("../spec/VECTOR-enumerated-accounts-v4-2026-11-21.json")
        val digest = MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }
        assertEquals("15b54fa2be6b2d187ec8be305312e3219c0e0bfa7772fb36cb4df5a71ccdd3b4", digest)
        val text = file.readText()
        listOf(
            "EA-01-multi-old-all-cleared", "EA-02-only-page-copy-pgp-chat-old", "EA-03-unattributable-kept-counted",
            "EA-04-active-equals-candidate-kept-whole", "EA-05-enumeration-source-read-failed-not_ready", "EA-06-replay-same-key-no-redelete",
            "EA-07-active-unknown-not_ready", "EA-08-active-unknown-differs-from-equal", "EA-09-mismatch-mid-run-stop-no-rollback",
            "EA-10-non-enumerable-residue-counted-not-ok-silent", "EA-11-se-key-kept-identified-only",
            "EA-12-readback-mismatch-readable-account_mismatch", "EA-13-mid-run-active-switch-stop", "EA-14-iOS-nonenumerable-residue-counted-ok",
        ).forEach { assertTrue(it, text.contains("\"id\": \"$it\"")) }
    }

    @Test
    fun ea01MultiOldAllCleared() {
        val fx = Fx(tmp.newFolder("ea01"))
        fx.fill(keyVault = listOf(old1), mnemonic = listOf(old2), passcode = listOf(old1, old2), page = listOf(old2), pgp = listOf(old1), chat = listOf(old2), kItem = listOf(old1))
        val out = fx.cleanup(activeEoa = newEoa)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(0, out.retainedUnattributed)
        assertFalse(File(fx.native, NativeWalletVault.REC).exists())
        assertFalse(File(fx.native, NativeWalletVault.MNEM).exists())
        assertFalse(File(fx.passDir, old1).exists())
        assertFalse(File(fx.passDir, old2).exists())
        assertFalse(File(fx.pageDir, "page.v1.${hex(old2)}.default.rec").exists())
        assertFalse(File(fx.native, "pgp.v1.${hex(old1)}").exists())
        assertFalse(File(fx.history, ChatHistoryFileNames.localName(old2)).exists())
        assertFalse(fx.k.map.containsKey("K.v1|$old1|default"))
        listOf("owner_v1.txt", "inbox_v1.json", "call_signals_v1.json").forEach { assertTrue(File(fx.native, it).exists()) }
    }

    @Test
    fun ea02OnlyPageCopyPgpChatOfOldAreCleared() {
        val fx = Fx(tmp.newFolder("ea02"))
        fx.fill(page = listOf(old1), pgp = listOf(old1), chat = listOf(old1))
        val out = fx.cleanup(activeEoa = newEoa)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(0, out.retainedUnattributed)
        assertFalse(File(fx.pageDir, "page.v1.${hex(old1)}.default.rec").exists())
        assertFalse(File(fx.native, "pgp.v1.${hex(old1)}").exists())
        assertFalse(File(fx.history, ChatHistoryFileNames.localName(old1)).exists())
    }

    @Test
    fun ea03UnattributableKeptAndCounted() {
        val fx = Fx(tmp.newFolder("ea03"))
        // The vector's unattributable entries are stray page and PGP copies whose names no old address recomputes.
        fx.fill(keyVault = listOf(old1), strays = listOf("stray_page_1", "stray_pgp_1"))
        val out = fx.cleanup(activeEoa = newEoa)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(2, out.retainedUnattributed)
        assertFalse(File(fx.native, NativeWalletVault.REC).exists())
        assertTrue(File(fx.native, "pgp.v1.stray_pgp_1").exists())
        assertTrue(File(fx.native, "pgp.v1.stray_page_1").exists())
    }

    @Test
    fun ea04ActiveEqualsCandidateKeptWholeOtherOldCleared() {
        val fx = Fx(tmp.newFolder("ea04"))
        fx.fill(keyVault = listOf(old1), page = listOf(old1), passcode = listOf(old2))
        // Defensive branch only: reachable in production when the read-back passes, so the read-back is given explicitly as PASS.
        val out = fx.cleanup(activeEoa = old1, readBack = ReadBackCheck.Verdict.PASS)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        // The vector's count: the old1 group (key file and page copy), kept whole and counted.
        assertEquals(2, out.retainedUnattributed)
        assertTrue(File(fx.native, NativeWalletVault.REC).exists())
        assertTrue(File(fx.pageDir, "page.v1.${hex(old1)}.default.rec").exists())
        assertFalse(File(fx.passDir, old2).exists())
    }

    @Test
    fun ea05EnumerationSourceReadFailedIsNotReadyAndDeletesNothing() {
        val fx = Fx(tmp.newFolder("ea05"))
        fx.fill(keyVault = listOf(old1), passcodeAsFile = true)
        assertRefused(fx.cleanup(activeEoa = newEoa), AccountCleanupOld.NOT_READY)
        assertTrue(File(fx.native, NativeWalletVault.REC).exists())
    }

    @Test
    fun ea06ReplayWithSameKeyDoesNotRedelete() {
        val fx = Fx(tmp.newFolder("ea06"))
        fx.fill()
        val first = fx.cleanup(activeEoa = newEoa, idem = "k-1")
        val replay = fx.cleanup(activeEoa = newEoa, idem = "k-1")
        assertEquals(AccountCleanupOld.OK, first.code)
        assertEquals(AccountCleanupOld.OK, replay.code)
        assertFalse(replay.cleanupPending)
        assertEquals(emptyList<String>(), replay.deleted)
    }

    @Test
    fun ea07ActiveUnknownIsNotReadyDeletesNothingAndCountsNothing() {
        val fx = Fx(tmp.newFolder("ea07"))
        fx.fill(keyVault = listOf(old1))
        assertRefused(fx.cleanup(activeEoa = null), AccountCleanupOld.NOT_READY)
        assertTrue(File(fx.native, NativeWalletVault.REC).exists())
    }

    @Test
    fun ea08ActiveUnknownDiffersFromActiveEqualsCandidate() {
        val fx = Fx(tmp.newFolder("ea08"))
        fx.fill(page = listOf(old1))
        assertRefused(fx.cleanup(activeEoa = null), AccountCleanupOld.NOT_READY)
        assertTrue(File(fx.pageDir, "page.v1.${hex(old1)}.default.rec").exists())
    }

    /** v4 EA-09: the second old account's re-read mismatches. One removal, then account_mismatch; the rest stays. Trigger counts are recorded. */
    @Test
    fun ea09MismatchMidRunStopsWithoutRollback() {
        val fx = Fx(tmp.newFolder("ea09"))
        fx.fill(keyVault = listOf(old1), page = listOf(old2))
        var reads = 0
        // Reads: 1 the run's snapshot, 2 the re-read before removal one, 3 the re-read before removal two (the pointer has moved to old2).
        val out = fx.cleanup(activeEoa = newEoa, pointer = { reads++; if (reads <= 2) newEoa else old2 })
        assertRefused(out, AccountCleanupOld.ACCOUNT_MISMATCH)
        // Trigger counts (actual): three pointer reads, one removal done, the second account's page kept.
        assertEquals(3, reads)
        assertEquals(1, out.deleted.size)
        assertFalse(File(fx.native, NativeWalletVault.REC).exists())
        assertTrue(File(fx.pageDir, "page.v1.${hex(old2)}.default.rec").exists())
    }

    @Test
    fun ea10NonEnumerableResidueCountedNotSilentlyOk() {
        val fx = Fx(tmp.newFolder("ea10"))
        fx.fill(keyVault = listOf(old1))
        // Real isolated copies of the vault (NativeWalletVault: name.isolated.<stamp>.<hex>): counted unattributed, never removed.
        isolated(fx, "a")
        isolated(fx, "b")
        val out = fx.cleanup(activeEoa = newEoa)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(2, out.retainedUnattributed)
        assertFalse(File(fx.native, NativeWalletVault.REC).exists())
    }

    @Test
    fun ea12ReadBackMismatchReadableIsAccountMismatchAndDeletesNothing() {
        val fx = Fx(tmp.newFolder("ea12"))
        fx.fill(keyVault = listOf(old1))
        // Driven from the active account (not an injected verdict): the derived read-back of newEoa against the active pointer old1 is MISMATCH.
        assertEquals(ReadBackCheck.Verdict.MISMATCH, AccountCleanupWiring.readBackVerdict(newEoa, AccountCleanupWiring.takeSnapshot { old1 }))
        val out = fx.cleanup(activeEoa = old1)
        assertRefused(out, AccountCleanupOld.ACCOUNT_MISMATCH)
        assertTrue(File(fx.native, NativeWalletVault.REC).exists())
    }

    /** v4 EA-13: the active account switches to another during the run (the re-read fails before the second account). Stop; the removed one stays removed. */
    @Test
    fun ea13MidRunActiveSwitchStopsAndDoesNotRollBack() {
        val fx = Fx(tmp.newFolder("ea13"))
        fx.fill(keyVault = listOf(old1), page = listOf(old2))
        var reads = 0
        val out = fx.cleanup(activeEoa = newEoa, pointer = { reads++; if (reads <= 2) newEoa else "0x4444444444444444444444444444444444444444" })
        assertRefused(out, AccountCleanupOld.ACCOUNT_MISMATCH)
        assertEquals(3, reads)
        assertFalse(File(fx.native, NativeWalletVault.REC).exists())
        assertTrue(File(fx.pageDir, "page.v1.${hex(old2)}.default.rec").exists())
    }

    @Test
    fun ea14NonEnumerableResidueCountedOk() {
        val fx = Fx(tmp.newFolder("ea14"))
        fx.fill(keyVault = listOf(old1))
        // Real stores: two isolated vault copies (wallet raw), one backup flag of old1 (exact owner: removed), one backup flag whose name carries no
        // address (unattributable: kept, counted). The passcode H layer is inside the passcode record (exact-owner removed with it); WalletCredential
        // writes no file on Android. The vector's count of 4 needs H and credential items that have no Android store: the actual count is asserted.
        isolated(fx, "a")
        isolated(fx, "b")
        File(fx.pageDir, "${AccountCleanupWiring.BACKUP_FLAG_PREFIX}${hex(old1)}.v1").writeText("flag")
        File(fx.pageDir, "${AccountCleanupWiring.BACKUP_FLAG_PREFIX}zz.v1").writeText("flag")
        val out = fx.cleanup(activeEoa = newEoa)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(3, out.retainedUnattributed)
        assertFalse(File(fx.native, NativeWalletVault.REC).exists())
        assertFalse(File(fx.pageDir, "${AccountCleanupWiring.BACKUP_FLAG_PREFIX}${hex(old1)}.v1").exists())
        assertTrue(File(fx.pageDir, "${AccountCleanupWiring.BACKUP_FLAG_PREFIX}zz.v1").exists())
    }

    /**
     * EA-11 (restored, not removed): Android has no per-account hardware key. The three Keystore alias generation sites are fixed names:
     * beamio_chat_wallet_v1 (BeamioChatWalletKeyStore), beamio.page.record.v1 (ShellRecord), beamio.wallet.wrap.v1 (AndroidNativeWallet).
     * The case drives the passcode-record removal only; the fixed-name keys are not per account and are not enumerated.
     */
    @Test
    fun ea11PerAccountHardwareKeyNotApplicablePasscodeRecordCleared() {
        val fx = Fx(tmp.newFolder("ea11"))
        fx.fill(passcode = listOf(old1))
        // Decoys named exactly as the three fixed Keystore aliases, in the stores the cleanup scans: no adapter may claim them (not deleted, not counted).
        val aliases = listOf("beamio_chat_wallet_v1", "beamio.wallet.wrap.v1", "beamio.page.record.v1")
        aliases.forEach { File(fx.native, it).writeText("decoy"); File(fx.pageDir, it).writeText("decoy") }
        val out = fx.cleanup(activeEoa = newEoa)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(0, out.retainedUnattributed)
        assertFalse(File(fx.passDir, old1).exists())
        aliases.forEach {
            assertTrue("alias-named $it kept in the vault directory", File(fx.native, it).exists())
            assertTrue("alias-named $it kept in the page directory", File(fx.pageDir, it).exists())
        }
    }

    /** A real SQLite database through the production [network.conet.chat.localread.SqlDb] seam (JVM, sqlite-jdbc; test-only). */
    private class JdbcSqlDb(file: File) : network.conet.chat.localread.SqlDb {
        private val c: java.sql.Connection = java.sql.DriverManager.getConnection("jdbc:sqlite:${file.absolutePath}")

        override fun execute(sql: String, args: Array<Any?>) {
            c.prepareStatement(sql).use { ps -> args.forEachIndexed { i, a -> ps.setObject(i + 1, a) }; ps.execute() }
        }

        override fun query(sql: String, args: Array<Any?>): List<Array<Any?>> {
            c.prepareStatement(sql).use { ps ->
                args.forEachIndexed { i, a -> ps.setObject(i + 1, a) }
                ps.executeQuery().use { rs ->
                    val n = rs.metaData.columnCount
                    val out = ArrayList<Array<Any?>>()
                    while (rs.next()) out.add(Array(n) { rs.getObject(it + 1) })
                    return out
                }
            }
        }

        override fun <T> transaction(block: () -> T): T = block()

        override fun close() = c.close()
    }

    /** A real chat history database with the msg table (pending_publish column as in localread/SqlSchema). [pending] rows are unsent. */
    private fun realHistoryDb(file: File, pending: Int) {
        file.delete()
        val db = JdbcSqlDb(file)
        try {
            db.execute("CREATE TABLE msg (conv_blind TEXT, stable_id TEXT, sort_ts INTEGER, revision INTEGER, state INTEGER, pending_publish INTEGER NOT NULL DEFAULT 0, cid_blind TEXT, body_enc BLOB, meta_enc BLOB)")
            repeat(pending) { i -> db.execute("INSERT INTO msg (conv_blind, stable_id, sort_ts, revision, state, pending_publish) VALUES ('cb', 's$i', 1, 1, 0, 1)") }
            db.execute("INSERT INTO msg (conv_blind, stable_id, sort_ts, revision, state, pending_publish) VALUES ('cb', 'sent', 1, 1, 0, 0)")
        } finally {
            db.close()
        }
    }

    /** SNAP-06 (real SQLite, production predicate): old2's history holds pending_publish rows and is kept; old1's history has none and is removed; old1's page copy is removed. */
    @Test
    fun snap06RealSqliteUnsentHistoryKeptCountedOkOthersRemoved() {
        val fx = Fx(tmp.newFolder("snap06real"))
        fx.fill(page = listOf(old1))
        realHistoryDb(File(fx.history, ChatHistoryFileNames.localName(old2)), pending = 2)
        realHistoryDb(File(fx.history, ChatHistoryFileNames.localName(old1)), pending = 0)
        val out = fx.cleanup(activeEoa = newEoa, unsent = { AccountCleanupWiring.historyUnsentRead(it) { f -> JdbcSqlDb(f) } })
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(1, out.retainedUnattributed)
        assertTrue("old2 unsent history kept", File(fx.history, ChatHistoryFileNames.localName(old2)).exists())
        assertFalse("old1 history without unsent rows removed", File(fx.history, ChatHistoryFileNames.localName(old1)).exists())
        assertFalse("old1 page removed", File(fx.pageDir, "page.v1.${hex(old1)}.default.rec").exists())
    }

    /** A non-database file is UNKNOWN: the predicate reports unknown (kept, never guessed from the name). */
    @Test
    fun historyPredicateIsFalseForANonDatabaseFile() {
        val fx = Fx(tmp.newFolder("nondb"))
        val f = File(fx.history, ChatHistoryFileNames.localName(old1)).apply { writeText("not sqlite") }
        // Not a database: unreadable, so UNKNOWN (kept, never treated as "no unsent").
        assertEquals(UnsentRead.UNKNOWN, AccountCleanupWiring.historyUnsentRead(f) { JdbcSqlDb(it) })
    }

    /** The predicate reads the real column: rows with pending_publish = 0 are not unsent. */
    @Test
    fun historyPredicateIsFalseWhenNoPendingPublishRow() {
        val fx = Fx(tmp.newFolder("nopending"))
        val f = File(fx.history, ChatHistoryFileNames.localName(old1))
        realHistoryDb(f, pending = 0)
        assertEquals(UnsentRead.NONE, AccountCleanupWiring.historyUnsentRead(f) { JdbcSqlDb(it) })
    }

    /**
     * Unreadable histories ( 第 2 条; the reviewer's blocker on qa.35): a library that cannot be read is UNKNOWN. It is kept (never removed, never
     * counted), the run answers clear_incomplete with cleanupPending, and the other confirmed old account is still removed.
     */
    private fun assertUnknownHistoryKeptIncomplete(fx: Fx, history: File) {
        // old1 is confirmed and removable (its page copy); old2's history is the unreadable library. old2 is known from its page copy.
        fx.fill(page = listOf(old1, old2))
        // The production read (real files through the JDBC SqlDb seam), no injected verdict.
        val out = fx.cleanup(activeEoa = newEoa, unsent = { file -> AccountCleanupWiring.historyUnsentRead(file) { JdbcSqlDb(it) } })
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
        assertEquals(0, out.retainedUnattributed)
        assertTrue("unreadable history kept", history.exists())
        assertFalse("other account still removed", File(fx.pageDir, "page.v1.${hex(old1)}.default.rec").exists())
    }

    /** A corrupted database file (a real SQLite header, then garbage): UNKNOWN, kept, clear_incomplete, other accounts processed. */
    @Test
    fun corruptHistoryLibraryIsKeptIncompleteAndOthersProceed() {
        val fx = Fx(tmp.newFolder("corrupt"))
        val f = File(fx.history, ChatHistoryFileNames.localName(old2))
        realHistoryDb(f, pending = 0)
        f.writeBytes(f.readBytes().copyOf(200) + ByteArray(4096) { 0x5A })
        assertUnknownHistoryKeptIncomplete(fx, f)
    }

    /** A non-database file under the history name: UNKNOWN, kept, clear_incomplete, other accounts processed. */
    @Test
    fun nonDatabaseHistoryFileIsKeptIncompleteAndOthersProceed() {
        val fx = Fx(tmp.newFolder("nondb-run"))
        val f = File(fx.history, ChatHistoryFileNames.localName(old2)).apply { writeText("not sqlite") }
        assertUnknownHistoryKeptIncomplete(fx, f)
    }

    /** A locked library (another connection holds an exclusive lock): the read fails, UNKNOWN, kept, clear_incomplete, other accounts processed. */
    @Test
    fun lockedHistoryLibraryIsKeptIncompleteAndOthersProceed() {
        val fx = Fx(tmp.newFolder("locked"))
        val f = File(fx.history, ChatHistoryFileNames.localName(old2))
        realHistoryDb(f, pending = 0)
        val locker = java.sql.DriverManager.getConnection("jdbc:sqlite:${f.absolutePath}")
        try {
            locker.createStatement().use { it.execute("BEGIN EXCLUSIVE") }
            assertUnknownHistoryKeptIncomplete(fx, f)
        } finally {
            runCatching { locker.rollback() }
            locker.close()
        }
    }

    @Test
    fun snap01SingleSnapshotNoSecondPointerRead() {
        var reads = 0
        val snap = AccountCleanupWiring.takeSnapshot { reads++; newEoa }
        assertEquals(ReadBackCheck.Verdict.PASS, AccountCleanupWiring.readBackVerdict(newEoa, snap))
        assertEquals(1, reads)
    }

    /** SNAP-03: one item fails (an undeletable entry); the other confirmed account is still removed; the answer is clear_incomplete with pending. */
    @Test
    fun snap03ItemFailureContinuesOtherAccountsAndAnswersClearIncomplete() {
        val fx = Fx(tmp.newFolder("snap03"))
        fx.fill(passcode = listOf(old2))
        // old1's PGP entry is a non-empty directory: its removal fails (the other accounts must still be processed).
        File(fx.native, "pgp.v1.${hex(old1)}").apply { mkdirs(); File(this, "x").writeText("x") }
        val out = fx.cleanup(activeEoa = newEoa)
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
        assertFalse(File(fx.passDir, old2).exists())
        assertTrue(File(fx.native, "pgp.v1.${hex(old1)}").exists())
    }

    /** SNAP-06: an old account with unsent messages keeps its history: counted unattributed, answer ok, no pending, the other account still removed. */
    @Test
    fun snap06UnsentHistoryKeptCountedOk() {
        val fx = Fx(tmp.newFolder("snap06"))
        fx.fill(page = listOf(old1), chat = listOf(old2))
        // The local history of old2 holds pending_publish rows (the seam stands in for the SQL check, which needs a device).
        val out = fx.cleanup(activeEoa = newEoa, unsent = { if (it.name == ChatHistoryFileNames.localName(old2)) UnsentRead.UNSENT else UnsentRead.NONE })
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        // The kept history library of old2 is one counted item; old1's page copy is removed.
        assertEquals(1, out.retainedUnattributed)
        assertFalse(File(fx.pageDir, "page.v1.${hex(old1)}.default.rec").exists())
        assertTrue(File(fx.history, ChatHistoryFileNames.localName(old2)).exists())
    }

    /** SNAP-07: unsent history kept, and another entry fails: clear_incomplete with pending; the kept unsent items stay counted. */
    @Test
    fun snap07UnsentPlusItemFailureAnswersClearIncomplete() {
        val fx = Fx(tmp.newFolder("snap07"))
        fx.fill(chat = listOf(old1), pgp = listOf(old2))
        File(fx.native, "pgp.v1.${hex(old2)}").apply { delete(); mkdirs(); File(this, "x").writeText("x") }
        val out = fx.cleanup(activeEoa = newEoa, unsent = { if (it.name == ChatHistoryFileNames.localName(old1)) UnsentRead.UNSENT else UnsentRead.NONE })
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
        assertEquals(1, out.retainedUnattributed)
        assertTrue(File(fx.history, ChatHistoryFileNames.localName(old1)).exists())
    }

    /** UNV-01: a readable residue that does not verify stays, counted; old1's exact PGP entry is removed. */
    @Test
    fun unv01UnverifiableResidueKeptCountedOtherExactItemsProceed() {
        val fx = Fx(tmp.newFolder("unv01"))
        fx.fill(pgp = listOf(old1))
        unverifiableResidue(fx, old1)
        val out = fx.cleanup(activeEoa = newEoa)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(1, out.retainedUnattributed)
        assertTrue("the residue stays", File(fx.native, NativeWalletVault.MNEM).exists())
        assertFalse("the exact-owner PGP entry of the same account is removed", File(fx.native, "pgp.v1.${hex(old1)}").exists())
    }

    /** UNV-02: with the residue kept, another confirmed old account is still removed (its page copy). */
    @Test
    fun unv02OtherOldAccountStillRemovedWhileTheResidueStays() {
        val fx = Fx(tmp.newFolder("unv02"))
        fx.fill(pgp = listOf(old1), page = listOf(old2))
        unverifiableResidue(fx, old1)
        val out = fx.cleanup(activeEoa = newEoa)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(1, out.retainedUnattributed)
        assertTrue("the residue stays", File(fx.native, NativeWalletVault.MNEM).exists())
        assertFalse("old2's page copy is removed", File(fx.pageDir, "page.v1.${hex(old2)}.default.rec").exists())
    }

    /** UNV-03: an envelope eoa equal to a candidate is not proof of ownership: the residue alone is kept and counted, and nothing else is removed. */
    @Test
    fun unv03EnvelopeEoaEqualToACandidateIsNotProof() {
        val fx = Fx(tmp.newFolder("unv03"))
        unverifiableResidue(fx, old1)
        val out = fx.cleanup(activeEoa = newEoa)
        assertEquals(AccountCleanupOld.OK, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(1, out.retainedUnattributed)
        assertTrue("the residue stays", File(fx.native, NativeWalletVault.MNEM).exists())
    }

    /**
     * UNK-01 (unknown, not unowned): a mnemonic path that cannot be read as a regular file is unknown. The mnemonic record is part of the old-account
     * enumeration, so an unreadable one makes the enumeration source unknown: not_ready, nothing deleted (v220 240.4(5)), and it is never taken
     * for an unowned residue. No cleanupPending: the run did not start.
     */
    @Test
    fun unk01UnreadableMnemonicPathIsUnknownNotReadyNothingDeleted() {
        val fx = Fx(tmp.newFolder("unk01"))
        fx.fill(pgp = listOf(old1))
        File(fx.native, NativeWalletVault.MNEM).mkdirs()
        val out = fx.cleanup(activeEoa = newEoa)
        assertEquals(AccountCleanupOld.NOT_READY, out.code)
        assertFalse(out.cleanupPending)
        assertEquals(0, out.retainedUnattributed)
        assertTrue("the unknown mnemonic path is kept", File(fx.native, NativeWalletVault.MNEM).exists())
        assertTrue("nothing is deleted while the enumeration is unknown", File(fx.native, "pgp.v1.${hex(old1)}").exists())
    }

    /** Makes a file unreadable by the owner (a real read failure: the read raises an IOException); [readable] restores it. */
    private fun setReadable(f: File, readable: Boolean) {
        val perms = if (readable) setOf(java.nio.file.attribute.PosixFilePermission.OWNER_READ, java.nio.file.attribute.PosixFilePermission.OWNER_WRITE)
            else emptySet()
        java.nio.file.Files.setPosixFilePermissions(f.toPath(), perms)
    }

    /**
     * UNK-02 (stage 1, enumeration): a mnemonic record that cannot be read while the old-account set is built is unknown: not_ready, nothing deleted,
     * nothing counted. The mnemonic record is an enumeration source.
     */
    @Test
    fun unk02ReadFailureDuringEnumerationIsNotReadyNothingDeleted() {
        val fx = Fx(tmp.newFolder("unk02"))
        fx.fill(mnemonic = listOf(old2), pgp = listOf(old1))
        val mnem = File(fx.native, NativeWalletVault.MNEM)
        setReadable(mnem, false)
        try {
            val out = fx.cleanup(activeEoa = newEoa)
            assertEquals(AccountCleanupOld.NOT_READY, out.code)
            assertFalse(out.cleanupPending)
            assertEquals(0, out.retainedUnattributed)
            assertTrue("the record is kept", mnem.exists())
            assertTrue("nothing is deleted", File(fx.native, "pgp.v1.${hex(old1)}").exists())
        } finally {
            setReadable(mnem, true)
        }
    }

    /**
     * UNK-03 (stage 2, per-item removal): the mnemonic record is read during the scan (it is verified and owned) but cannot be read at its removal. That
     * item is kept (not counted), the other confirmed account is still removed, and the answer is clear_incomplete with cleanupPending (retryable).
     */
    @Test
    fun unk03ReadFailureDuringRemovalKeepsTheItemClearIncompleteOthersProceed() {
        val fx = Fx(tmp.newFolder("unk03"))
        fx.fill(mnemonic = listOf(old2), pgp = listOf(old1))
        val mnem = File(fx.native, NativeWalletVault.MNEM)
        val out = try {
            fx.cleanup(activeEoa = newEoa, beforeRemoval = { setReadable(mnem, false) })
        } finally {
            setReadable(mnem, true)
        }
        assertEquals(AccountCleanupOld.CLEAR_INCOMPLETE, out.code)
        assertTrue(out.cleanupPending)
        assertEquals("the unknown item is not counted", 0, out.retainedUnattributed)
        assertTrue("the record is kept", mnem.exists())
        assertFalse("the other confirmed account's exact PGP entry is removed", File(fx.native, "pgp.v1.${hex(old1)}").exists())
    }
}
