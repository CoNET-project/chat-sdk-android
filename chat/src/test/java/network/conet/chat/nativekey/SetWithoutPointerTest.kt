package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * A set file on disk with no `current.v1` (a version was written and the pointer move did not finish). It is not an empty store:
 * the store answers unknown (pointer_missing); the page pre-read and walletStatus answer read_error and not_ready, never confirmed_missing and
 * no_key; the create guard blocks; and a repeat of the same sync repairs the pointer. Synthetic data only.
 */
class SetWithoutPointerTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val passcode = "123456"

    private fun dir() = File(tmp.root, MnemonicSetStore.DIRECTORY)
    private fun store() = MnemonicSetStore(dir())
    private fun sealed() = MnemonicCipherV3.seal(eoa, passcode, phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
    private fun setFiles(): List<String> = dir().list()?.filter { it.startsWith("set.") }?.sorted() ?: emptyList()
    private fun body(seq: Int = 1) = JSONObject().put("trustedOrigin", true).put("seq", seq)

    /**
     * The real failure: the set file is moved into place, then the pointer write fails (its temp name is a directory). Returns how the commit ended.
     * The module aborts the staged write after a failed commit (abort removes only the temp file, which is already gone).
     */
    private fun writeThenFailThePointer(stage: () -> MnemonicSetStore.Stage): MnemonicSetStore.Commit {
        val staged = (stage() as MnemonicSetStore.Stage.Ready).staged
        File(dir(), "current.v1.tmp").mkdirs()
        val out = staged.commitOutcome()
        staged.abort()
        File(dir(), "current.v1.tmp").deleteRecursively()
        return out
    }

    private fun v3WithoutPointer() {
        val s = store()
        assertEquals(MnemonicSetStore.Commit.WRITE_FAILED, writeThenFailThePointer { s.stageEnvelope(sealed()) })
        assertEquals(listOf("set.$eoa.v3.1.v1"), setFiles())
        assertFalse(File(dir(), "current.v1").exists())
    }

    // ---- the store ----

    /** Positive: a v3 set with no pointer is unknown with the pointer_missing reason, and the set is still known to the store. */
    @Test
    fun aV3SetWithoutAPointerIsUnknownNotAbsent() {
        v3WithoutPointer()
        val c = store().current()
        assertTrue(c is MnemonicSetStore.Current.Unknown)
        assertEquals(MnemonicSetStore.POINTER_MISSING, (c as MnemonicSetStore.Current.Unknown).reason)
        assertEquals(true, store().hasV3Set(eoa))
    }

    /** Positive: the same for a plain set. */
    @Test
    fun aPlainSetWithoutAPointerIsUnknownNotAbsent() {
        val s = store()
        assertEquals(MnemonicSetStore.Commit.WRITE_FAILED, writeThenFailThePointer { s.stagePlain(eoa, phrase) })
        val c = store().current()
        assertEquals(MnemonicSetStore.POINTER_MISSING, (c as MnemonicSetStore.Current.Unknown).reason)
    }

    /** Negative: the empty cases stay Absent: no directory, an empty directory, a stage temp file alone, the identity_cleared marker alone. */
    @Test
    fun theEmptyCasesStayAbsent() {
        assertTrue(store().current() is MnemonicSetStore.Current.Absent)
        dir().mkdirs()
        assertTrue(store().current() is MnemonicSetStore.Current.Absent)
        File(dir(), "set.$eoa.v3.1.v1.tmp").writeText("half", Charsets.UTF_8)
        assertTrue(store().current() is MnemonicSetStore.Current.Absent)
        assertTrue(store().markIdentityCleared())
        assertTrue(store().current() is MnemonicSetStore.Current.Absent)
    }

    /** Negative: after an identity clear the retained sets are not re-adopted: a set with no pointer under the marker still answers Absent. */
    @Test
    fun anIdentityClearedStoreWithRetainedSetsStaysAbsent() {
        v3WithoutPointer()
        assertTrue(store().markIdentityCleared())
        assertTrue(store().current() is MnemonicSetStore.Current.Absent)
    }

    /** Negative: a valid pointer is untouched by the new rule (Found), and an invalid one is still pointer_invalid. */
    @Test
    fun aValidPointerStillAnswersFoundAndAnInvalidOneStaysInvalid() {
        val s = store()
        assertTrue(s.writeEnvelope(sealed()) is MnemonicSetStore.Write.Stored)
        assertTrue(store().current() is MnemonicSetStore.Current.Found)
        File(dir(), "current.v1").writeText("garbage", Charsets.UTF_8)
        assertEquals("pointer_invalid", (store().current() as MnemonicSetStore.Current.Unknown).reason)
    }

    // ---- path A: nativeMnemonicPreread ----

    /** Path A, with the vault fallback for a vault with no key: read_error, never confirmed_missing. */
    @Test
    fun theUnknownStoreAnswersReadErrorOnThePagePreread() {
        v3WithoutPointer()
        val p = NativeSyncAck.prereadStorePayload(7, body(), vault = { PrereadStoreAnswer.VaultSource.NoKey }) { store().current() }
        assertTrue(p.getBoolean("ok"))
        assertEquals("read_error", p.getJSONObject("result").getString("code"))
        assertFalse(p.toString().contains("confirmed_missing"))
    }

    /** Path A with a key-only vault in the fallback: still read_error (the store decides first and it is unknown). */
    @Test
    fun theUnknownStoreIsReadErrorEvenWithAKeyOnlyVault() {
        v3WithoutPointer()
        val keyOnly = PrereadStoreAnswer.VaultSource.Ready(eoa, { null }, { true })
        val p = NativeSyncAck.prereadStorePayload(7, body(), vault = { keyOnly }) { store().current() }
        assertEquals("read_error", p.getJSONObject("result").getString("code"))
    }

    // ---- path B: walletStatus and the other store-first status answers ----

    /** Path B: the store view is Unknown, so walletStatus is not_ready/unreadable (decided before the vault), never no_key. */
    @Test
    fun walletStatusIsNotReadyUnreadableAndNeverNoKey() {
        v3WithoutPointer()
        val view = StoreAccountView.of(store().current(), null)
        assertTrue(view is StoreAccountView.View.Unknown)
        val answer = StoreAccountView.walletStatus(view, null)
        assertNotNull(answer)
        assertEquals(NoKeyGate.walletStatusUnreadable().toString(), answer.toString())
        assertFalse(answer.toString().contains("no_key"))
        val pc = StoreAccountView.passcodeStatus(view, null)
        assertNotNull(pc)
        assertEquals(true, pc!!.getBoolean("hasKey"))
    }

    /** Control: an empty store leaves the decision to the vault (null), as before. */
    @Test
    fun anEmptyStoreStillLeavesWalletStatusToTheVault() {
        assertNull(StoreAccountView.walletStatus(StoreAccountView.of(store().current(), null), null))
    }

    // ---- the create guard ----

    private fun inputs(store: StoreState = StoreState.EMPTY, pointer: Boolean = false) = CreateGuardInputs(
        key = KeyState.NONE, legacyReport = LegacyReportState.ABSENT, legacyUnreadable = false,
        pointer = pointer, pageCopy = false, migrating = false, store = store,
    )

    /** OV-06 and the denials: an empty store allows; an unknown store (orphan version) and an account in the store deny, each with its own SDK-log code. */
    @Test
    fun theGuardBlocksACreateUnlessTheStoreIsEmpty() {
        assertNull(AccountCreateGuard.denial(inputs()))
        assertEquals(AccountCreateGuard.ORPHAN_VERSION, AccountCreateGuard.denial(inputs(store = StoreState.UNKNOWN)))
        assertEquals(AccountCreateGuard.STORE_ACCOUNT, AccountCreateGuard.denial(inputs(store = StoreState.ACCOUNT)))
        // the earlier reasons keep their order
        assertEquals(AccountCreateGuard.POINTER_SET, AccountCreateGuard.denial(inputs(store = StoreState.UNKNOWN, pointer = true)))
    }

    /** The guard's live input is the store's current(): Absent is EMPTY, Found is ACCOUNT, Unknown (or a read that throws) is UNKNOWN. */
    @Test
    fun theGuardInputComesFromTheStoreAndReadsItFailClosed() {
        val src = File("src/main/java/network/conet/chat/nativekey/AccountCreateGuard.kt").readText(Charsets.UTF_8)
        assertTrue(src.contains("MnemonicSetStore(File(context.applicationContext.noBackupFilesDir, MnemonicSetStore.DIRECTORY)).current()"))
        assertTrue(src.contains("is MnemonicSetStore.Current.Absent -> StoreState.EMPTY"))
        assertTrue(src.contains("is MnemonicSetStore.Current.Found -> StoreState.ACCOUNT"))
        assertTrue(src.contains("is MnemonicSetStore.Current.Unknown -> StoreState.UNKNOWN"))
        assertTrue(src.substringAfter("val store = try").substringAfter("catch (_: Exception) {").trimStart().startsWith("StoreState.UNKNOWN"))
        // the three store states of the real store
        assertTrue(store().current() is MnemonicSetStore.Current.Absent)
        v3WithoutPointer()
        assertTrue(store().current() is MnemonicSetStore.Current.Unknown)
        assertTrue(store().markIdentityCleared())
        assertTrue(store().current() is MnemonicSetStore.Current.Absent)
    }

    // ---- OV-02, OV-03, OV-07, filesChanged ----

    /** OV-02: two orphan versions (same eoa, then another eoa), no pointer: unknown, read_error, and the files are not changed by the reads. */
    @Test
    fun severalOrphanVersionsStayUnknownAndTheReadsChangeNothing() {
        val s = store()
        val other = "0x1111111111111111111111111111111111111111"
        assertEquals(MnemonicSetStore.Commit.WRITE_FAILED, writeThenFailThePointer { s.stageEnvelope(sealed()) })
        // a second version of the same eoa and a version of another eoa, written as the failed commits would leave them
        File(dir(), "set.$eoa.v3.2.v1").writeText(File(dir(), "set.$eoa.v3.1.v1").readText(Charsets.UTF_8), Charsets.UTF_8)
        File(dir(), "set.$other.v3.1.v1").writeText(File(dir(), "set.$eoa.v3.1.v1").readText(Charsets.UTF_8), Charsets.UTF_8)
        val before = snapshot()
        assertEquals(MnemonicSetStore.POINTER_MISSING, (store().current() as MnemonicSetStore.Current.Unknown).reason)
        val p = NativeSyncAck.prereadStorePayload(7, body(), vault = { PrereadStoreAnswer.VaultSource.NoKey }) { store().current() }
        assertEquals("read_error", p.getJSONObject("result").getString("code"))
        assertEquals(before, snapshot())
    }

    /** OV-03: the orphan version file is damaged or empty: still unknown (the listing decides, the content is not needed), read_error. */
    @Test
    fun aDamagedOrphanVersionIsStillUnknown() {
        v3WithoutPointer()
        File(dir(), "set.$eoa.v3.1.v1").writeText("{not json", Charsets.UTF_8)
        assertEquals(MnemonicSetStore.POINTER_MISSING, (store().current() as MnemonicSetStore.Current.Unknown).reason)
        File(dir(), "set.$eoa.v3.1.v1").writeText("", Charsets.UTF_8)
        val p = NativeSyncAck.prereadStorePayload(7, body(), vault = { PrereadStoreAnswer.VaultSource.NoKey }) { store().current() }
        assertEquals("read_error", p.getJSONObject("result").getString("code"))
    }

    /** OV-07: a plaintext set without a pointer is not confirmed_missing on Android: read_error, and no phrase in the reply. */
    @Test
    fun aPlainSetWithoutAPointerIsReadErrorOnThePagePreread() {
        val s = store()
        assertEquals(MnemonicSetStore.Commit.WRITE_FAILED, writeThenFailThePointer { s.stagePlain(eoa, phrase) })
        val p = NativeSyncAck.prereadStorePayload(7, body(), vault = { PrereadStoreAnswer.VaultSource.NoKey }) { store().current() }
        assertEquals("read_error", p.getJSONObject("result").getString("code"))
        assertFalse(p.toString().contains("confirmed_missing"))
        assertFalse(p.toString().contains("fog spot"))
    }

    /** OV-06 (regression): an empty store with no key is still confirmed_missing on the page preread. */
    @Test
    fun anEmptyStoreIsStillConfirmedMissing() {
        val p = NativeSyncAck.prereadStorePayload(7, body(), vault = { PrereadStoreAnswer.VaultSource.NoKey }) { store().current() }
        assertEquals("confirmed_missing", p.getJSONObject("result").getString("code"))
    }

    private fun snapshot(): Map<String, String> =
        dir().listFiles()!!.associate { it.name to if (it.isFile) it.readText(Charsets.UTF_8) else "<dir>" }

    // ---- the repair: a repeat of the same sync moves the pointer ----

    /** Self-heal 1: the same envelope again, no passcode: idempotent content, only the pointer moves, no new version. */
    @Test
    fun theSameEnvelopeAgainRepairsThePointerWithoutANewVersion() {
        val s = store()
        val env = sealed()
        assertEquals(MnemonicSetStore.Commit.WRITE_FAILED, writeThenFailThePointer { s.stageEnvelope(env) })
        val out = PwaSyncCipher.run(env, null) { e, v -> s.stageEnvelope(e, v) }
        assertTrue(out is PwaSyncCipher.Outcome.Ok)
        val c = store().current() as MnemonicSetStore.Current.Found
        assertEquals(MnemonicSetStore.Kind.V3, c.kind)
        assertEquals(1, c.version)
        assertEquals(listOf("set.$eoa.v3.1.v1"), setFiles())
    }

    /** Self-heal 2: a re-sealed envelope with the correct passcode is a new version and moves the pointer; the old version stays. */
    @Test
    fun aVerifiedReSealRepairsThePointerAsANewVersion() {
        v3WithoutPointer()
        val s = store()
        assertTrue(PwaSyncCipher.run(sealed(), passcode) { e, v -> s.stageEnvelope(e, v) } is PwaSyncCipher.Outcome.Ok)
        assertEquals(2, (store().current() as MnemonicSetStore.Current.Found).version)
        assertEquals(listOf("set.$eoa.v3.1.v1", "set.$eoa.v3.2.v1"), setFiles())
    }

    /** Negative: a re-sealed envelope without a passcode cannot be verified: refused, nothing written, the store stays unknown (no silent adoption). */
    @Test
    fun anUnverifiedDifferentEnvelopeDoesNotRepairAndWritesNothing() {
        v3WithoutPointer()
        val s = store()
        val out = PwaSyncCipher.run(sealed(), null) { e, v -> s.stageEnvelope(e, v) }
        assertTrue(out is PwaSyncCipher.Outcome.Fail && out.code == NativeSyncAck.BAD_REQUEST)
        assertEquals(listOf("set.$eoa.v3.1.v1"), setFiles())
        assertEquals(MnemonicSetStore.POINTER_MISSING, (store().current() as MnemonicSetStore.Current.Unknown).reason)
    }

    /** Self-heal 3: the same plain phrase again moves the pointer to the saved plain set. */
    @Test
    fun theSamePlainPhraseAgainRepairsThePointer() {
        val s = store()
        assertEquals(MnemonicSetStore.Commit.WRITE_FAILED, writeThenFailThePointer { s.stagePlain(eoa, phrase) })
        val st = (s.stagePlain(eoa, phrase) as MnemonicSetStore.Stage.Ready).staged
        assertFalse(st.isNew)
        assertTrue(st.commit())
        val c = store().current() as MnemonicSetStore.Current.Found
        assertEquals(MnemonicSetStore.Kind.PLAIN, c.kind)
        assertEquals(phrase, c.value)
    }

    /** OV-04: the same envelope is retried: sync ok, then the page preread is ok with the cipher, and the guard denies (an account exists). */
    @Test
    fun afterTheRepairThePrereadIsOkWithTheCipherAndTheGuardStillDenies() {
        val s = store()
        val env = sealed()
        assertEquals(MnemonicSetStore.Commit.WRITE_FAILED, writeThenFailThePointer { s.stageEnvelope(env) })
        assertTrue(PwaSyncCipher.run(env, null) { e, v -> s.stageEnvelope(e, v) } is PwaSyncCipher.Outcome.Ok)
        val p = NativeSyncAck.prereadStorePayload(9, body(9), vault = { PrereadStoreAnswer.VaultSource.NoKey }) { store().current() }
        val r = p.getJSONObject("result")
        assertEquals("ok", r.getString("code"))
        assertTrue(r.has("cipher"))
        assertFalse(p.toString().contains("fog spot"))
        assertEquals(AccountCreateGuard.STORE_ACCOUNT, AccountCreateGuard.denial(inputs(store = StoreState.ACCOUNT)))
    }

    /** OV-05 (regression): a normal v3 account with its pointer answers ok with the cipher. */
    @Test
    fun aNormalV3AccountStillAnswersOkWithTheCipher() {
        assertTrue(store().writeEnvelope(sealed()) is MnemonicSetStore.Write.Stored)
        val p = NativeSyncAck.prereadStorePayload(9, body(9), vault = { PrereadStoreAnswer.VaultSource.NoKey }) { store().current() }
        assertEquals("ok", p.getJSONObject("result").getString("code"))
        assertTrue(p.getJSONObject("result").has("cipher"))
    }

    /**
     * Path B (walletStatus): in the G0 branch the store-first answer is decided before the vault and before the pre-read's no_key judgment, so an
     * unknown store never reaches the no_key answer. The startup pre-read (MnemonicPreread) has no store input; its only other consumer, the
     * legacy PGP precheck, settles to the same outcome either way.
     */
    @Test
    fun walletStatusAsksTheStoreBeforeTheVaultAndTheNoKeyJudgment() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        val branch = module.substringAfter("NoKeyGate.Route.WALLET_STATUS -> {")
        val store = branch.indexOf("StoreAccountView.walletStatus(")
        val noKey = branch.indexOf("noWalletConfirmedBy(")
        assertTrue(store in 0 until noKey)
    }

    /** The bridge lets exactly this unknown through to the sync (plain and cipher), so the repair is not blocked; other unknowns still refuse. */
    @Test
    fun theSyncHandlersLetOnlyThePointerMissingUnknownThrough() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        assertEquals(2, Regex("""reason != MnemonicSetStore\.POINTER_MISSING""").findAll(module).count())
    }

    // ---- identity_cleared: the marker is store-wide, so it must not hide a version written after the clear ----

    private val other = "0x1111111111111111111111111111111111111111"
    private fun otherSealed() = MnemonicCipherV3.seal(other, passcode, phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())

    /** Moves the mtime of every file of [names] (and only them) to [at], so "written before the clear" and "after" do not depend on the clock. */
    private fun touch(at: Long, vararg names: String) = names.forEach { assertTrue(File(dir(), it).setLastModified(at)) }

    /** The cleared identity's own state: its set (with or without a pointer) was written before the clear and the marker was written after. */
    private fun clearedIdentity(withPointer: Boolean): Long {
        val s = store()
        if (withPointer) assertTrue(s.writeEnvelope(sealed()) is MnemonicSetStore.Write.Stored)
        else assertEquals(MnemonicSetStore.Commit.WRITE_FAILED, writeThenFailThePointer { s.stageEnvelope(sealed()) })
        val clearAt = 2_000_000_000_000L
        assertTrue(s.markIdentityCleared())
        File(dir(), "set.$eoa.v3.1.v1").setLastModified(clearAt - 5_000)
        File(dir(), "current.v1").takeIf { it.exists() }?.setLastModified(clearAt - 5_000)
        assertTrue(File(dir(), MnemonicSetStore.IDENTITY_CLEARED).setLastModified(clearAt))
        return clearAt
    }

    /** OV-08a: an orphan version of the identity that was cleared is ignored with it: Absent, confirmed_missing, the guard allows, nothing is written. */
    @Test
    fun anOrphanVersionOfTheClearedIdentityIsIgnoredWithIt() {
        clearedIdentity(withPointer = false)
        val before = snapshot()
        assertTrue(store().current() is MnemonicSetStore.Current.Absent)
        val p = NativeSyncAck.prereadStorePayload(7, body(), vault = { PrereadStoreAnswer.VaultSource.NoKey }) { store().current() }
        assertEquals("confirmed_missing", p.getJSONObject("result").getString("code"))
        assertNull(AccountCreateGuard.denial(inputs(store = StoreState.EMPTY)))
        assertEquals(before, snapshot())
    }

    /**
     * OV-08b: another identity's version written AFTER the clear whose pointer never moved (the marker is still there, because it is removed only
     * after a commit): unknown, read_error, the guard denies. The cleared identity's own retained set does not hide it.
     */
    @Test
    fun anotherIdentitysOrphanVersionIsNotHiddenByTheClearMarker() {
        val clearAt = clearedIdentity(withPointer = true)
        val s = store()
        // the real route: a sync of the other identity writes its set and the pointer write fails; the marker stays
        assertEquals(MnemonicSetStore.Commit.WRITE_FAILED, writeThenFailThePointer { s.stageEnvelope(otherSealed()) })
        touch(clearAt + 5_000, "set.$other.v3.1.v1")
        assertTrue(File(dir(), MnemonicSetStore.IDENTITY_CLEARED).exists())
        val c = store().current()
        assertEquals(MnemonicSetStore.POINTER_MISSING, (c as MnemonicSetStore.Current.Unknown).reason)
        val p = NativeSyncAck.prereadStorePayload(7, body(), vault = { PrereadStoreAnswer.VaultSource.NoKey }) { store().current() }
        assertEquals("read_error", p.getJSONObject("result").getString("code"))
        assertEquals(AccountCreateGuard.ORPHAN_VERSION, AccountCreateGuard.denial(inputs(store = StoreState.UNKNOWN)))
    }

    /** The repair of OV-08b: the other identity's sync is repeated, the pointer moves, the marker goes, the store names that identity. */
    @Test
    fun repeatingTheOtherIdentitysSyncRepairsItAndReleasesTheMarker() {
        val clearAt = clearedIdentity(withPointer = true)
        val s = store()
        val env = otherSealed()
        assertEquals(MnemonicSetStore.Commit.WRITE_FAILED, writeThenFailThePointer { s.stageEnvelope(env) })
        touch(clearAt + 5_000, "set.$other.v3.1.v1")
        assertTrue(PwaSyncCipher.run(env, null) { e, v -> s.stageEnvelope(e, v) } is PwaSyncCipher.Outcome.Ok)
        assertFalse(File(dir(), MnemonicSetStore.IDENTITY_CLEARED).exists())
        val c = store().current() as MnemonicSetStore.Current.Found
        assertEquals(other, c.eoa)
    }

    /** OV-08c: the store directory cannot be listed (with or without the marker): unknown, read_error, data kept. */
    @Test
    fun anUnlistableStoreIsUnknownWithAndWithoutTheMarker() {
        for (withMarker in listOf(false, true)) {
            dir().deleteRecursively()
            v3WithoutPointer()
            if (withMarker) assertTrue(store().markIdentityCleared())
            val before = snapshot()
            assertTrue(dir().setReadable(false))
            try {
                val c = store().current()
                assertTrue("marker=$withMarker: $c", c is MnemonicSetStore.Current.Unknown)
                val p = NativeSyncAck.prereadStorePayload(7, body(), vault = { PrereadStoreAnswer.VaultSource.NoKey }) { store().current() }
                assertEquals("read_error", p.getJSONObject("result").getString("code"))
            } finally {
                dir().setReadable(true)
            }
            assertEquals(before, snapshot())
        }
    }

    /** OV-08c: a pointer that cannot be read as a pointer is unknown (no marker): the existing rule, kept. */
    @Test
    fun anInvalidPointerWithoutTheMarkerIsStillUnknown() {
        assertTrue(store().writeEnvelope(sealed()) is MnemonicSetStore.Write.Stored)
        File(dir(), "current.v1").writeText("0xnot-a-pointer", Charsets.UTF_8)
        assertTrue(store().current() is MnemonicSetStore.Current.Unknown)
    }

    /** OV-08d: a v3 set named by the pointer plus the marker: the guard input is EMPTY (the cleared identity does not block a create). */
    @Test
    fun aClearedIdentityWithItsPointerDoesNotBlockACreate() {
        clearedIdentity(withPointer = true)
        assertTrue(store().current() is MnemonicSetStore.Current.Absent)
        assertNull(AccountCreateGuard.denial(inputs(store = StoreState.EMPTY)))
    }
}
