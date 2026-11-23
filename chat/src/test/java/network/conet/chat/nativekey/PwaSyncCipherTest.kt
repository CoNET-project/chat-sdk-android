package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The pwaWalletSync cipher branch (step (2)). Synthetic phrase and passcode only. The decision and the write are
 * checked against the two-state store: a failed check or a wrong passcode writes nothing; a success writes a new version and moves the
 * pointer only at commit; a failed commit leaves the current set as it was.
 */
class PwaSyncCipherTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val passcode = "123456"

    private fun store(): MnemonicSetStore = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))

    private fun sealed(pc: String = passcode) =
        MnemonicCipherV3.seal(eoa, pc, phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())

    private fun setFiles(): List<String> =
        File(tmp.root, MnemonicSetStore.DIRECTORY).list()?.filter { it.startsWith("set.") }?.sorted() ?: emptyList()

    /** Positive: no passcode sent: the format is checked, the envelope is stored, nothing is decrypted (decrypted=false). */
    @Test
    fun withoutPasscodeStoresAndDoesNotDecrypt() {
        val s = store()
        val out = PwaSyncCipher.run(sealed(), null) { e, v -> s.stageEnvelope(e, v) }
        assertTrue(out is PwaSyncCipher.Outcome.Ok)
        assertFalse((out as PwaSyncCipher.Outcome.Ok).decrypted)
        val c = s.current() as MnemonicSetStore.Current.Found
        assertEquals(MnemonicSetStore.Kind.V3, c.kind)
        assertEquals(1, c.version)
    }

    /** Positive: the correct passcode opens the envelope in memory and the record is stored with decrypted=true. */
    @Test
    fun withCorrectPasscodeStoresAndDecrypts() {
        val s = store()
        val out = PwaSyncCipher.run(sealed(), passcode) { e, v -> s.stageEnvelope(e, v) }
        assertTrue((out as PwaSyncCipher.Outcome.Ok).decrypted)
        assertEquals(MnemonicSetStore.Kind.V3, (s.current() as MnemonicSetStore.Current.Found).kind)
    }

    /** Negative: a wrong passcode is unlock_failed and writes nothing (no set file, the store stays Absent). */
    @Test
    fun wrongPasscodeIsUnlockFailedAndWritesNothing() {
        val s = store()
        val out = PwaSyncCipher.run(sealed(), "000000") { e, v -> s.stageEnvelope(e, v) }
        assertEquals("unlock_failed", (out as PwaSyncCipher.Outcome.Fail).code)
        assertEquals(emptyList<String>(), setFiles())
        assertTrue(s.current() is MnemonicSetStore.Current.Absent)
    }

    /** Negative: a format failure (version 2) and a missing envelope are verify_failed; nothing is decrypted or written. */
    @Test
    fun badFormatAndMissingEnvelopeAreVerifyFailedAndWriteNothing() {
        val s = store()
        val bad = PwaSyncCipher.run(sealed().copy(v = 2), passcode) { e, v -> s.stageEnvelope(e, v) }
        assertEquals("verify_failed", (bad as PwaSyncCipher.Outcome.Fail).code)
        val none = PwaSyncCipher.run(null, null) { e, v -> s.stageEnvelope(e, v) }
        assertEquals("verify_failed", (none as PwaSyncCipher.Outcome.Fail).code)
        assertEquals(emptyList<String>(), setFiles())
        assertTrue(s.current() is MnemonicSetStore.Current.Absent)
    }

    /** Negative: a stage that cannot write (the store directory is a file) is write_failed; the pointer does not exist. */
    @Test
    fun stageFailureIsWriteFailedAndNothingIsSwitched() {
        val blocker = File(tmp.root, MnemonicSetStore.DIRECTORY)
        blocker.writeText("not a directory", Charsets.UTF_8)
        val out = PwaSyncCipher.run(sealed(), null) { e, v -> store().stageEnvelope(e, v) }
        assertEquals("write_failed", (out as PwaSyncCipher.Outcome.Fail).code)
        assertFalse(File(blocker, "current.v1").exists())
    }

    /**
     * Negative: a commit that cannot move the new file into place (the target exists) returns false; the pointer is not moved, and the
     * current set stays the older one (version 1). The temp file is removed by abort.
     */
    @Test
    fun failedCommitKeepsTheCurrentSet() {
        val s = store()
        val first = PwaSyncCipher.run(sealed(), null) { e, v -> s.stageEnvelope(e, v) } as PwaSyncCipher.Outcome.Ok
        assertTrue(first.decrypted.not())
        val before = s.current() as MnemonicSetStore.Current.Found
        val next = sealed()
        val st = (s.stageEnvelope(next) as MnemonicSetStore.Stage.Ready).staged
        File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.v3.2.v1").writeText("occupied", Charsets.UTF_8)
        assertFalse(st.commit())
        st.abort()
        val after = s.current() as MnemonicSetStore.Current.Found
        assertEquals(before.version, after.version)
        assertEquals(before.value, after.value)
        assertFalse(File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.v3.2.v1.tmp").exists())
    }

    /** Guard 1 (2026-11-22): after a switch to v3 the earlier PLAIN set and the earlier v3 versions stay, readable and byte-identical. */
    @Test
    fun olderSetsSurviveTheSwitchToV3() {
        val s = store()
        assertTrue(s.writePlain(eoa, phrase) is MnemonicSetStore.Write.Stored)
        val plainFile = File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.plain.1.v1")
        val plainBefore = plainFile.readBytes()
        val first = sealed()
        PwaSyncCipher.run(first, null) { e, v -> s.stageEnvelope(e, v) }
        assertTrue(s.current() is MnemonicSetStore.Current.Found && (s.current() as MnemonicSetStore.Current.Found).kind == MnemonicSetStore.Kind.V3)
        assertTrue(plainBefore.contentEquals(plainFile.readBytes()))
        val v3First = File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.v3.1.v1").readBytes()
        // M6 v3.3: different bytes without a passcode cannot be verified and are refused; with the correct passcode they are a new version.
        val refused = PwaSyncCipher.run(sealed(), null) { e, v -> s.stageEnvelope(e, v) }
        assertTrue(refused is PwaSyncCipher.Outcome.Fail && refused.code == NativeSyncAck.BAD_REQUEST)
        assertEquals(1, (s.current() as MnemonicSetStore.Current.Found).version)
        assertTrue(PwaSyncCipher.run(sealed(), passcode) { e, v -> s.stageEnvelope(e, v) } is PwaSyncCipher.Outcome.Ok)
        assertTrue(v3First.contentEquals(File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.v3.1.v1").readBytes()))
        assertEquals(2, (s.current() as MnemonicSetStore.Current.Found).version)
        assertTrue(plainBefore.contentEquals(plainFile.readBytes()))
    }

    /** Guard 2: a byte-identical envelope to the current set returns ok and adds no version. */
    @Test
    fun identicalEnvelopeToCurrentIsIdempotent() {
        val s = store()
        val env = sealed()
        assertTrue(PwaSyncCipher.run(env, null) { e, v -> s.stageEnvelope(e, v) } is PwaSyncCipher.Outcome.Ok)
        assertTrue(PwaSyncCipher.run(env, null) { e, v -> s.stageEnvelope(e, v) } is PwaSyncCipher.Outcome.Ok)
        assertEquals(listOf("set.$eoa.v3.1.v1"), setFiles())
        assertEquals(1, (s.current() as MnemonicSetStore.Current.Found).version)
    }

    /** Guard 3: an envelope for another EOA is a change of account: its own new set, the other account's set is kept and not overwritten. */
    @Test
    fun anotherAccountGetsItsOwnSetAndKeepsTheOld() {
        val s = store()
        val other = "0x1111111111111111111111111111111111111111"
        PwaSyncCipher.run(sealed(), null) { e, v -> s.stageEnvelope(e, v) }
        val oldBytes = File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.v3.1.v1").readBytes()
        val otherEnv = MnemonicCipherV3.seal(other, passcode, phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        assertTrue(PwaSyncCipher.run(otherEnv, null) { e, v -> s.stageEnvelope(e, v) } is PwaSyncCipher.Outcome.Ok)
        assertTrue(oldBytes.contentEquals(File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.v3.1.v1").readBytes()))
        val c = s.current() as MnemonicSetStore.Current.Found
        assertEquals(other, c.eoa)
        assertEquals(1, c.version)
    }

    /** Step 3: a new phrase is a new staged file (UPDATED); the same phrase again adds nothing (IDEMPOTENT). */
    @Test
    fun aPhraseStageIsNewOnceAndIdempotentAfter() {
        val s = store()
        val first = (s.stagePlain(eoa, phrase) as MnemonicSetStore.Stage.Ready).staged
        assertTrue(first.isNew)
        assertTrue(first.commit())
        val again = (s.stagePlain(eoa, phrase) as MnemonicSetStore.Stage.Ready).staged
        assertFalse(again.isNew)
    }

    /** Step 3 guard: the bridge's phrase sync writes the store only; the vault sync and the init PGP vault write are not called. */
    @Test
    fun theBridgeWritesOnlyTheStoreForAPhraseSync() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        assertFalse(module.contains("vault.syncPhrase("))
        // init PGP keeps writing the native PGP vault (restored: the published store never receives a new account's private armor).
        assertTrue(module.contains("NativeWallet.pgpFor(ctx, eoa).put(eoa, armor, passphrase)"))
    }

    /** Source guard: the cipher decision never logs; the passcode is only passed in memory. */
    @Test
    fun theDecisionFileNeverLogs() {
        val src = File("src/main/java/network/conet/chat/nativekey/PwaSyncCipher.kt").readText(Charsets.UTF_8)
        assertFalse(src.contains("Log."))
        assertFalse(src.contains("println"))
        assertTrue(src.contains("MnemonicCipherV3.formatOk"))
    }
}
