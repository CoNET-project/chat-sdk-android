package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The two-state mnemonic store (storage layer). Synthetic phrases and accounts. Positive and negative examples: a validated phrase is stored and
 * becomes current; a phrase that does not derive its EOA is refused; a different plain phrase for the same EOA is refused and nothing changes;
 * a second account switches current and the first set stays readable; a v3 envelope is kept as the original ciphertext; a passcode change
 * writes a new version beside the old one (the old bytes do not change, the pointer moves after the read back); an identical v3 rewrite is
 * idempotent; a missing set or a bad pointer is Unknown, never Absent; no temp file is left behind.
 */
class MnemonicSetStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val phraseA = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val eoaA = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val phraseB = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val eoaB: String = checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(phraseB)))).lowercase()

    private fun dir(): File = File(tmp.root, MnemonicSetStore.DIRECTORY)
    private fun store(): MnemonicSetStore = MnemonicSetStore(dir())

    /** Positive: a validated phrase is stored and is the current set; the value read back is the phrase. */
    @Test
    fun aValidatedPhraseIsStoredAndBecomesCurrent() {
        val s = store()
        assertTrue(s.writePlain(eoaA, phraseA) is MnemonicSetStore.Write.Stored)
        val c = s.current() as MnemonicSetStore.Current.Found
        assertEquals(eoaA, c.eoa)
        assertEquals(MnemonicSetStore.Kind.PLAIN, c.kind)
        assertEquals(phraseA, c.value)
    }

    /** Negative: a phrase that does not derive the given EOA is refused and nothing is written (current stays Absent). */
    @Test
    fun aPhraseThatDoesNotDeriveItsEoaIsRefusedAndNothingIsWritten() {
        val s = store()
        assertTrue(s.writePlain(eoaB, phraseA) is MnemonicSetStore.Write.Refused)
        assertTrue(s.current() is MnemonicSetStore.Current.Absent)
        assertFalse(dir().exists())
    }

    /** Negative: a different plain phrase for an EOA that already has one is refused, and the existing bytes do not change. */
    @Test
    fun aDifferentPlainPhraseForTheSameEoaIsRefused() {
        val s = store()
        s.writePlain(eoaB, phraseB)
        val file = File(dir(), "set.$eoaB.plain.1.v1")
        val before = file.readBytes()
        assertTrue(s.writePlain(eoaB, phraseB + "") is MnemonicSetStore.Write.Stored)
        assertTrue(before.contentEquals(file.readBytes()))
    }

    /** Positive: a second account becomes current; the first account's set stays and is still readable (old sets are kept). */
    @Test
    fun aSecondAccountSwitchesCurrentAndKeepsTheFirstSet() {
        val s = store()
        s.writePlain(eoaA, phraseA)
        assertTrue(s.writePlain(eoaB, phraseB) is MnemonicSetStore.Write.Stored)
        val c = s.current() as MnemonicSetStore.Current.Found
        assertEquals(eoaB, c.eoa)
        assertEquals(phraseB, c.value)
        val old = File(dir(), "set.$eoaA.plain.1.v1")
        assertTrue(old.exists())
        assertEquals(phraseA, old.readText(Charsets.UTF_8))
    }

    /** Positive: a passcode-protected v3 envelope is kept as the original ciphertext and is current, with its fields unchanged. */
    @Test
    fun aV3EnvelopeIsKeptAsTheOriginalCiphertext() {
        val s = store()
        val env = MnemonicCipherV3.seal(eoaA, "482913", phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        assertTrue(s.writeEnvelope(env) is MnemonicSetStore.Write.Stored)
        val c = s.current() as MnemonicSetStore.Current.Found
        assertEquals(MnemonicSetStore.Kind.V3, c.kind)
        assertEquals(1, c.version)
        val j = JSONObject(c.value)
        assertEquals(3, j.getInt("v"))
        assertEquals(env.ctB64, j.getString("ct"))
        assertEquals(env.saltB64, j.getString("salt"))
        assertEquals(env.ivB64, j.getString("iv"))
        assertFalse("no plaintext phrase in a v3 record", c.value.contains("fog spot"))
    }

    /** Positive (2026-11-22): a passcode change writes version 2 beside version 1; version 1 keeps its bytes and the pointer moves to 2. */
    @Test
    fun aPasscodeChangeWritesANewVersionAndKeepsTheOldOne() {
        val s = store()
        val first = MnemonicCipherV3.seal(eoaA, "482913", phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        s.writeEnvelope(first)
        val v1 = File(dir(), "set.$eoaA.v3.1.v1")
        val before = v1.readBytes()
        val changed = MnemonicCipherV3.seal(eoaA, "123456", phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        val r = s.writeEnvelope(changed)
        assertTrue(r is MnemonicSetStore.Write.Stored)
        assertEquals(2, (r as MnemonicSetStore.Write.Stored).version)
        assertTrue("version 1 keeps its bytes", before.contentEquals(v1.readBytes()))
        val c = s.current() as MnemonicSetStore.Current.Found
        assertEquals(2, c.version)
        assertEquals(changed.ctB64, JSONObject(c.value).getString("ct"))
        assertTrue(File(dir(), "set.$eoaA.v3.2.v1").exists())
    }

    /** Positive: the same envelope written again is idempotent: no new version, the same bytes. */
    @Test
    fun anIdenticalV3RewriteIsIdempotent() {
        val s = store()
        val env = MnemonicCipherV3.seal(eoaA, "482913", phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        s.writeEnvelope(env)
        val v1 = File(dir(), "set.$eoaA.v3.1.v1")
        val before = v1.readBytes()
        val r = s.writeEnvelope(env)
        assertEquals(1, (r as MnemonicSetStore.Write.Stored).version)
        assertTrue(before.contentEquals(v1.readBytes()))
        assertFalse(File(dir(), "set.$eoaA.v3.2.v1").exists())
    }

    /** Positive: the same plain phrase written again is idempotent (stored, bytes unchanged). */
    @Test
    fun anIdenticalPlainRewriteIsIdempotent() {
        val s = store()
        assertTrue(s.writePlain(eoaA, phraseA) is MnemonicSetStore.Write.Stored)
        val file = File(dir(), "set.$eoaA.plain.1.v1")
        val before = file.readBytes()
        assertTrue(s.writePlain(eoaA, phraseA) is MnemonicSetStore.Write.Stored)
        assertTrue(before.contentEquals(file.readBytes()))
    }

    /** Negative: a current pointer whose set file is missing is Unknown (set_missing), never Absent: nothing is confirmed missing. */
    @Test
    fun aMissingSetFileIsUnknownNotAbsent() {
        val s = store()
        s.writePlain(eoaA, phraseA)
        File(dir(), "set.$eoaA.plain.1.v1").delete()
        assertEquals("set_missing", (s.current() as MnemonicSetStore.Current.Unknown).reason)
    }

    /** Negative: a corrupt pointer is Unknown (pointer_invalid). */
    @Test
    fun aCorruptPointerIsUnknown() {
        val s = store()
        s.writePlain(eoaA, phraseA)
        File(dir(), "current.v1").writeText("not a pointer", Charsets.UTF_8)
        assertEquals("pointer_invalid", (s.current() as MnemonicSetStore.Current.Unknown).reason)
    }

    /** Positive: a write leaves no temp file behind (write, read back, rename). */
    @Test
    fun aWriteLeavesNoTempFile() {
        val s = store()
        s.writePlain(eoaA, phraseA)
        assertFalse(dir().list()!!.any { it.endsWith(".tmp") })
    }

    /**
     * Plain then v3 for one EOA keeps the older plain set; a plaintext set is then never written again for that EOA (M6 v3.2: passcode protection changes
     * only through the passcode commands), so the pointer stays on the v3 set and a later envelope adds a version.
     */
    @Test
    fun aPlainSetCanBeFollowedByV3ButNeverTheOtherWayRound() {
        val s = store()
        assertTrue(s.writePlain(eoaA, phraseA) is MnemonicSetStore.Write.Stored)
        val plainV1 = File(dir(), "set.$eoaA.plain.1.v1").readBytes()
        val env1 = MnemonicCipherV3.seal(eoaA, "482913", phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        assertTrue(s.writeEnvelope(env1) is MnemonicSetStore.Write.Stored)
        assertEquals(MnemonicSetStore.Kind.V3, (s.current() as MnemonicSetStore.Current.Found).kind)
        assertEquals("a plaintext write for an account with a v3 set is refused", MnemonicSetStore.Write.Refused, s.writePlain(eoaA, phraseA))
        assertEquals("the pointer stays on the v3 set", MnemonicSetStore.Kind.V3, (s.current() as MnemonicSetStore.Current.Found).kind)
        assertTrue("the plain set keeps its bytes", plainV1.contentEquals(File(dir(), "set.$eoaA.plain.1.v1").readBytes()))
        val env2 = MnemonicCipherV3.seal(eoaA, "123456", phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        assertTrue(s.writeEnvelope(env2) is MnemonicSetStore.Write.Stored)
        assertEquals(MnemonicSetStore.Kind.V3, (s.current() as MnemonicSetStore.Current.Found).kind)
        assertTrue(File(dir(), "set.$eoaA.v3.1.v1").exists())
        assertTrue(File(dir(), "set.$eoaA.v3.2.v1").exists())
        assertFalse(dir().list()!!.any { it.endsWith(".tmp") })
    }

    /** Negative: a plaintext write for an account with a v3 set is refused (M6 v3.2); the v3 set keeps its bytes and stays current. */
    @Test
    fun aV3SetIsKeptWhenAPlaintextWriteArrivesForTheSameAccount() {
        val s = store()
        val env = MnemonicCipherV3.seal(eoaA, "482913", phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        s.writeEnvelope(env)
        val v3 = File(dir(), "set.$eoaA.v3.1.v1").readBytes()
        assertEquals(MnemonicSetStore.Write.Refused, s.writePlain(eoaA, phraseA))
        assertTrue("the v3 version keeps its bytes", v3.contentEquals(File(dir(), "set.$eoaA.v3.1.v1").readBytes()))
        assertEquals(MnemonicSetStore.Kind.V3, (s.current() as MnemonicSetStore.Current.Found).kind)
    }

    /** Positive (account switch): a second EOA's sync creates its own set and moves current; the first account's set is kept. */
    @Test
    fun anotherAccountCreatesItsOwnSetAndKeepsTheFirst() {
        val s = store()
        s.writePlain(eoaA, phraseA)
        val a = File(dir(), "set.$eoaA.plain.1.v1").readBytes()
        assertTrue(s.writePlain(eoaB, phraseB) is MnemonicSetStore.Write.Stored)
        assertEquals(eoaB, (s.current() as MnemonicSetStore.Current.Found).eoa)
        assertTrue(a.contentEquals(File(dir(), "set.$eoaA.plain.1.v1").readBytes()))
        assertEquals(phraseA, File(dir(), "set.$eoaA.plain.1.v1").readText(Charsets.UTF_8))
    }

    /** Negative (staged write): an aborted stage leaves the pointer and the older sets unchanged, and no temp file remains. */
    @Test
    fun anAbortedStageChangesNothing() {
        val s = store()
        s.writePlain(eoaA, phraseA)
        val pointerBefore = File(dir(), "current.v1").readBytes()
        val stage = (s.stageEnvelope(MnemonicCipherV3.seal(eoaA, "482913", phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())) as MnemonicSetStore.Stage.Ready).staged
        stage.abort()
        assertTrue(pointerBefore.contentEquals(File(dir(), "current.v1").readBytes()))
        assertFalse(dir().list()!!.any { it.endsWith(".tmp") })
        assertEquals(MnemonicSetStore.Kind.PLAIN, (s.current() as MnemonicSetStore.Current.Found).kind)
    }

    /** Positive (staged write): a committed stage moves the pointer after the readback; before commit the current set is still the old one. */
    @Test
    fun aCommittedStageMovesThePointerOnlyAtCommit() {
        val s = store()
        s.writePlain(eoaA, phraseA)
        val stage = (s.stageEnvelope(MnemonicCipherV3.seal(eoaA, "482913", phraseA, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())) as MnemonicSetStore.Stage.Ready).staged
        assertEquals(MnemonicSetStore.Kind.PLAIN, (s.current() as MnemonicSetStore.Current.Found).kind)
        assertTrue(stage.commit())
        assertEquals(MnemonicSetStore.Kind.V3, (s.current() as MnemonicSetStore.Current.Found).kind)
    }
}
