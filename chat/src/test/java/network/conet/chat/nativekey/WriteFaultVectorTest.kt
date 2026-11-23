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
 * The interface write-fault vector (write-fault-shape-independent.v2, SHA256 prefix 925f9d55; interface seat 2026-11-22, SRP-04 option A).
 * mustPass cases hold for any fault shape, and PS-W-v291 (the top-level reason envelope) is must-pass in v2. The pendingShape cases (PS-W-v286,
 * PS-W-iOS, PS-R-v286, PS-R-v291) are not must-pass and are not asserted here.
 */
class WriteFaultVectorTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val doc = JSONObject(File("src/test/resources/vectors/write-fault-shape-independent.v2.json").readText(Charsets.UTF_8))
    private val must = doc.getJSONObject("mustPass")

    @Test
    fun theVectorCarriesTheFixedMustPassCases() {
        assertEquals("write-fault-shape-independent.v2", doc.getString("schema"))
        assertEquals(7, must.getJSONArray("pwaCases").length())
        assertEquals(3, must.getJSONArray("shellCases").length())
        val shellIds = (0 until must.getJSONArray("shellCases").length()).map { must.getJSONArray("shellCases").getJSONObject(it).getString("id") }.toSet()
        assertEquals(setOf("MS-W1", "MS-W2", "MS-R1"), shellIds)
    }

    /**
     * PS-W-v291 (must-pass in v2): the pwaWalletSync write-failure envelope is {ok:false, error:write_failed, reason:internal_state} with reason at
     * the top level. The envelope built by NativeSyncAck must match that reply exactly, and reason is never inside result.
     */
    @Test
    fun ps_wV291WriteFailedEnvelopeMatchesTheVectorReply() {
        val case = (0 until must.getJSONArray("pwaCases").length())
            .map { must.getJSONArray("pwaCases").getJSONObject(it) }
            .single { it.getString("id") == "PS-W-v291" }
        val reply = case.getJSONObject("reply")
        val built = NativeSyncAck.writeFailedEnvelope("req-1", NativeSyncAck.INTERNAL_STATE)
        assertEquals(reply.getBoolean("ok"), built.getBoolean("ok"))
        assertEquals(reply.getString("error"), built.getString("error"))
        assertEquals(reply.getString("reason"), built.getString("reason"))
        assertFalse("reason stays out of result", built.has("result"))
        val expect = case.getJSONObject("expect")
        assertEquals("write_failed", expect.getString("classify"))
        assertFalse(expect.getBoolean("completed"))
        assertFalse(expect.getBoolean("confirmedMissing"))
        assertFalse(expect.getBoolean("onboarding"))
        assertFalse(expect.getBoolean("newKey"))
        assertFalse(expect.getBoolean("currentSwitched"))
    }

    /** MS-R1: a read fault keeps the data: current is unknown (never absent), and the set file is neither deleted nor written. */
    @Test
    fun ms_r1ReadFaultKeepsTheDataAndAnswersUnknown() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
        val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
        assertTrue(store.writePlain(eoa, phrase) is MnemonicSetStore.Write.Stored)
        val file = File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.plain.1.v1")
        // A read that fails: the set path is not a readable file.
        val bytes = file.readBytes()
        file.delete()
        file.mkdir()
        val c = store.current()
        assertTrue("unknown, never absent", c is MnemonicSetStore.Current.Unknown)
        assertTrue("not deleted", file.exists())
        file.delete()
        file.writeBytes(bytes)
        assertTrue("the original bytes are back, unchanged", file.readBytes().contentEquals(bytes))
    }

    /** MS-W1 analogue: a write that fails before the pointer moves does not switch current; the older set stays (see the commit-failure test). */
    @Test
    fun ms_w1WriteFailureDoesNotSwitchCurrent() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
        val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
        store.writePlain(eoa, phrase)
        val before = store.current() as MnemonicSetStore.Current.Found
        val env = MnemonicCipherV3.seal(eoa, "123456", phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        val st = (store.stageEnvelope(env) as MnemonicSetStore.Stage.Ready).staged
        File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.v3.1.v1").writeText("occupied", Charsets.UTF_8)
        assertFalse(st.commit())
        st.abort()
        val after = store.current() as MnemonicSetStore.Current.Found
        assertEquals(before.kind, after.kind)
        assertEquals(before.value, after.value)
    }
}
