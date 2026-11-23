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
 * shellRecord answers for a passcode-protected account and for an undetermined store state (SRP v2, the byte-exact copy in test resources,
 * sha256 0833f6ab…). Positive and negative examples: a v3 current set gives not_ready with passcode_not_provided on read and on write, and
 * the write stores nothing; an undetermined state (a corrupt pointer, a missing set) gives not_ready with unreadable and never the ordinary
 * path; a plain or absent store is neither; the codes storage_locked, write_failed (for the passcode state), and unknown are not used.
 */
class ShellPasscodeAnswerTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val srp = JSONObject(File("src/test/resources/vectors/shell-record-passcode-not-provided.v2.json").readText(Charsets.UTF_8))
    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"

    private fun srpCase(id: String): JSONObject {
        val cases = srp.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("id").startsWith(id)) return c
        }
        error("no case $id")
    }

    /** Positive (SRP-01): the read answer is ok with result {code:not_ready, notReadyReason:passcode_not_provided, retryable:true}. */
    @Test
    fun srp01ReadAnswerMatchesTheVector() {
        val want = srpCase("SRP-01").getJSONObject("expect")
        val got = ShellPasscodeAnswer.readAck("r1")
        assertEquals(want.getBoolean("ok"), got.getBoolean("ok"))
        val r = got.getJSONObject("result")
        val wr = want.getJSONObject("result")
        assertEquals(wr.getString("code"), r.getString("code"))
        assertEquals(wr.getString("notReadyReason"), r.getString("notReadyReason"))
        assertEquals(wr.getBoolean("retryable"), r.getBoolean("retryable"))
    }

    /** Positive (SRP-02 and SRP-09): the write answer is ok:false, error not_ready, the same notReadyReason and retryable; nothing is written. */
    @Test
    fun srp02And09WriteAnswerMatchesTheVector() {
        for (id in listOf("SRP-02", "SRP-09")) {
            val want = srpCase(id).getJSONObject("expect")
            val got = ShellPasscodeAnswer.writeAck("w1")
            assertEquals(want.getBoolean("ok"), got.getBoolean("ok"))
            assertEquals(want.getString("error"), got.getString("error"))
            assertEquals(want.getString("notReadyReason"), got.getString("notReadyReason"))
            assertTrue(got.getBoolean("retryable"))
        }
    }

    /** Negative (SRP-07): the passcode state never uses storage_locked, write_failed, or unknown. */
    @Test
    fun srp07ForbidsStorageLockedWriteFailedAndUnknownForThePasscodeState() {
        val forbidden = srpCase("SRP-07").getJSONObject("expect").getJSONArray("forbiddenCodes")
        val read = ShellPasscodeAnswer.readAck("r").toString()
        val write = ShellPasscodeAnswer.writeAck("w").toString()
        for (i in 0 until forbidden.length()) {
            val code = forbidden.getString(i).removeSuffix("_for_passcode_state")
            assertFalse(read.contains("\"$code\""))
            assertFalse(write.contains("\"$code\""))
        }
    }

    /** Positive (SRP-05): an undetermined state reads as not_ready with notReadyReason unreadable, retryable, and no unknown code. */
    @Test
    fun srp05UnknownStateReadsAsUnreadable() {
        val want = srpCase("SRP-05").getJSONObject("expect").getJSONObject("result")
        val r = ShellPasscodeAnswer.readUnknownAck("r").getJSONObject("result")
        assertEquals(want.getString("code"), r.getString("code"))
        assertEquals(want.getString("notReadyReason"), r.getString("notReadyReason"))
        assertTrue(r.getBoolean("retryable"))
    }

    /** Positive: only a v3 current set is a passcode account; plain, absent, and unknown are not. */
    @Test
    fun onlyAV3CurrentSetIsAPasscodeAccount() {
        assertTrue(ShellPasscodeAnswer.isPasscodeAccount(MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.V3, "{}")))
        assertFalse(ShellPasscodeAnswer.isPasscodeAccount(MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, "fog")))
        assertFalse(ShellPasscodeAnswer.isPasscodeAccount(MnemonicSetStore.Current.Absent))
        assertFalse(ShellPasscodeAnswer.isPasscodeAccount(MnemonicSetStore.Current.Unknown("set_missing")))
    }

    /** Negative (2026-11-22 on the review): a corrupt pointer in the real store is unknown, so the unreadable answer applies. */
    @Test
    fun aCorruptPointerInTheStoreIsUnknownAndUnreadable() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        store.writePlain("0xd49251e1e9f4d4d5bac808861fa4ce23053c986f", "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect")
        File(tmp.root, "${MnemonicSetStore.DIRECTORY}/current.v1").writeText("garbage", Charsets.UTF_8)
        val c = store.current()
        assertTrue(ShellPasscodeAnswer.isUnknownState(c))
        assertEquals("pointer_invalid", (c as MnemonicSetStore.Current.Unknown).reason)
        assertEquals("unreadable", ShellPasscodeAnswer.readUnknownAck("r").getJSONObject("result").getString("notReadyReason"))
    }

    /** Negative: a missing set file under a valid pointer is unknown (set_missing), never absent. */
    @Test
    fun aMissingSetFileInTheStoreIsUnknownAndUnreadable() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        val e = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
        store.writePlain(e, "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect")
        File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$e.plain.1.v1").delete()
        val c = store.current()
        assertTrue(ShellPasscodeAnswer.isUnknownState(c))
        assertEquals("set_missing", (c as MnemonicSetStore.Current.Unknown).reason)
    }

    /** Source guard: the bridge checks the passcode state and the unknown state after the not_ready gate and before any read or write. */
    @Test
    fun theBridgeChecksTheStoreStateBeforeAnyRead() {
        val src = File("src/main/java/network/conet/chat/nativekey/ShellRecord.kt").readText(Charsets.UTF_8)
        val gate = src.indexOf("if (acc is ShellRecordAccount.NotReady) return reply(\"not_ready\", emptyList())")
        val pw = src.indexOf("ShellPasscodeAnswer.isPasscodeAccount(pwState)")
        val unk = src.indexOf("ShellPasscodeAnswer.isUnknownState(pwState)")
        val readCall = src.indexOf("if (type == \"shellRecordRead\") read(acc, reply)")
        assertTrue(gate in 0 until pw)
        assertTrue(pw in 0 until unk)
        assertTrue(unk in 0 until readCall)
    }
}
