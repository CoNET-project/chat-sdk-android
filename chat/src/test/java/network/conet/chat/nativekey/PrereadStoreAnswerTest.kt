package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The preread answer from the store (MCF3-09 confirmed missing, MCF3-10 read error with the data kept; the SRP-03/04/05 fault codes are the
 * shellRecord ones). Synthetic data only. A read error never becomes confirmed_missing.
 */
class PrereadStoreAnswerTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"

    /** Positive (MCF3-09): an empty store is the one confirmed absence. */
    @Test
    fun mcf3_09EmptyStoreIsConfirmedMissing() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        assertEquals("confirmed_missing", PrereadStoreAnswer.answer(store.current()).getString("code"))
    }

    /** Positive: a plain current set answers ok with the phrase. */
    @Test
    fun aPlainCurrentSetAnswersOkWithThePhrase() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        store.writePlain(eoa, phrase)
        val a = PrereadStoreAnswer.answer(store.current())
        assertEquals("ok", a.getString("code"))
        assertEquals(phrase, a.getString("mnemonic"))
    }

    /** Positive: a v3 current set answers ok with the ciphertext only, and no plaintext. */
    @Test
    fun aV3CurrentSetAnswersTheCiphertextOnly() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        store.writeEnvelope(MnemonicCipherV3.seal(eoa, "482913", phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv()))
        val a = PrereadStoreAnswer.answer(store.current())
        assertEquals("ok", a.getString("code"))
        assertTrue(a.has("cipher"))
        assertFalse(a.toString().contains("fog spot"))
    }

    /** Negative (MCF3-10): a read error answers read_error, never confirmed_missing, and the store's files are kept unchanged. */
    @Test
    fun mcf3_10ReadErrorIsNotConfirmedMissingAndKeepsTheData() {
        val dir = File(tmp.root, MnemonicSetStore.DIRECTORY)
        val store = MnemonicSetStore(dir)
        store.writePlain(eoa, phrase)
        val before = File(dir, "set.$eoa.plain.1.v1").readBytes()
        File(dir, "current.v1").writeText("garbage", Charsets.UTF_8)
        val a = PrereadStoreAnswer.answer(store.current())
        assertEquals("read_error", a.getString("code"))
        assertTrue(before.contentEquals(File(dir, "set.$eoa.plain.1.v1").readBytes()))
    }

    /** Source guards (SRP-03, SRP-04): the real read fault answers record_unreadable and the real write fault answers write_failed. */
    @Test
    fun theRealFaultCodesAreKept() {
        val src = File("src/main/java/network/conet/chat/nativekey/ShellRecord.kt").readText(Charsets.UTF_8)
        assertTrue(src.contains("reply(\"error\", listOf(\"sub\" to \"record_unreadable\")) else reply(\"write_failed\""))
    }

    /** Negative: a damaged v3 set file is a read error, never a crash and never a confirmed absence. */
    @Test
    fun aDamagedV3SetFileIsAReadError() {
        val store = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
        store.writeEnvelope(MnemonicCipherV3.seal(eoa, "482913", phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv()))
        File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.v3.1.v1").writeText("{not json", Charsets.UTF_8)
        assertEquals("read_error", PrereadStoreAnswer.answer(store.current()).getString("code"))
    }
}
