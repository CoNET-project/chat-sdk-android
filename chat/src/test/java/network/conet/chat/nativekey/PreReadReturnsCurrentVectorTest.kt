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
 * preread-returns-current-record-as-is.v1, byte-exact copy in test resources (sha256 aa8d0d70…). PRR-01 to PRR-05 run on the
 * JVM through prereadStorePayload (the command path's function). PRR-06 is PWA-side diagnostics and is not an SDK answer; PRR-07 is that the
 * passcode state is not a preread answer. Synthetic data only.
 */
class PreReadReturnsCurrentVectorTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val vector = JSONObject(File("src/test/resources/vectors/preread-returns-current-record-as-is.v1.json").readText(Charsets.UTF_8))
    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    // A seq above any earlier test in this JVM, so the shared ledger (latestAcceptedSeq) never marks it stale.
    private fun body() = JSONObject().put("trustedOrigin", true).put("seq", 9_000_000_000_000L)
    private fun store() = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))
    private fun expect(id: String): JSONObject {
        val cases = vector.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("id").startsWith(id)) return c.getJSONObject("expect")
        }
        error("no $id")
    }

    /** PRR-01: plaintext current returned as it is: code ok with the mnemonic. */
    @Test
    fun prr01PlaintextCurrentIsReturnedAsIs() {
        val s = store()
        s.writePlain(eoa, phrase)
        val r = NativeSyncAck.prereadStorePayload(1, body()) { s.current() }.getJSONObject("result")
        assertEquals(expect("PRR-01").getString("code"), r.getString("code"))
        assertEquals(phrase, r.getString("mnemonic"))
    }

    /** PRR-02: a ciphertext current is returned without a passcode, as the cipher, and no plaintext. */
    @Test
    fun prr02CiphertextReadBackWithoutPasscodeIsCipherOnly() {
        val s = store()
        s.writeEnvelope(MnemonicCipherV3.seal(eoa, "482913", phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv()))
        val p = NativeSyncAck.prereadStorePayload(2, body()) { s.current() }
        val r = p.getJSONObject("result")
        assertEquals(expect("PRR-02").getString("code"), r.getString("code"))
        assertTrue(r.has("cipher"))
        assertFalse(p.toString().contains("fog spot"))
    }

    /** PRR-03: an empty store is confirmed_missing. */
    @Test
    fun prr03EmptyIsConfirmedMissing() {
        val r = NativeSyncAck.prereadStorePayload(3, body()) { store().current() }.getJSONObject("result")
        assertEquals(expect("PRR-03").getString("code"), r.getString("code"))
    }

    /** PRR-04: a read failure is read_error, never confirmed_missing, and the data is kept. */
    @Test
    fun prr04ReadFailureIsReadErrorAndKeepsTheData() {
        val s = store()
        s.writePlain(eoa, phrase)
        val before = File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.plain.1.v1").readBytes()
        val r = NativeSyncAck.prereadStorePayload(4, body()) { throw IllegalStateException("injected read failure") }.getJSONObject("result")
        assertEquals(expect("PRR-04").getString("code"), r.getString("code"))
        assertTrue(before.contentEquals(File(tmp.root, "${MnemonicSetStore.DIRECTORY}/set.$eoa.plain.1.v1").readBytes()))
    }

    /** PRR-05: a ciphertext current with no passcode and no SDK initialisation: the function needs no init, no unlock and no passcode. */
    @Test
    fun prr05CiphertextWithoutPasscodeOrInitIsReturned() {
        val s = store()
        s.writeEnvelope(MnemonicCipherV3.seal(eoa, "482913", phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv()))
        val r = NativeSyncAck.prereadStorePayload(5, body()) { s.current() }.getJSONObject("result")
        assertEquals(expect("PRR-05").getString("code"), r.getString("code"))
        assertTrue(r.has("cipher"))
    }

    /** PRR-07: the passcode state is not a preread answer: the ciphertext current is ok regardless of any passcode state. */
    @Test
    fun prr07PasscodeStateIsNotAPrereadAnswer() {
        val s = store()
        s.writeEnvelope(MnemonicCipherV3.seal(eoa, "482913", phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv()))
        val r = NativeSyncAck.prereadStorePayload(7, body()) { s.current() }.getJSONObject("result")
        assertEquals(expect("PRR-07").getString("code"), r.getString("code"))
        assertFalse(r.has("notReadyReason"))
    }
}
