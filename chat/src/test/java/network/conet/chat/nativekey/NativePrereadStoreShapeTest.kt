package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The nativeMnemonicPreread reply from the store (step (2), code shape, the freeze prerequisite of). Synthetic data.
 * Positive: a plain set answers result.code ok with mnemonic; a v3 set answers ok with cipher only; an empty store answers confirmed_missing.
 * Negative: a read that cannot be completed is read_error, never confirmed_missing; an untrusted request carries nothing; a phrase in the request
 * is refused; the state shape is not returned.
 */
class NativePrereadStoreShapeTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private val eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"
    private fun body(seq: Int = 1, trusted: Boolean = true) = JSONObject().put("trustedOrigin", trusted).put("seq", seq)
    private fun store() = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))

    /** Positive: a plain current set is returned as it is: result.code ok, with the mnemonic. */
    @Test
    fun aPlainSetIsReturnedAsOkWithTheMnemonic() {
        val s = store()
        s.writePlain(eoa, phrase)
        val p = NativeSyncAck.prereadStorePayload(7, body()) { s.current() }
        assertTrue(p.getBoolean("ok"))
        assertEquals("ok", p.getJSONObject("result").getString("code"))
        assertEquals(phrase, p.getJSONObject("result").getString("mnemonic"))
    }

    /** Positive: a v3 current set answers ok with the ciphertext only, no passphrase needed, and no plaintext. */
    @Test
    fun aV3SetIsReturnedAsOkWithTheCiphertextOnly() {
        val s = store()
        s.writeEnvelope(MnemonicCipherV3.seal(eoa, "482913", phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv()))
        val p = NativeSyncAck.prereadStorePayload(8, body()) { s.current() }
        assertEquals("ok", p.getJSONObject("result").getString("code"))
        assertTrue(p.getJSONObject("result").has("cipher"))
        assertFalse(p.toString().contains("fog spot"))
    }

    /** Positive (MCF3-09 shape): an empty store is confirmed_missing, and nothing else is returned. */
    @Test
    fun anEmptyStoreIsConfirmedMissing() {
        val p = NativeSyncAck.prereadStorePayload(9, body()) { store().current() }
        assertEquals("confirmed_missing", p.getJSONObject("result").getString("code"))
        assertNull(p.getJSONObject("result").opt("mnemonic"))
    }

    /** Negative: a read that cannot be completed is read_error, never confirmed_missing (the data is kept). */
    @Test
    fun aReadThatCannotBeCompletedIsReadErrorNotConfirmedMissing() {
        val p = NativeSyncAck.prereadStorePayload(10, body()) { throw IllegalStateException("injected read fault") }
        assertEquals("read_error", p.getJSONObject("result").getString("code"))
        assertFalse(p.toString().contains("confirmed_missing"))
    }

    /** Negative: an untrusted request is refused before any read; a phrase in the request is refused. */
    @Test
    fun anUntrustedRequestAndAPhraseInTheRequestAreRefused() {
        var read = false
        val untrusted = NativeSyncAck.prereadStorePayload(11, body(trusted = false)) { read = true; MnemonicSetStore.Current.Absent }
        assertFalse(untrusted.getBoolean("ok"))
        assertFalse("nothing is read for an untrusted request", read)
        val withPhrase = NativeSyncAck.prereadStorePayload(12, body().put("phrase", phrase)) { MnemonicSetStore.Current.Absent }
        assertFalse(withPhrase.getBoolean("ok"))
        assertFalse(withPhrase.toString().contains("fog spot"))
    }

    /** Negative: the state shape ({state: valid|absent|unknown}) is not returned on the command path. */
    @Test
    fun theStateShapeIsNotReturned() {
        val p = NativeSyncAck.prereadStorePayload(13, body()) { MnemonicSetStore.Current.Absent }
        assertFalse(p.getJSONObject("result").has("state"))
    }
}
