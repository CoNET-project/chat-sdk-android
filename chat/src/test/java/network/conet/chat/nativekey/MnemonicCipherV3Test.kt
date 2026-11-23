package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The v3 mnemonic cipher (format v3, section 2) against the byte-exact vector files: `mnemonic-cipher-format.v3.json` (source
 * sha256 9fc7d406…8842, the MCF3 cases) and `mnemonic-cipher-format.v3-mcf305-explicit.json` (sha256 d123f518…, the MCF3-05 construction, the
 * open order, and MCF3-05b). Both are copies of the project source vectors; the test reads them with org.json. Synthetic phrase and passcode only.
 */
class MnemonicCipherV3Test {

    private val vectors = File("src/test/resources/vectors/mnemonic-cipher-format.v3.json")
    private val explicit = File("src/test/resources/vectors/mnemonic-cipher-format.v3-mcf305-explicit.json")
    private val v3 = JSONObject(vectors.readText(Charsets.UTF_8))
    private val mcf305 = JSONObject(explicit.readText(Charsets.UTF_8))
    private val inputs = v3.getJSONObject("syntheticInputs")
    private val phrase = inputs.getString("phrase")
    private val correct = inputs.getString("sixDigitPasscode")
    private val fixtureSalt = inputs.getString("saltB64")
    private val fixtureIv = inputs.getString("ivB64")

    private fun v3Case(id: String): JSONObject {
        val cases = v3.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("id").startsWith(id)) return c
        }
        error("no case $id")
    }

    private fun envelopeOf(e: JSONObject, v: Int = e.getInt("v")) = MnemonicCipherV3.Envelope(
        v = v,
        mode = e.getString("mode"),
        eoa = e.getString("eoa"),
        kdf = e.getString("kdf"),
        saltB64 = e.getString("salt"),
        ivB64 = e.getString("iv"),
        alg = e.getString("alg"),
        ctB64 = e.getString("ct"),
    )

    /** Positive: MCF3-01 opens with the correct passcode; the derived address matches; the phrase is the fixture's. */
    @Test
    fun mcf3_01OpensWithTheCorrectPasscode() {
        val c = v3Case("MCF3-01")
        val r = MnemonicCipherV3.open(envelopeOf(c.getJSONObject("envelope")), correct)
        assertEquals("ok", r.code)
        assertEquals(phrase, r.phrase)
        assertEquals("0xd49251e1e9f4d4d5bac808861fa4ce23053c986f", c.getJSONObject("envelope").getString("eoa"))
    }

    /** Negative: MCF3-02 (wrong six digits) and MCF3-03 (tampered ciphertext) are unlock_failed; no phrase is returned. */
    @Test
    fun mcf3_02And03AreUnlockFailed() {
        val wrong = MnemonicCipherV3.open(envelopeOf(v3Case("MCF3-02").getJSONObject("envelope")), "000000")
        assertEquals("unlock_failed", wrong.code)
        assertNull(wrong.phrase)
        assertEquals("unlock_failed", MnemonicCipherV3.open(envelopeOf(v3Case("MCF3-03").getJSONObject("envelope")), correct).code)
    }

    /** Negative: MCF3-04 (version 2) is verify_failed before any decryption; the version check is first. */
    @Test
    fun mcf3_04IsVerifyFailedBeforeDecryption() {
        val e = v3Case("MCF3-04").getJSONObject("envelope")
        assertEquals("verify_failed", MnemonicCipherV3.open(envelopeOf(e, v = 2), correct).code)
    }

    /**
     * MCF3-05 construction (mcf305-explicit): the ciphertext was encrypted with the AAD of the wrong EOA 0x2222…, and the envelope names
     * 0x2222…. It decrypts (the AAD follows the envelope's eoa); the derived address 0xd49251e1… does not match: verify_failed.
     */
    @Test
    fun mcf3_05ConstructionDecryptsAndFailsTheAddressCheck() {
        val c = mcf305.getJSONObject("construction").getJSONObject("MCF3-05-verify_failed")
        val env = MnemonicCipherV3.Envelope(3, "passcode", c.getString("envelopeEoa"), MnemonicCipherV3.KDF, fixtureSalt, fixtureIv, MnemonicCipherV3.ALG, c.getString("ct"))
        assertEquals("verify_failed", MnemonicCipherV3.open(env, correct).code)
        assertEquals("verify_failed", c.getJSONObject("expect").getString("code"))
    }

    /** Negative: MCF3-05b (the envelope eoa was edited after encryption): the AAD does not match, so unlock_failed. */
    @Test
    fun mcf3_05bEditedEnvelopeEoaIsUnlockFailed() {
        val c = mcf305.getJSONObject("construction").getJSONObject("MCF3-05b-unlock_failed-envelope-eoa-edited-after-encrypt")
        val env = MnemonicCipherV3.Envelope(3, "passcode", c.getString("envelopeEoa"), MnemonicCipherV3.KDF, fixtureSalt, fixtureIv, MnemonicCipherV3.ALG, c.getString("ct"))
        assertEquals("unlock_failed", MnemonicCipherV3.open(env, correct).code)
    }

    /** Negative: MCF3-06 reference (the ciphertext was encrypted with another EOA's AAD): unlock_failed. */
    @Test
    fun mcf3_06ReferenceIsUnlockFailed() {
        val c = mcf305.getJSONObject("construction").getJSONObject("MCF3-06-reference")
        val env = MnemonicCipherV3.Envelope(3, "passcode", c.getString("envelopeEoa"), MnemonicCipherV3.KDF, fixtureSalt, fixtureIv, MnemonicCipherV3.ALG, c.getString("ct"))
        assertEquals("unlock_failed", MnemonicCipherV3.open(env, correct).code)
    }

    /** Cross-generation (positive): sealing with the fixture salt, IV and passcode reproduces MCF3-01's ciphertext byte for byte. */
    @Test
    fun aSealWithTheFixtureInputsReproducesTheFixtureCiphertext() {
        val e = v3Case("MCF3-01").getJSONObject("envelope")
        val sealed = MnemonicCipherV3.seal(e.getString("eoa"), correct, phrase, b64(fixtureSalt), b64(fixtureIv))
        assertEquals(e.getString("ct"), sealed.ctB64)
        assertEquals(e.getString("kdf"), sealed.kdf)
    }

    /** Positive: a random seal round-trips (production salt and IV are random per record). */
    @Test
    fun aRandomSealRoundTrips() {
        val eoa = v3Case("MCF3-01").getJSONObject("envelope").getString("eoa")
        val sealed = MnemonicCipherV3.seal(eoa, correct, phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        val r = MnemonicCipherV3.open(sealed, correct)
        assertEquals("ok", r.code)
        assertEquals(phrase, r.phrase)
    }

    /** Negative: a salt or IV of the wrong size, or another mode, is verify_failed (no decryption attempt). */
    @Test
    fun wrongSizesAndModeAreVerifyFailed() {
        val eoa = v3Case("MCF3-01").getJSONObject("envelope").getString("eoa")
        val good = MnemonicCipherV3.seal(eoa, correct, phrase, MnemonicCipherV3.newSalt(), MnemonicCipherV3.newIv())
        val shortIv = good.copy(ivB64 = java.util.Base64.getEncoder().encodeToString(ByteArray(8)))
        assertEquals("verify_failed", MnemonicCipherV3.open(shortIv, correct).code)
        assertEquals("verify_failed", MnemonicCipherV3.open(good.copy(mode = "device"), correct).code)
    }

    /**
     * Source guard and the String limit (accepted by the reviewer): the code never logs; the passcode bytes are zeroed right after the KDF
     * input, the derived key and the plaintext bytes are zeroed, and the returned phrase is a String (JVM strings cannot be zeroed; the caller
     * keeps it only in memory for this run).
     */
    @Test
    fun theCodeNeverLogsAndZeroesItsByteCopies() {
        val src = File("src/main/java/network/conet/chat/nativekey/MnemonicCipherV3.kt").readText(Charsets.UTF_8)
        assertFalse(src.contains("Log."))
        assertFalse(src.contains("println"))
        assertTrue(src.contains("pw.fill(0)"))
        assertTrue(src.contains("key.fill(0)"))
        assertTrue(src.contains("pt.fill(0)"))
    }

    private fun b64(s: String): ByteArray = java.util.Base64.getDecoder().decode(s)
}
