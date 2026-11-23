package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Data-driven cases of spec-59e-synthetic-vectors.v3.3.1-E9.10.3-add.json (vendored, sha256 22f1471a...): WK-29a, WK-04a, WK-30a, WK-31a.
 * Each input builds a residue (REC, MARK present or absent, COMMIT absent, MNEM absent and read empty) and an optional read fault on REC.
 * The external answers are checked: walletStatus no_key, phrase verdict absent (MISSING), pre-read absent, and no byte deleted.
 * WK-30a: the internal state may be NoKey or Ready(keyOnly) (2026-11-17, non-normative); the external answers decide.
 */
class E9103AddVectorsTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    // The vectors give the keystore as normal (keystoreOk true): the wrap key presence is known (PRESENT).
    private val wrap: KeyWrap = object : KeyWrap by NativeTestWrap() {
        override fun presence(): WrapKeyPresence = WrapKeyPresence.PRESENT
    }
    private fun key() = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoa() = checkNotNull(WalletAddress.fromPrivateKey(key()))

    private fun vectors(): List<JSONObject> {
        val text = javaClass.getResourceAsStream("/spec-vectors/spec-59e-synthetic-vectors.v3.3.1-E9.10.3-add.json")!!
            .bufferedReader(Charsets.UTF_8).readText()
        val cases = JSONObject(text).getJSONArray("cases")
        return (0 until cases.length()).map { cases.getJSONObject(it) }.filter { it.getString("id") in setOf("WK-29a", "WK-04a", "WK-30a", "WK-31a") }
    }

    @Test fun everyE9103AddCaseHoldsItsExternalAnswers() {
        val cases = vectors()
        assertEquals(4, cases.size)
        for (c in cases) {
            val id = c.getString("id")
            val r = c.getJSONObject("input").getJSONObject("residue")
            val files = NativeTestFiles()
            assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(eoa(), key()))
            files.map.remove(NativeWalletVault.COMMIT)
            files.map.remove(NativeWalletVault.MNEM)
            if (!r.getBoolean("rec")) files.map.remove(NativeWalletVault.REC)
            if (!r.getBoolean("mark")) files.map.remove(NativeWalletVault.MARK)
            if (r.optString("failure") == "marker_mismatch") files.map[NativeWalletVault.MARK] = "not-the-digest".toByteArray()
            if (!r.getBoolean("readsOk") && r.optString("failedObject") == "REC") files.failRead = { it == NativeWalletVault.REC }
            val before = files.map.keys.toSet()
            NativeWalletVault.resetLaunchForTests()
            val v = NativeWalletVault(wrap, files)
            val st = v.state()
            val notRecord = c.getJSONObject("expect")
            // Internal state (WK-30a: NoKey or Ready keyOnly are both acceptable, 2026-11-17).
            val stateOk = if (id == "WK-30a") st is NativeWalletVault.State.NoKey || (st is NativeWalletVault.State.Ready && v.isKeyOnlyAccount()) else st == NativeWalletVault.State.NoKey
            assertTrue("$id: state $st", stateOk)
            val status = NoKeyGate.walletStatusFor(NoKeyGate.walletStatusGate(st, sessionReady = true, keyOnly = v.isKeyOnlyAccount()), st).getString("status")
            assertEquals("$id: walletStatus", notRecord.getString("walletStatus"), status)
            assertEquals("$id: phrase verdict absent", NativeWalletVault.PhraseVerdict.MISSING, v.phraseVerdict())
            assertEquals("$id: pre-read absent", MnemonicPreread.Answer.Absent, MnemonicPreread.vaultAnswerOrUnknown(NativeWalletVault(wrap, files)))
            files.failRead = null
            assertTrue("$id: no byte deleted", files.map.keys.containsAll(before))
        }
    }
}
