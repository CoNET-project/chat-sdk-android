package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The live pre-read reply (supplement 32; vectors v4 NP-14..NP-17): a plain ok carries the set's EOA, a vault fallback carries the
 * vault account's EOA, a store/vault mismatch keeps the store's EOA and reports `diagnostic: store_vault_eoa_mismatch` at the top level, and the
 * cipher reply carries no eoa. An untrusted request is refused before any read (NP-17).
 */
class PrereadEoaTest {

    private val e1 = "0x1111111111111111111111111111111111111111"
    private val e2 = "0x2222222222222222222222222222222222222222"
    private val phrase = "SYNTHETIC-TEST-PHRASE-NOT-A-WALLET"

    @Before
    fun baseline() {
        MnemonicPreread.resetForTests()
        assertTrue(MnemonicPreread.accept(0L))
    }

    private fun body(trusted: Boolean): JSONObject {
        val b = JSONObject().put("type", "nativeMnemonicPreread").put("reqId", "np").put("seq", 1)
        if (trusted) b.put("trustedOrigin", true)
        return b
    }

    private fun plainStore(eoa: String) = MnemonicSetStore.Current.Found(eoa, MnemonicSetStore.Kind.PLAIN, phrase, 1)

    /** NP-14: a trusted request with a plain store set answers ok with the mnemonic and the set's EOA. */
    @Test
    fun np14PlainStoreOkCarriesTheSetsEoa() {
        val p = NativeSyncAck.prereadStorePayload("np", body(true), current = { plainStore(e1) })
        val r = p.getJSONObject("result")
        assertEquals("ok", r.getString("code"))
        assertEquals(phrase, r.getString("mnemonic"))
        assertEquals(e1, r.getString("eoa"))
        assertFalse(p.has("diagnostic"))
    }

    /** NP-15: an absent store with a Ready vault falls back and answers ok with the vault account's EOA. */
    @Test
    fun np15VaultFallbackCarriesTheVaultsEoa() {
        val p = NativeSyncAck.prereadStorePayload(
            "np", body(true),
            vault = { PrereadStoreAnswer.VaultSource.Ready(e2, { phrase }) },
            current = { MnemonicSetStore.Current.Absent },
        )
        val r = p.getJSONObject("result")
        assertEquals("ok", r.getString("code"))
        assertEquals(e2, r.getString("eoa"))
        assertFalse(p.has("diagnostic"))
    }

    /** NP-16: the store's EOA differs from the vault account: the store's EOA is kept and the top-level diagnostic is reported. */
    @Test
    fun np16MismatchKeepsTheStoreEoaAndReportsTheDiagnostic() {
        var diag: String? = null
        val p = NativeSyncAck.prereadStorePayload(
            "np", body(true),
            vault = { PrereadStoreAnswer.VaultSource.Ready(e2, { phrase }) },
            onDiag = { diag = it },
            current = { plainStore(e1) },
        )
        assertEquals(e1, p.getJSONObject("result").getString("eoa"))
        assertEquals("store_vault_eoa_mismatch", p.getString("diagnostic"))
        assertEquals("store_vault_eoa_mismatch", diag)
    }

    /** The cipher reply is unchanged: no eoa is added to a v3 current set. */
    @Test
    fun theCipherReplyCarriesNoEoa() {
        val v3 = MnemonicSetStore.Current.Found(e1, MnemonicSetStore.Kind.V3, "{\"v\":3}", 1)
        val r = NativeSyncAck.prereadStorePayload("np", body(true), current = { v3 }).getJSONObject("result")
        assertEquals("ok", r.getString("code"))
        assertTrue(r.has("cipher"))
        assertFalse(r.has("eoa"))
    }

    /** NP-17: a request that carries trustedOrigin only in the page is refused before any read (the shell owns the marker). */
    @Test
    fun np17AnUntrustedRequestIsRefusedBeforeAnyRead() {
        var reads = 0
        val p = NativeSyncAck.prereadStorePayload("np", body(false), current = { reads++; plainStore(e1) })
        assertFalse(p.getBoolean("ok"))
        assertEquals("untrusted_source", p.getString("error"))
        assertEquals(0, reads)
        assertFalse(p.toString().contains(phrase))
    }
}
