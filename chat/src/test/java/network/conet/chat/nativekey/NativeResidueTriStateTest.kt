package network.conet.chat.nativekey

import network.conet.chat.nativekey.NativeWalletVault.Import
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File
import java.io.IOException

/**
 * The account decision of a key record that is missing (25.52Y.107, final; 25.52Y.108 第 3 条). A readable phrase is has; a phrase entry that cannot
 * be read is unknown; a read that completed with no phrase is confirmed none (no_key), whatever the marker, commit, intent or other residues are.
 * kPresent (K only) does not decide the account. The pinned vector cases TS-07 to TS-10 run here as written.
 */
class NativeResidueTriStateTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    /** A store whose read of one name fails, as a store that cannot be read does. */
    private class ReadFailsFor(private val inner: VaultFiles, private val name: String) : VaultFiles {
        override fun read(name: String): ByteArray? = if (name == this.name) throw IOException("store unreadable") else inner.read(name)

        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)

        override fun delete(name: String) = inner.delete(name)
    }

    /** A phrase row that opens under its own EOA, with no key record: the phrase is the only record of the account. */
    private fun phraseOnly(wrap: NativeTestWrap, files: NativeTestFiles) {
        val key = MnemonicDerivation.deriveKey(phrase)!!
        val eoa = WalletAddress.fromPrivateKey(key)!!
        assertEquals(Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(eoa, key, phrase))
        files.map.remove(NativeWalletVault.REC)
        files.map.remove(NativeWalletVault.MARK)
        files.map.remove(NativeWalletVault.COMMIT)
    }

    /**
     * The page's answer for the account: the walletStatus of the vault state and the tri-state of it (kPresent is K only and does not decide).
     * A state that cannot be read is unknown (snapshot unknown): the page's not_ready.
     */
    private fun classifyVault(files: VaultFiles, wrap: NativeTestWrap): String {
        val vault = NativeWalletVault(wrap, files)
        val state = try {
            vault.state()
        } catch (_: IOException) {
            return NativeMnemonicTriState.classify(true, null, null, false)
        }
        val gate = NoKeyGate.gateOf(state, sessionReady = false)
        val ws = NoKeyGate.walletStatusFor(gate, state)
        return NativeMnemonicTriState.classify(false, ws.getString("status"), ws.optString("notReadyReason").ifEmpty { null }, false)
    }

    /** The pinned vector cases TS-07 to TS-10, run as written (25.52Y.107 第 6 条). */
    @Test
    fun theResidueCasesOfThePinnedVectorRunAsWritten() {
        val doc = JSONObject(File("../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8))
        val cases = doc.getJSONArray("nativeResidueTriStateCases")
        assertEquals(4, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("id")
            val input = c.getJSONObject("input")
            val files = NativeTestFiles()
            val wrap = NativeTestWrap()
            when (input.getString("mnemonic")) {
                "readable" -> phraseOnly(wrap, files)
                "error" -> files.map[NativeWalletVault.MNEM] = "phrase entry".toByteArray(Charsets.UTF_8)
                "absent" -> Unit
            }
            if (input.optBoolean("commitOnly", false)) files.map[NativeWalletVault.COMMIT] = "commit-residue".toByteArray(Charsets.UTF_8)
            val result = if (input.getString("mnemonic") == "error") {
                // The phrase entry is present and its read fails: the state is not taken (unknown), never confirmed none.
                assertThrows(IOException::class.java) { NativeWalletVault(wrap, ReadFailsFor(files, NativeWalletVault.MNEM)).state() }
                classifyVault(ReadFailsFor(files, NativeWalletVault.MNEM), wrap)
            } else {
                classifyVault(files, wrap)
            }
            assertEquals("$id: as written", c.getString("expect"), result)
        }
    }

    /**
     * Y.107 第 1 条 through the storage answer: the page's walletStatus for a readable phrase without the key record is not intercepted as a storage
     * lock; it is the G1 walletStatus that has the shape of has (not_ready, g1_uninitialized), which classifies as has.
     */
    @Test
    fun aReadablePhraseWithoutTheKeyRecordIsNotInterceptedAndWalletStatusIsHas() {
        val state = NativeWalletVault.State.Locked(NativeWalletVault.PHRASE_ONLY)
        assertEquals(null, NoKeyGate.storageAnswer("walletStatus", state))
        val ws = NoKeyGate.walletStatusFor(NoKeyGate.gateOf(state, sessionReady = false), state)
        assertEquals("not_ready", ws.getString("status"))
        assertEquals(NoKeyGate.NOT_READY_G1_UNINITIALIZED, ws.getString("notReadyReason"))
        assertEquals(NativeMnemonicTriState.HAS, NativeMnemonicTriState.classify(false, "not_ready", NoKeyGate.NOT_READY_G1_UNINITIALIZED, false))
    }

    /** A storage-derived lock (a record that cannot be read) is still intercepted: not_ready and unreadable, never has. */
    @Test
    fun aStorageDerivedLockIsStillInterceptedAsUnreadable() {
        val state = NativeWalletVault.State.Locked("record_missing")
        assertEquals(NoKeyGate.StorageAnswer.WALLET_STATUS_NOT_READY, NoKeyGate.storageAnswer("walletStatus", state))
    }
}
