package network.conet.chat.nativekey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * Synthetic cases SO-18..SO-23 of v3.1 (spec-59e-synthetic-vectors.v3-add.json, sha256 b2781c76…; text spec-59e-revision-text-v3.1-decided.md,
 * sha256 02fbf938…). Accounts are the synthetic test phrases; the wrap and the files are the test doubles. SO-01..17 are in SpecV2SealTest;
 * SO-16 is skipped pending. Confirmed loss (SO-22A) and unknown (SO-22B) are asserted separately.
 */
class SpecV3SealTest {
    private val oldPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val newPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"

    private fun keyOf(phrase: String): ByteArray = checkNotNull(MnemonicDerivation.deriveKey(phrase))
    private fun eoaOf(key: ByteArray): String = checkNotNull(WalletAddress.fromPrivateKey(key))

    private fun oldAccount(wrap: VaultWrap, files: VaultFiles): NativeWalletVault {
        val vault = NativeWalletVault(wrap, files)
        val key = keyOf(oldPhrase)
        assertEquals(NativeWalletVault.Import.OK, vault.importMnemonicKey(eoaOf(key), key, oldPhrase))
        return vault
    }

    private fun isolatedOf(files: NativeTestFiles, name: String): List<String> = files.map.keys.filter { it.startsWith("$name.isolated.") }

    /** Delegates to a [NativeTestWrap], with the presence answer chosen by the case (25.52Y.122: confirmed absent only when enumerated). */
    private class VaultWrap(val inner: NativeTestWrap) : KeyWrap {
        var presenceValue: WrapKeyPresence = WrapKeyPresence.UNKNOWN
        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray = inner.seal(aad, plain)
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = inner.open(aad, sealed)
        override fun deleteKey(): Boolean = inner.deleteKey()
        override fun presence(): WrapKeyPresence = presenceValue
    }

    /** A file double with hooks after a rename and on a read. */
    private class Faulty(val inner: NativeTestFiles) : VaultFiles {
        var afterRename: ((String, String) -> Unit)? = null
        var corruptReadOnce: String? = null
        var failReadOf: String? = null
        override fun read(name: String): ByteArray? {
            if (failReadOf == name) throw IOException("storage unreadable")
            if (corruptReadOnce == name) {
                corruptReadOnce = null
                return "garbage".toByteArray()
            }
            return inner.read(name)
        }
        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)
        override fun delete(name: String) = inner.delete(name)
        override fun names(): List<String> = inner.names()
        override fun rename(from: String, to: String) {
            inner.rename(from, to)
            afterRename?.invoke(from, to)
        }
    }

    private fun digest(b: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    private fun snapshot(files: NativeTestFiles): Map<String, String> = files.map.mapValues { (_, b) -> digest(b) }

    // SO-18: the seal readback fails and the fixed name is non-empty: both kept, unknown, nothing deleted.
    @Test fun so18_sealFailureWithNonEmptyFixedNameKeepsBothAndIsUnknown() {
        val wrap = VaultWrap(NativeTestWrap()); val inner = NativeTestFiles()
        oldAccount(wrap, inner)
        val faulty = Faulty(inner)
        faulty.afterRename = { from, to ->
            if (from == NativeWalletVault.REC) {
                faulty.corruptReadOnce = to
                inner.map[NativeWalletVault.REC] = "something-else".toByteArray()
            }
        }
        val key = keyOf(newPhrase)
        val outcome = NativeWalletVault(wrap, faulty).syncPhrase(eoaOf(key), key, newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.ROLLBACK_PENDING, outcome)
        assertEquals(1, isolatedOf(inner, NativeWalletVault.REC).size)
        assertTrue(inner.map.containsKey(NativeWalletVault.PENDING))
        assertEquals("unknown", NativeWalletVault(wrap, inner).readStateLabel())
    }

    // SO-19: a rename in step 4 fails after the first file moved: the moved file is renamed back, bytes checked, sealing_failed, retryable.
    @Test fun so19_partialStepFourIsRolledBackFileByFile() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        oldAccount(wrap, files)
        val oldRec = files.map[NativeWalletVault.REC]!!.copyOf()
        val oldMnem = files.map[NativeWalletVault.MNEM]!!.copyOf()
        files.failRename = { it == NativeWalletVault.MNEM }
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.SEALING_FAILED, NativeWalletVault(wrap, files).syncPhrase(eoaOf(key), key, newPhrase))
        assertArrayEquals(oldRec, files.map[NativeWalletVault.REC])
        assertArrayEquals(oldMnem, files.map[NativeWalletVault.MNEM])
        assertTrue(isolatedOf(files, NativeWalletVault.REC).isEmpty())
        assertFalse("the new value was never written", files.map.containsKey(NativeWalletVault.PENDING))
        assertTrue("the restore is audited", String(files.map.getValue(NativeWalletVault.AUDIT)).contains("restored_after_failed_write"))
    }

    // SO-20: the same partial failure, and the restore cannot complete: kept as they are, unknown.
    @Test fun so20_partialStepFourWithAFailedRestoreKeepsEverythingAndIsUnknown() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        oldAccount(wrap, files)
        files.failRename = { it == NativeWalletVault.MNEM || it.startsWith(NativeWalletVault.REC + ".isolated.") }
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.ROLLBACK_PENDING, NativeWalletVault(wrap, files).syncPhrase(eoaOf(key), key, newPhrase))
        assertEquals(1, isolatedOf(files, NativeWalletVault.REC).size)
        assertTrue(files.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-21: the native state cannot be read on the write path: nothing is touched.
    @Test fun so21_unreadableNativeStateChangesNothing() {
        val wrap = VaultWrap(NativeTestWrap()); val inner = NativeTestFiles()
        oldAccount(wrap, inner)
        val before = snapshot(inner)
        val faulty = Faulty(inner)
        faulty.failReadOf = NativeWalletVault.REC
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, NativeWalletVault(wrap, faulty).syncPhrase(eoaOf(key), key, newPhrase))
        assertEquals(before, snapshot(inner))
        assertFalse(inner.map.containsKey(NativeWalletVault.PENDING))
        assertTrue(isolatedOf(inner, NativeWalletVault.REC).isEmpty())
    }

    // SO-22A: a confirmed loss (the alias is confirmed absent, the old record does not open): the new account is written as WK
    // requires; the old bytes are kept under an isolated name, not deleted, and the audit row says so.
    @Test fun so22A_confirmedLossWritesTheNewAccountAndKeepsTheBytes() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        val seeded = oldAccount(wrap, files)
        assertTrue(seeded.state() is NativeWalletVault.State.Ready)
        val lostBytes = files.map[NativeWalletVault.REC]!!.copyOf()
        wrap.inner.deleteKey()
        wrap.presenceValue = WrapKeyPresence.CONFIRMED_ABSENT
        val key = keyOf(newPhrase)
        val result = NativeWalletVault(wrap, files).importMnemonicKey(eoaOf(key), key, newPhrase)
        assertEquals(NativeWalletVault.Import.OK, result)
        val iso = isolatedOf(files, NativeWalletVault.REC)
        assertEquals(1, iso.size)
        assertArrayEquals("the lost bytes are kept, not deleted", lostBytes, files.map[iso.single()])
        assertTrue("the audit row says confirmed loss", auditLines(files).any {
            it.optString("reason") == "isolated_for_new_slot" && it.optBoolean("confirmedLost", false)
        })
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
        assertEquals("retained", NativeWalletVault(wrap, files).readStateLabel())
    }

    // SO-22B: the loss cannot be told from an unknown state (the alias is not confirmed absent): nothing is written; retryable.
    @Test fun so22B_undecidedLossChangesNothingAndIsRetryable() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        oldAccount(wrap, files)
        wrap.inner.deleteKey()
        wrap.presenceValue = WrapKeyPresence.UNKNOWN
        val before = snapshot(files)
        val key = keyOf(newPhrase)
        val outcome = NativeWalletVault(wrap, files).syncPhrase(eoaOf(key), key, newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.NOT_READY, outcome)
        assertEquals(before, snapshot(files))
        assertFalse(files.map.containsKey(NativeWalletVault.PENDING))
    }

    // SO-23: the retained record holds exactly the allowed fields and nothing sensitive; it is its own file.
    @Test fun so23_retainedFieldsAreAllowedAndSensitiveFree() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        val vault = oldAccount(wrap, files)
        val key = keyOf(newPhrase)
        assertEquals(NativeWalletVault.SyncOutcome.UPDATED, vault.syncPhrase(eoaOf(key), key, newPhrase))
        assertTrue(files.map.containsKey("wallet.isolation.retained"))
        val raw = String(files.map.getValue("wallet.isolation.retained"), Charsets.UTF_8)
        val json = org.json.JSONObject(raw)
        assertEquals(setOf("oldEoa", "time", "auditRef", "isolatedNames", "oldSha"), json.keys().asSequence().toSet())
        for (bad in listOf("mnemonic", "phrase", "privateKey", "password", "passcode", "pin", "ciphertext")) {
            assertFalse("no $bad", raw.contains(bad, ignoreCase = true))
        }
        assertFalse(String(files.map.getValue(NativeWalletVault.AUDIT)).contains("phrase"))
    }

    private fun auditLines(files: NativeTestFiles): List<org.json.JSONObject> =
        String(files.map[NativeWalletVault.AUDIT] ?: ByteArray(0)).lines().filter { it.isNotBlank() }.map { org.json.JSONObject(it) }
}
