package network.conet.chat.nativekey

import network.conet.chat.nativekey.NativeWalletVault.PublishedWalletCopy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.IOException

/**
 * the P3 exemption (A1, A3, A4) and the order of the G0 marker rule before the key-only precheck (A2). Synthetic accounts.
 */
class G0PlanBPrecheckTest {
    private val x = "0x" + "a".repeat(40)
    private val wrap = NativeTestWrap()
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p))).lowercase()

    private fun precheck(
        owner: PendingOwner = PendingOwner.Absent,
        current: String? = null,
        keyOnly: Boolean = true,
        cleared: Boolean = true,
        vaultNoKey: Boolean = true,
        copy: PublishedWalletCopy = PublishedWalletCopy.Present,
        g0: Boolean = current == null,
        g2: Boolean = false,
    ) = clearPrecheck(g2, g0, owner, current, keyOnly, cleared, vaultNoKey, copy)

    /** The exemption holds only in the narrow state (GB-P3b). */
    @Test
    fun theExemptionHoldsOnlyInTheNarrowState() {
        assertEquals(ClearPrecheck.PROCEED, precheck())
        assertEquals("never cleared (GB-P3d)", ClearPrecheck.REFUSED_KEY_ONLY, precheck(cleared = false))
        assertEquals("current account (GB-P3a)", ClearPrecheck.REFUSED_KEY_ONLY, precheck(current = x, g2 = true))
        assertEquals("A4: copy unreadable is never exempt", ClearPrecheck.REFUSED_KEY_ONLY, precheck(copy = PublishedWalletCopy.Unknown))
    }

    /** A1 counterexample: cleared once, later restored with a private-key-only account; the vault is Locked (no current account) and the session is ready. */
    @Test
    fun clearedBeforeThenRestoredWithAKeyOnlyAccountIsRefusedAgain() {
        val files = NativeTestFiles()
        val a = eoaOf(phrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importKey(a, keyOf(phrase).copyOf()))
        val vault = NativeWalletVault(wrap, files)
        assertFalse("a key record exists", vault.keyRecordsAbsent())
        val flags = ClearFlagFiles(NativeTestFiles())
        assertTrue(flags.setIdentityCleared())
        assertTrue("the old identity_cleared marker is still set", flags.identityClearedStrict())
        // Locked and ready: currentEoa is null (not a Ready snapshot), the gate is G2 (Locked with a ready session).
        val keyOnly = vault.keyWithoutPhraseFor(null, MnemonicSetStore(java.nio.file.Files.createTempDirectory("a1").toFile()), PublishedWalletCopy.Absent)
        assertTrue(keyOnly)
        assertEquals(
            ClearPrecheck.REFUSED_KEY_ONLY,
            clearPrecheck(g2 = true, g0 = false, owner = PendingOwner.Absent, currentEoa = null, keyOnly = keyOnly,
                identityClearedStrict = flags.identityClearedStrict(), vaultNoKey = false, copy = PublishedWalletCopy.Absent),
        )
        // Nothing was written by the decision.
        assertFalse(vault.keyRecordsAbsent())
    }

    @Test
    fun keyRecordsAbsentIsTrueOnlyWhenEveryFileReadsAbsent() {
        assertTrue(NativeWalletVault(wrap, NativeTestFiles()).keyRecordsAbsent())
        for (name in listOf(NativeWalletVault.REC, NativeWalletVault.MARK, NativeWalletVault.COMMIT, NativeWalletVault.INTENT)) {
            val files = NativeTestFiles()
            files.map[name] = byteArrayOf(1)
            assertFalse("$name present", NativeWalletVault(wrap, files).keyRecordsAbsent())
        }
        val failing = object : VaultFiles by NativeTestFiles() {
            override fun read(name: String): ByteArray? = throw IOException("read fault")
        }
        assertFalse("a read failure is never absence", NativeWalletVault(wrap, failing).keyRecordsAbsent())
    }

    /** A3: the marker's content is checked. */
    @Test
    fun identityClearedIsStrictOnContent() {
        val files = NativeTestFiles()
        val flags = ClearFlagFiles(files)
        assertFalse(flags.identityClearedStrict())
        files.map[ClearFlagFiles.IDENTITY_CLEARED] = ByteArray(0)
        assertFalse("empty file", flags.identityClearedStrict())
        files.map[ClearFlagFiles.IDENTITY_CLEARED] = "garbage".toByteArray()
        assertFalse("damaged content", flags.identityClearedStrict())
        assertTrue("the non-strict reader still counts a present file as set", flags.identityCleared())
        assertTrue(flags.setIdentityCleared())
        assertTrue("written content", flags.identityClearedStrict())
        val failing = ClearFlagFiles(object : VaultFiles by NativeTestFiles() {
            override fun read(name: String): ByteArray? = throw IOException("read fault")
        })
        assertFalse("unreadable", failing.identityClearedStrict())
    }

    /** A2: the G0 marker rule is ahead of the key-only precheck, with the published copy kept. */
    @Test
    fun g0WithAMarkerAnswersClearIncompleteEvenWithTheKeptPublishedCopy() {
        for (copy in PublishedWalletCopy.values()) {
            assertEquals("owned X, copy $copy", ClearPrecheck.INCOMPLETE,
                precheck(owner = PendingOwner.Owned(x), copy = copy, cleared = false, vaultNoKey = false))
            assertEquals("unknown marker, copy $copy", ClearPrecheck.INCOMPLETE,
                precheck(owner = PendingOwner.Unknown, copy = copy, cleared = false, vaultNoKey = false))
        }
        // No marker and the copy kept on a device that never cleared: still the key-only refusal.
        assertEquals(ClearPrecheck.REFUSED_KEY_ONLY, precheck(cleared = false))
        // The current account equal to X resumes (no precheck refusal).
        assertEquals(ClearPrecheck.PROCEED, precheck(owner = PendingOwner.Owned(x), current = x, keyOnly = true, g0 = false, g2 = false))
    }

    @Test
    fun theModuleUsesTheTwoStepPrecheck() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        assertTrue(module.contains("when (clearPrecheck("))
        assertTrue(module.contains("vaultNoKey = stateNow is NativeWalletVault.State.NoKey && vaultNow.keyRecordsAbsent()"))
    }
}
