package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

/**
 * The native account answers under the failures the PWA's onboarding rule depends on (Y.104 project ruling, 2026-11-16): a read that fails, a
 * Keystore that is locked or unavailable, a record that cannot be read, and a record that is missing only partly must never answer `no_key` with
 * `kPresent` false (confirmed none). Each case below pins what the vault and the gate answer. Temporary directories and in-memory fakes only.
 */
class NativeUnknownStateTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val keyA = ByteArray(32).also { it[31] = 1 }
    private val eoaA = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"

    /** A wrapping key whose opening fails, as an unavailable or locked Keystore does. */
    private class UnavailableWrap : KeyWrap {
        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray = throw IllegalStateException("keystore unavailable")

        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = throw IllegalStateException("keystore locked")

        override fun deleteKey(): Boolean = false
    }

    /** A store whose reads of the key record fail, as a store that cannot be read does. */
    private class RecordReadFails(private val inner: VaultFiles) : VaultFiles {
        override fun read(name: String): ByteArray? = if (name == NativeWalletVault.REC) throw IOException("store unreadable") else inner.read(name)

        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)

        override fun delete(name: String) = inner.delete(name)
    }

    /** A present key record that the platform store cannot read is a read failure, never `no_key` (AndroidVaultFiles). */
    @Test
    fun aKeyRecordThatIsNotARegularFileIsAReadFailureNotNoKey() {
        val dir = tmp.root.resolve("native_wallet_v1").apply { mkdirs() }
        File(dir, NativeWalletVault.REC).mkdirs()
        val v = NativeWalletVault(NativeTestWrap(), AndroidVaultFiles(dir))

        assertThrows(IOException::class.java) { v.state() }
        assertNull("nothing is taken as the state", v.snapshotState())
    }

    /** A vault directory that exists but cannot be listed is a read failure, never an absent record. */
    @Test
    fun aVaultDirectoryThatCannotBeListedIsAReadFailureNotNoKey() {
        val dir = tmp.root.resolve("native_wallet_v1")
        dir.writeText("not a directory")
        val v = NativeWalletVault(NativeTestWrap(), AndroidVaultFiles(dir))

        assertThrows(IOException::class.java) { v.state() }
        assertNull(v.snapshotState())
    }

    /** A record that cannot be read at all makes the state unknown: the read throws, and the state is not taken. */
    @Test
    fun aRecordReadThatFailsIsUnknownNotNoKey() {
        val files = NativeTestFiles()
        NativeWalletVault(NativeTestWrap(), files).importKey(eoaA, keyA)
        val v = NativeWalletVault(NativeTestWrap(), RecordReadFails(files))

        assertThrows(IOException::class.java) { v.state() }
        assertNull(v.snapshotState())
    }

    /** A Keystore that is locked or unavailable makes an existing record Locked (unreadable), never NoKey. */
    @Test
    fun aKeystoreThatIsLockedOrUnavailableLocksTheRecordAsUnreadable() {
        val files = NativeTestFiles()
        NativeWalletVault(NativeTestWrap(), files).importKey(eoaA, keyA)

        val state = NativeWalletVault(UnavailableWrap(), files).state()

        assertTrue("locked, not no_key", state is NativeWalletVault.State.Locked)
        assertEquals("unreadable", (state as NativeWalletVault.State.Locked).reason)
    }

    /**
     * A commit record without the key record and without a phrase: every read completed, so it is confirmed none (no_key). Residues other than the
     * phrase do not block (project ruling 2026-11-16, urgent); a read that fails throws instead (see the tests above).
     */
    @Test
    fun aCommitWithoutTheKeyRecordAndWithoutAPhraseIsNoKeyByTheRuling() {
        val files = NativeTestFiles()
        files.map[NativeWalletVault.COMMIT] = "commit".toByteArray(Charsets.UTF_8)

        assertEquals(NativeWalletVault.State.NoKey, NativeWalletVault(NativeTestWrap(), files).state())
    }

    /** Only a vault with no record at all, read successfully, is NoKey (the one confirmed-absent state the gate maps to G0). */
    @Test
    fun aVaultWithNothingOnDiskIsTheOnlyNoKey() {
        val dir = tmp.root.resolve("native_wallet_v1")
        val state = NativeWalletVault(NativeTestWrap(), AndroidVaultFiles(dir)).state()

        assertEquals(NativeWalletVault.State.NoKey, state)
        assertEquals(NoKeyGate.Gate.G0, NoKeyGate.gateOf(state, sessionReady = false))
    }

    /** Every non-NoKey state answers `not_ready` with an unreadable reason, never `no_key`, at the gate. */
    @Test
    fun everyUnknownStateAnswersNotReadyNeverNoKeyAtTheGate() {
        val unknown = listOf(
            NativeWalletVault.State.Locked("unreadable"),
            NativeWalletVault.State.Locked("record_missing"),
            NativeWalletVault.State.Locked("marker_missing"),
        )
        for (state in unknown) {
            for (ready in listOf(false, true)) {
                val gate = NoKeyGate.gateOf(state, sessionReady = ready)
                assertFalse("not G0 for $state", gate == NoKeyGate.Gate.G0)
                assertFalse("no_key never answered for $state", NoKeyGate.walletStatusFor(gate, state).optString("status") == "no_key")
            }
        }
    }

    /** A missing PGP record does not change the account answer: the vault decides it alone. */
    @Test
    fun aMissingPgpRecordDoesNotMakeTheAccountAbsent() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        NativeWalletVault(wrap, files).importKey(eoaA, keyA)
        assertFalse(files.map.keys.any { it.startsWith("pgp.v1.") })

        val state = NativeWalletVault(wrap, files).state()

        assertEquals(NativeWalletVault.State.Ready::class.java, state.javaClass)
        assertEquals(eoaA, (state as NativeWalletVault.State.Ready).eoa)
    }

    /**
     * A vault entry that cannot be stat-ed (permission denied) is unknown, not absent: the read throws and the state is not taken (Y.104 第 3 条,
     * Y.105 第 2 条). Skipped as root, where every permission check passes.
     */
    @Test
    fun aVaultEntryThatCannotBeStatedIsUnknownNotAbsent() {
        val dir = tmp.root.resolve("native_wallet_v1").apply { mkdirs() }
        org.junit.Assume.assumeTrue("permission checks need a non-root process", System.getProperty("user.name") != "root")
        assertTrue(dir.setExecutable(false))
        try {
            val files = AndroidVaultFiles(dir)
            assertThrows(IOException::class.java) { files.read(NativeWalletVault.REC) }
            assertThrows(IOException::class.java) { NativeWalletVault(NativeTestWrap(), files).state() }
        } finally {
            dir.setExecutable(true)
        }
    }

    /** A missing entry in a readable directory is absent: the one case that reads as no record. */
    @Test
    fun aMissingEntryInAReadableDirectoryIsAbsent() {
        val dir = tmp.root.resolve("native_wallet_v1").apply { mkdirs() }
        assertNull(AndroidVaultFiles(dir).read(NativeWalletVault.REC))
    }
}
