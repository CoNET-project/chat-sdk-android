package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * Every unreadable read on the PGP, migration, backup-flag and create-gate paths is unknown (25.52Y.84, Y.104 第 3 条): it throws, or it counts as
 * present, or it is not confirmed; it never becomes a confirmed none, an absent record or a success. Temporary-free, in-memory only.
 */
class UnknownAnswerTest {
    private val account = "0x2222222222222222222222222222222222222222"

    /** A store whose reads of the names selected by [fails] throw, as a store that cannot be read does. */
    private class FailingReads(private val inner: VaultFiles, private val fails: (String) -> Boolean) : VaultFiles {
        override fun read(name: String): ByteArray? = if (fails(name)) throw IOException("store unreadable") else inner.read(name)

        override fun write(name: String, bytes: ByteArray) = inner.write(name, bytes)

        override fun delete(name: String) = inner.delete(name)
    }

    /** The native PGP vault: an unreadable record or marker throws from state(), and hasRecord() counts it as present (never absent). */
    @Test
    fun nativePgpVaultStateThrowsWhenTheRecordCannotBeRead() {
        val files = FailingReads(NativeTestFiles()) { it.endsWith(".rec") }
        val vault = NativePgpVault(NativeTestWrap(), files, account, NativePgpVault.Slot.ACTIVE)

        assertThrows(IOException::class.java) { vault.state() }
    }

    @Test
    fun nativePgpVaultStateThrowsWhenTheMarkerCannotBeRead() {
        val files = FailingReads(NativeTestFiles()) { it.endsWith(".ok") }
        val vault = NativePgpVault(NativeTestWrap(), files, account, NativePgpVault.Slot.ACTIVE)

        assertThrows(IOException::class.java) { vault.state() }
    }

    @Test
    fun nativePgpVaultHasRecordCountsAnUnreadableRecordAsPresent() {
        val files = FailingReads(NativeTestFiles()) { it.endsWith(".rec") }
        val vault = NativePgpVault(NativeTestWrap(), files, account, NativePgpVault.Slot.ACTIVE)

        assertTrue("unknown is present, never absent", vault.hasRecord())
    }

    /**
     * The migration's last code: an unreadable last code throws from the migration state. It is not taken for an absent code, so the state is never
     * "none" or "pending" on an unknown read.
     */
    @Test
    fun migrationStateThrowsOnAnUnreadableLastCode() {
        val files = FailingReads(NativeTestFiles()) { it == lastCodeFileName() }
        val engine = migrationEngine(files, NativeTestWrap(), null, ChainAnswer.Absent)

        assertThrows(IOException::class.java) { engine.state() }
    }

    /** The recovery-backup flag is confirmed only on a successful read-back: a read-back that throws is not confirmed (the write is not complete). */
    @Test
    fun aBackupFlagWhoseReadBackFailsIsNotConfirmed() {
        val eoa = "0x2222222222222222222222222222222222222222"
        val files = FailingReads(NativeTestFiles()) { it == ClearFlagFiles.backupFlagName(eoa) }

        assertFalse(ClearFlagFiles(files).setRecoveryBackupConfirmed(eoa))
    }

    /** The create gate with an unreadable legacy report refuses (migrating): the same refusal as a report that is not "absent", never a create. */
    @Test
    fun aCreateGateWithAnUnreadableLegacyReportRefuses() {
        val unreadable = CreateGuardInputs(
            key = KeyState.NONE,
            legacyReport = null,
            legacyUnreadable = false,
            pointer = false,
            pageCopy = false,
            migrating = false,
        )
        val refusal = AccountCreateGuard.denial(unreadable)

        assertNotNull("an unreadable report never allows a create", refusal)
        assertEquals(AccountCreateGuard.denial(unreadable.copy(migrating = true)), refusal)
    }

    /**
     * The window-channel walletEoaAddress answer (25.52Y.42 第 5 项 (c)): an unreadable vault is one ack with error not_ready, never an exception out of
     * the bridge (25.52Y.84). The vault is a real vault whose record read throws.
     */
    @Test
    fun walletEoaAddressIsNotReadyOnAnUnreadableVaultWithOneAck() {
        val files = FailingReads(NativeTestFiles()) { it == NativeWalletVault.REC }
        val vault = NativeWalletVault(NativeTestWrap(), files)
        val body = org.json.JSONObject().put("type", WalletEoaAddressBridge.NAME).put("reqId", "w1")

        val ack = WalletEoaAddressBridge.answer(originAllowed = true, body = body) { vault to NoKeyGate.Gate.G2 }

        assertEquals("w1", ack.getString("reqId"))
        assertFalse(ack.getBoolean("ok"))
        assertEquals("not_ready", ack.getString("error"))
    }
}
