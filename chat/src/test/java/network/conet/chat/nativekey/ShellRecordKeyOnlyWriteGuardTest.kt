package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * AK-37 (option 1): the page write guard counts a mnemonic account (and an unreadable phrase record) only. A key-only
 * account (private key or address, no phrase) does not make the write answer migrating. The creation transaction stays exempt.
 * The identity clear / unregister key-only refusal is a separate criterion and is covered by KeyOnlyPerAccountTest.
 */
class ShellRecordKeyOnlyWriteGuardTest {
    private val eoa = DerivedAccount.ADDRESS

    /** A device that has not established an account pointer: nothing else holds the write back. */
    private object NoPointerFlags : DeviceFlags {
        override fun accountPointer(): Boolean = false
        override fun setAccountPointer() = Unit
        override fun accountAddress(): String? = null
        override fun setAccountAddress(eoa: String) = Unit
        override fun legacyUnreadable(): Boolean = false
        override fun setLegacyUnreadable() = Unit
        override fun clearLegacyUnreadable() = Unit
    }

    private fun write(account: (SealedPageRecordStore) -> ShellRecordAccount, creation: Boolean = false): JSONObject {
        val store = SealedPageRecordStore(NativeTestWrap(), NativeTestFiles(), "$eoa:default")
        val bridge = ShellRecordBridge(
            account = { account(store) },
            migrating = { false },
            outcome = { ImportOutcome.ABSENT },
            flags = NoPointerFlags,
            creationMode = { creation },
            explicitChoice = { creation },
        )
        val body = JSONObject().put("type", "shellRecordWrite").put("reqId", "ak37")
            .put("record", JSONObject().put("rev", 0).put("schemaVersion", 2))
        return bridge.handle(ShellOrigin.EMBEDDED_PAGE, body, 300)
    }

    private fun codeOf(r: JSONObject): String = (r.optJSONObject("result") ?: r).optString("code", r.optString("code", ""))

    /** AK-37 (new): a key-only account holding a key with no phrase does not block the write. */
    @Test
    fun aKeyOnlyAccountDoesNotMakeThePageWriteMigrating() {
        val r = write({ ShellRecordAccount.Ready(it, eoa, nativeKeyPresent = true, mnemonicHeld = false) })
        assertNotEquals("migrating", codeOf(r))
        // The guard passes; the next check (the record carries no wallet fields) answers. Not migrating is the point.
        assertEquals("wallet_fields_missing", codeOf(r))
    }

    /** Control (v3.1): a mnemonic account with a residual key and no page copy still answers migrating. */
    @Test
    fun aMnemonicAccountWithAResidualKeyStillAnswersMigrating() {
        val r = write({ ShellRecordAccount.Ready(it, eoa, nativeKeyPresent = true, mnemonicHeld = true) })
        assertEquals("migrating", codeOf(r))
        // The default (mnemonicHeld follows nativeKeyPresent) keeps the older callers' behavior.
        assertEquals("migrating", codeOf(write({ ShellRecordAccount.Ready(it, eoa, nativeKeyPresent = true) })))
    }

    /** The creation transaction is exempt either way. */
    @Test
    fun theCreationTransactionIsStillExempt() {
        assertEquals("wallet_fields_missing", codeOf(write({ ShellRecordAccount.Ready(it, eoa, nativeKeyPresent = true, mnemonicHeld = true) }, creation = true)))
    }

    /** Fail closed: a held key whose phrase record cannot be read is not a Ready account; the write answers migrating. */
    @Test
    fun anUnreadablePhraseRecordStillFailsClosed() {
        assertEquals("migrating", codeOf(write({ ShellRecordAccount.NeedsRecovery })))
        assertEquals("migrating", codeOf(write({ ShellRecordAccount.Unreadable })))
    }

    /** No key at all: unchanged (no account, no record: migrating, never ok). */
    @Test
    fun noKeyAtAllStaysMigratingBecauseThereIsNoAccount() {
        assertEquals("migrating", codeOf(write({ ShellRecordAccount.Unknown })))
    }
}
