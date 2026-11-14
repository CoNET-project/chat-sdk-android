package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The r3bq items (spec §25.52U, R439): an unread legacy store answers `migrating`; `needs_native_recovery` is judged against the matching
 * profile, and `account_mismatch` covers a schema 2 record with no matching profile; a readable record wins over the device marker and repairs
 * the empty pointer (§25.52U.5).
 */
class ShellRecordR439Test {
    private fun store(files: NativeTestFiles, record: JSONObject?): SealedPageRecordStore {
        val s = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        record?.let { s.write(it) }
        return s
    }

    private fun bridge(s: SealedPageRecordStore, outcome: ImportOutcome?, flags: DeviceFlags) = ShellRecordBridge(
        account = { ShellRecordAccount.Ready(s, ACCOUNT) },
        migrating = { false },
        outcome = { outcome },
        flags = flags,
    )

    private fun read(b: ShellRecordBridge): JSONObject =
        b.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r"), 40).v()

    private fun record(keyId: String, withKey: Boolean, schema: Int = 2): JSONObject {
        val profile = JSONObject().put("keyID", keyId)
        if (withKey) profile.put("privateKeyArmor", "EOA")
        return JSONObject().put("rev", 1).put("schemaVersion", schema).put("profiles", JSONArray().put(profile))
    }

    @Test
    fun aReadWithoutALegacyReadAnswersMigrating() {
        // §25.52U.3 (AK-18): nothing read yet, no pointer, no marker, no record: migrating, never the import_not_done of the old code.
        val files = NativeTestFiles()
        assertEquals("migrating", read(bridge(store(files, null), null, DeviceFlagFiles(files))).getString("code"))
    }

    @Test
    fun aReadableRecordClearsTheMarkerAndRepairsTheEmptyPointer() {
        // §25.52U.5 (AK-17): the record is the source of truth; the marker has no say, and the pointer is repaired.
        val files = NativeTestFiles()
        val flags = DeviceFlagFiles(files)
        flags.setLegacyUnreadable()
        val resp = read(bridge(store(files, record(ACCOUNT, withKey = true)), ImportOutcome.LEGACY_UNREADABLE, flags))
        assertEquals("ok", resp.getString("code"))
        assertFalse("the marker is cleared", flags.legacyUnreadable())
        assertTrue("the empty pointer is repaired", flags.accountPointer())
    }

    @Test
    fun aSchemaTwoRecordWithNoMatchingProfileIsAccountMismatch() {
        // §25.52U.4 (AK-19): the profile's keyID is another address: account_mismatch, fail closed, and no pointer repair.
        val files = NativeTestFiles()
        val flags = DeviceFlagFiles(files)
        val resp = read(bridge(store(files, record("0x4444444444444444444444444444444444444444", withKey = true)), ImportOutcome.DONE, flags))
        assertEquals("error", resp.getString("code"))
        assertEquals("account_mismatch", resp.getString("sub"))
        assertFalse(flags.accountPointer())
    }

    @Test
    fun aMatchingProfileWithoutTheKeyIsNeedsNativeRecovery() {
        val files = NativeTestFiles()
        val resp = read(bridge(store(files, record(ACCOUNT, withKey = false)), ImportOutcome.DONE, DeviceFlagFiles(files)))
        assertEquals("needs_native_recovery", resp.getString("sub"))
    }

    @Test
    fun aMissingMnemonicPhraseDoesNotMatter() {
        // §25.52R.5: the EOA key is what counts; a record with the key and no mnemonicPhrase reads as ok.
        val files = NativeTestFiles()
        assertEquals("ok", read(bridge(store(files, record(ACCOUNT, withKey = true)), ImportOutcome.DONE, DeviceFlagFiles(files))).getString("code"))
    }

    @Test
    fun aSchemaOneRecordIsNotJudgedByTheAccount() {
        // The judgement is for schema 2 records (§25.52S.3): a schema 1 copy reads as it is.
        val files = NativeTestFiles()
        assertEquals("ok", read(bridge(store(files, record("0x4444444444444444444444444444444444444444", withKey = false, schema = 1)), null, DeviceFlagFiles(files))).getString("code"))
    }

    @Test
    fun aMatchingKeyIdIsCaseInsensitive() {
        val files = NativeTestFiles()
        val mixed = record(ACCOUNT.uppercase().replaceFirst("0X", "0x"), withKey = true)
        assertEquals("ok", read(bridge(store(files, mixed), null, DeviceFlagFiles(files))).getString("code"))
    }

    @Test
    fun aWriteWithoutTheAccountKeyIsWalletFieldsMissing() {
        // §25.52U.4 (write side): after the merge no profile matching the account holds the key: wallet_fields_missing, nothing stored.
        val files = NativeTestFiles()
        val s = store(files, null)
        val resp = bridge(s, ImportOutcome.ABSENT, DeviceFlagFiles(files)).handle(
            ShellOrigin.EMBEDDED_PAGE,
            JSONObject()
                .put("type", "shellRecordWrite")
                .put("reqId", "w")
                .put("record", JSONObject().put("rev", 0).put("schemaVersion", 2).put("profiles", JSONArray().put(JSONObject().put("keyID", ACCOUNT).put("emailAddr", "a")))),
            200,
        ).v()
        assertEquals("wallet_fields_missing", resp.getString("code"))
        assertNull(s.read())
    }
}
