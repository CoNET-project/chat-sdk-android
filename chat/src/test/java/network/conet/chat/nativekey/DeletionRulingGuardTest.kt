package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Static guards of (delete paths, section 1): the published PGP store and the shipped wallet key are never removed; the migration
 * records and the migration wallet are not removed; the identity clear does not remove the inbox; the removed methods are not in the main source.
 * A byte-digest check before and after the identity clear needs the Android runtime (the shared preferences and the inbox file); it is not run here.
 */
class DeletionRulingGuardTest {

    private val main = "src/main/java/network/conet/chat"
    private val module = File("$main/BeamioConetChatModule.kt").readText(Charsets.UTF_8)

    @Test
    fun theRemovedMethodsAreNotInTheMainSource() {
        val all = listOf("BeamioChatPgpStore.kt", "BeamioChatWalletKeyStore.kt", "nativekey/AccountCleanupStores.kt")
            .joinToString("\n") { File("$main/$it").readText(Charsets.UTF_8) }
        assertFalse("C1: BeamioChatPgpStore.clear is removed", all.contains("fun clear(context: Context) {"))
        assertFalse("C1: clearLegacyPrivateArmor is removed", all.contains("fun clearLegacyPrivateArmor("))
        assertFalse("B4: clearKeepingLegacy is removed", all.contains("fun clearKeepingLegacy("))
        assertFalse("C2: BeamioChatWalletKeyStore.clear is removed", all.contains("fun clear(context: Context): Boolean {"))
        assertFalse("C3: BeamioChatWalletKeyStore.clearRecord is removed", all.contains("fun clearRecord("))
        assertFalse("C4: SingleRecordCleanup is removed", all.contains("class SingleRecordCleanup("))
        assertFalse("C4: clearLegacyRecord is removed", all.contains("fun clearLegacyRecord("))
    }

    @Test
    fun theIdentityClearKeepsThePublishedStoresAndTheInbox() {
        assertFalse("B4: the identity clear never calls clearKeepingLegacy", module.contains("clearKeepingLegacy"))
        assertFalse("B6: the identity clear never clears the inbox", module.contains("BeamioConetChatInboxStore.clear("))
        assertTrue("B6: the inbox is kept (eraseInbox answers true)", module.contains("eraseInbox = { true }"))
        assertTrue("B4: the PGP store step is kept", module.contains("val pgpOk = true"))
        assertTrue("B5: the migration records are kept", module.contains("val migrationRecordsOk = true"))
        assertTrue("B5: the migration wallet is kept", module.contains("val migrationWalletOk = true"))
        assertTrue("the shipped wallet key is kept", module.contains("val keystoreOk = true"))
    }

    /** mnemonic_sets_v1 is kept in every clear path; identity clear and accountCleanupOld never delete it. */
    @Test
    fun theMnemonicSetStoreIsNeverDeletedByTheClearPaths() {
        val idStart = module.indexOf("private fun identityClear(")
        val identityClear = module.substring(idStart, module.indexOf("\n    }\n", idStart))
        // Writing the identity_cleared marker is allowed; deleting or otherwise touching the store directory is not.
        val storeRefs = Regex("MnemonicSetStore\\(").findAll(identityClear).count()
        val markerRefs = Regex("markIdentityCleared\\(").findAll(identityClear).count()
        assertEquals("identity clear touches the set store only to write the marker", storeRefs, markerRefs)
        assertFalse("identity clear never names the set store directory name", identityClear.contains("mnemonic_sets_v1"))
        assertFalse("identity clear never deletes recursively", identityClear.contains("deleteRecursively"))
        val cleanupFiles = listOf("nativekey/AccountCleanupWiring.kt", "nativekey/AccountCleanup.kt", "nativekey/AccountCleanupStores.kt")
        for (f in cleanupFiles) {
            val text = File("$main/$f").readText(Charsets.UTF_8)
            assertFalse("$f never names the set store", text.contains("MnemonicSetStore") || text.contains("mnemonic_sets_v1"))
            assertFalse("$f never deletes recursively", text.contains("deleteRecursively"))
        }
        val accountCleanupCommand = module.substring(module.indexOf("private fun accountCleanupRunFor("), module.indexOf("private fun accountCleanupRunFor(") + 3000)
        assertFalse("accountCleanupOld does not name the set store", accountCleanupCommand.contains("MnemonicSetStore"))
    }

    @Test
    fun theOrphanSweepRemovesNoMigrationRecord() {
        val start = module.indexOf("private fun sweepOrphanMigrations(")
        val body = module.substring(start, module.indexOf("\n    }\n", start))
        assertFalse("B5: the orphan sweep never calls clearMigrationRecords", body.contains("clearMigrationRecords"))
        assertTrue("B5: the orphan sweep answers true", body.contains("return true"))
    }
}
