package network.conet.chat

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import network.conet.chat.nativekey.BeamioShellRecordImport
import network.conet.chat.nativekey.ClearFlagFiles
import network.conet.chat.nativekey.LegacyWalletRecord
import network.conet.chat.nativekey.ShellImportCode
import network.conet.chat.nativekey.pageRecordFiles
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

/**
 * the kept legacy wallet key (BeamioChatWalletKeyStore) is never adopted as the current identity after an identity clear. With
 * the identity_cleared marker set, the first-run import answers absent, creates no page copy, and leaves the legacy wallet bytes unchanged.
 * Synthetic values only; digests are logged, never values. Runs on a task-dedicated emulator only (S25 is never a target).
 */
@RunWith(AndroidJUnit4::class)
class IdentityClearLegacyNotAdoptedTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val account = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"

    private fun walletPrefsFile() = File(context.applicationInfo.dataDir, "shared_prefs/beamio_chat_wallet_v1.xml")
    private fun sha(f: File): String = MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

    @Test
    fun aKeptLegacyWalletIsNotAdoptedAfterTheIdentityClear() {
        // The shipped wallet copy is kept by the clear (its bytes are the reference).
        assertTrue("seed the shipped wallet copy", context.getSharedPreferences("beamio_chat_wallet_v1", Context.MODE_PRIVATE).edit()
            .putString("eoa", account).putString("iv", "SYNTHETIC-IV").putString("ct", "SYNTHETIC-CT").commit())
        assertTrue("the wallet copy file exists", walletPrefsFile().isFile)
        val before = sha(walletPrefsFile())
        // The identity_cleared marker (set by the identity clear on ok).
        assertTrue("the identity_cleared marker is set", ClearFlagFiles(pageRecordFiles(context)).setIdentityCleared())
        assertTrue("the marker is read back", ClearFlagFiles(pageRecordFiles(context)).identityCleared())

        // The first-run import is given the kept copy as a Found record: it must not adopt it.
        val answer = BeamioShellRecordImport.runFirstImport(context, account, LegacyWalletRecord.Found("{}".toByteArray()), null)
        assertEquals("the kept wallet copy is answered absent", ShellImportCode.ABSENT, answer)
        assertNull("no page copy is created from the kept wallet copy", BeamioShellRecordImport.storeFor(context, account).read())
        val copies = pageRecordFiles(context).names().filter { it.startsWith("page.v1.") }
        assertTrue("no page copy file exists: $copies", copies.isEmpty())
        assertEquals("the kept wallet copy bytes are unchanged", before, sha(walletPrefsFile()))
    }
}
