package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Interruptions at each write point of the restore (REC, MNEM, MARK, COMMIT), and their resumes (E2 附加 .1; v3.3.1 window; 2026-11-17).
 * Each case: the old account is in place (window shape), the process stops at one write of the resume, the next launch resumes, and the old
 * sealed copy still opens to the original address. Then a second interruption during a later resume. Then an audit write fails after a rename.
 */
class WritePointInterruptTest {
    private val oldPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val newPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"

    @Before fun newLaunch() {
        NativeWalletVault.resetLaunchForTests()
    }

    private class VaultWrap(val inner: NativeTestWrap) : KeyWrap {
        override fun seal(aad: ByteArray, plain: ByteArray): ByteArray = inner.seal(aad, plain)
        override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = inner.open(aad, sealed)
        override fun deleteKey(): Boolean = inner.deleteKey()
    }

    private val oldKey by lazy { checkNotNull(MnemonicDerivation.deriveKey(oldPhrase)) }
    private val oldEoa by lazy { checkNotNull(WalletAddress.fromPrivateKey(oldKey)) }

    /**
     * The window before the restore, as the real flow leaves it: the write stopped right after the record (REC holds the partial new record).
     * The flow has moved every entry aside first, so the marker names all four and the resume must write all four back (each is a write point).
     * Returns the old bytes per fixed name.
     */
    private fun windowState(wrap: VaultWrap, files: NativeTestFiles): Map<String, ByteArray> {
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(oldEoa, oldKey, oldPhrase))
        val names = listOf(NativeWalletVault.REC, NativeWalletVault.MNEM, NativeWalletVault.MARK, NativeWalletVault.COMMIT)
        val old = names.associateWith { files.map[it]!!.copyOf() }
        val newKey = checkNotNull(MnemonicDerivation.deriveKey(newPhrase))
        files.crashAfterWrite = NativeWalletVault.REC
        try {
            NativeWalletVault(wrap, files).syncPhrase(checkNotNull(WalletAddress.fromPrivateKey(newKey)), newKey, newPhrase)
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        return old
    }

    private fun digest(b: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    /** Asserts the old account is in place and the sealed old record opens to the original address (not a new one). */
    private fun assertOldAddressAndBytes(wrap: VaultWrap, files: NativeTestFiles, old: Map<String, ByteArray>) {
        old.forEach { (name, bytes) -> assertArrayEquals("$name is the old bytes", bytes, files.map[name]) }
        assertTrue("no pending marker", !files.map.containsKey(NativeWalletVault.PENDING))
        val state = NativeWalletVault(wrap, files).state()
        assertTrue("the vault is ready: $state", state is NativeWalletVault.State.Ready)
        assertEquals("the original address", oldEoa.lowercase(), (state as NativeWalletVault.State.Ready).eoa.lowercase())
    }

    // Interrupted at each write point of the resume: the next launch resumes and the old address is recovered.
    @Test fun interruptAtREC_resumesToTheOldAddress() = interruptAt(NativeWalletVault.REC)

    @Test fun interruptAtMNEM_resumesToTheOldAddress() = interruptAt(NativeWalletVault.MNEM)

    @Test fun interruptAtMARK_resumesToTheOldAddress() = interruptAt(NativeWalletVault.MARK)

    @Test fun interruptAtCOMMIT_resumesToTheOldAddress() = interruptAt(NativeWalletVault.COMMIT)

    private fun interruptAt(point: String) {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        val old = windowState(wrap, files)
        files.crashAfterWrite = point
        NativeWalletVault.resetLaunchForTests()
        try {
            NativeWalletVault(wrap, files).settleForWrite()
        } catch (_: NativeTestCrash) {
        }
        files.crashAfterWrite = null
        NativeWalletVault.resetLaunchForTests()
        assertTrue("resumed after an interruption at $point", NativeWalletVault(wrap, files).settleForWrite())
        assertOldAddressAndBytes(wrap, files, old)
    }

    // Interrupted again in a later resume (the second launch stops at a different write); the third launch reaches the old address.
    @Test fun interruptAgainAtAnotherPoint_thenResumes() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        val old = windowState(wrap, files)
        for (point in listOf(NativeWalletVault.REC, NativeWalletVault.COMMIT)) {
            files.crashAfterWrite = point
            NativeWalletVault.resetLaunchForTests()
            try {
                NativeWalletVault(wrap, files).settleForWrite()
            } catch (_: NativeTestCrash) {
            }
        }
        files.crashAfterWrite = null
        NativeWalletVault.resetLaunchForTests()
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertOldAddressAndBytes(wrap, files, old)
    }

    // An audit write fails during the resume: nothing is lost, the next launch resumes to the old address.
    @Test fun auditFailureDuringTheResume_resumesLaterToTheOldAddress() {
        val wrap = VaultWrap(NativeTestWrap()); val files = NativeTestFiles()
        val old = windowState(wrap, files)
        files.failWrite = NativeWalletVault.AUDIT
        NativeWalletVault.resetLaunchForTests()
        assertFalse(NativeWalletVault(wrap, files).settleForWrite())
        assertTrue("marker kept", files.map.containsKey(NativeWalletVault.PENDING))
        files.failWrite = null
        NativeWalletVault.resetLaunchForTests()
        assertTrue(NativeWalletVault(wrap, files).settleForWrite())
        assertOldAddressAndBytes(wrap, files, old)
    }
}
