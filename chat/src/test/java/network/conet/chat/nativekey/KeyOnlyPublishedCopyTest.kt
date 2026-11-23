package network.conet.chat.nativekey

import network.conet.chat.BeamioChatWalletKeyStore
import network.conet.chat.nativekey.NativeWalletVault.PublishedWalletCopy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

/**
 * remaining item (clarification 2026-11-22: the published copy `beamio_chat_wallet_v1`): the copy counts as a key-only source.
 * Three observations: present, absent, unreadable (unknown, refuses, retryable). The copy is only observed: the criterion writes and removes nothing.
 * Synthetic values only.
 */
class KeyOnlyPublishedCopyTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val wrap = NativeTestWrap()
    private val fogPhrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
    private fun keyOf(p: String) = checkNotNull(MnemonicDerivation.deriveKey(p))
    private fun eoaOf(p: String) = checkNotNull(WalletAddress.fromPrivateKey(keyOf(p))).lowercase()
    private fun store() = MnemonicSetStore(File(tmp.root, MnemonicSetStore.DIRECTORY))

    // --- classification of the published copy (read of the ciphertext field only) ---

    @Test
    fun presentCopyIsPresent() {
        assertEquals(PublishedWalletCopy.Present, BeamioChatWalletKeyStore.classifyPublishedCopy({ "c3ludGhldGljLWNpcGhlcnRleHQ=" }))
    }

    @Test
    fun missingCopyIsAbsent() {
        assertEquals(PublishedWalletCopy.Absent, BeamioChatWalletKeyStore.classifyPublishedCopy({ "" }))
    }

    @Test
    fun unreadableCopyIsUnknownNotAbsent() {
        assertEquals(PublishedWalletCopy.Unknown, BeamioChatWalletKeyStore.classifyPublishedCopy({ throw IOException("read fault") }))
        assertEquals(PublishedWalletCopy.Unknown, BeamioChatWalletKeyStore.classifyPublishedCopy({ throw ClassCastException("bad type") }))
    }

    // --- effect on the criterion ---

    /** Present: only the copy, no vault record, no phrase set at all: refused; every byte unchanged. */
    @Test
    fun onlyThePublishedCopyWithNoPhraseSetIsKeyOnlyAndNothingChanges() {
        val files = NativeTestFiles()
        val before = files.map.toMap()
        val vault = NativeWalletVault(wrap, files)
        for (who in listOf(null, eoaOf(fogPhrase))) {
            assertTrue("copy present, no phrase: refused (account=$who)",
                keyOnlyClearRefused(vault.keyWithoutPhraseFor(who, store(), PublishedWalletCopy.Present), PendingOwner.Absent, who))
        }
        assertEquals("nothing is written or deleted", before, files.map.toMap())
        assertFalse("no phrase set was created", File(tmp.root, MnemonicSetStore.DIRECTORY).exists())
    }

    /** Absent: nothing on the device, the criterion adds nothing (default and explicit). */
    @Test
    fun noCopyAndNoKeyIsNotKeyOnly() {
        val vault = NativeWalletVault(wrap, NativeTestFiles())
        assertFalse(vault.keyWithoutPhraseFor(null, store()))
        assertFalse(vault.keyWithoutPhraseFor(eoaOf(fogPhrase), store(), PublishedWalletCopy.Absent))
    }

    /** Unknown: refuses in every state, even with a valid phrase; it only refuses, nothing is changed. */
    @Test
    fun anUnreadableCopyRefusesAndNothingChanges() {
        val files = NativeTestFiles()
        val a = eoaOf(fogPhrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(a, keyOf(fogPhrase), fogPhrase))
        val before = files.map.toMap()
        val vault = NativeWalletVault(wrap, files)
        assertTrue(keyOnlyClearRefused(vault.keyWithoutPhraseFor(a, store(), PublishedWalletCopy.Unknown), PendingOwner.Absent, a))
        assertTrue(keyOnlyClearRefused(vault.keyWithoutPhraseFor(null, store(), PublishedWalletCopy.Unknown), PendingOwner.Absent, null))
        assertEquals(before, files.map.toMap())
        // Retryable: once the copy reads, the same account with its phrase is no longer key-only.
        assertFalse(vault.keyWithoutPhraseFor(a, store(), PublishedWalletCopy.Absent))
    }

    /** A present copy does not block an account that has a valid phrase (per account). */
    @Test
    fun aPresentCopyDoesNotMakeAnAccountWithItsPhraseKeyOnly() {
        val files = NativeTestFiles()
        val a = eoaOf(fogPhrase)
        assertEquals(NativeWalletVault.Import.OK, NativeWalletVault(wrap, files).importMnemonicKey(a, keyOf(fogPhrase), fogPhrase))
        assertFalse(NativeWalletVault(wrap, files).keyWithoutPhraseFor(a, store(), PublishedWalletCopy.Present))
    }

    // --- P1 (P1): the backing file exists but the platform read it as empty ---

    private val emptyMapXml = "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map />\n".toByteArray()
    private fun fileSystem(vararg files: Pair<String, ByteArray>): (String) -> ByteArray? = { n -> files.toMap()[n] }

    @Test
    fun aCorruptFileReadAsEmptyIsUnknownNotAbsent() {
        val corrupt = "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map><string name=\"ct\">abc".toByteArray()
        assertEquals(PublishedWalletCopy.Unknown,
            BeamioChatWalletKeyStore.classifyPublishedCopy({ "" }, fileSystem("beamio_chat_wallet_v1.xml" to corrupt)))
        assertEquals(PublishedWalletCopy.Unknown,
            BeamioChatWalletKeyStore.classifyPublishedCopy({ "" }, fileSystem("beamio_chat_wallet_v1.xml" to ByteArray(40) { 0 })))
    }

    @Test
    fun aBakFileThatIsNotAnEmptyMapIsUnknown() {
        assertEquals(PublishedWalletCopy.Unknown,
            BeamioChatWalletKeyStore.classifyPublishedCopy({ "" }, fileSystem("beamio_chat_wallet_v1.xml.bak" to "<map><string name=\"eoa\">0x1</string></map>".toByteArray())))
    }

    @Test
    fun anExistingFileWithAnEmptyMapIsAbsent() {
        assertEquals(PublishedWalletCopy.Absent,
            BeamioChatWalletKeyStore.classifyPublishedCopy({ "" }, fileSystem("beamio_chat_wallet_v1.xml" to emptyMapXml)))
        assertEquals(PublishedWalletCopy.Absent,
            BeamioChatWalletKeyStore.classifyPublishedCopy({ "" }, fileSystem("beamio_chat_wallet_v1.xml" to "<map></map>".toByteArray())))
    }

    @Test
    fun noFileAtAllIsAbsent() {
        assertEquals(PublishedWalletCopy.Absent, BeamioChatWalletKeyStore.classifyPublishedCopy({ "" }, fileSystem()))
    }

    @Test
    fun aFileThatCannotBeReadIsUnknown() {
        assertEquals(PublishedWalletCopy.Unknown,
            BeamioChatWalletKeyStore.classifyPublishedCopy({ "" }, { throw IOException("read fault") }))
    }

    @Test
    fun aParsedCiphertextIsPresentWhateverTheFilesSay() {
        assertEquals(PublishedWalletCopy.Present,
            BeamioChatWalletKeyStore.classifyPublishedCopy({ "Y3Q=" }, fileSystem("beamio_chat_wallet_v1.xml" to emptyMapXml)))
    }

    /** The corrupt-file Unknown reaches the criterion: the clear is refused and every byte stays the same. */
    @Test
    fun aCorruptCopyOnAnOtherwiseEmptyDeviceRefusesTheClear() {
        val files = NativeTestFiles()
        val before = files.map.toMap()
        val state = BeamioChatWalletKeyStore.classifyPublishedCopy({ "" }, fileSystem("beamio_chat_wallet_v1.xml" to "<map><str".toByteArray()))
        assertTrue(keyOnlyClearRefused(NativeWalletVault(wrap, files).keyWithoutPhraseFor(null, store(), state), PendingOwner.Absent, null))
        assertEquals(before, files.map.toMap())
    }

    /** Source guard: the module passes the observation and never reads or removes the copy by the guarded calls. */
    @Test
    fun theModulePassesTheObservationToTheCriterion() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText(Charsets.UTF_8)
        assertTrue(module.contains("BeamioChatWalletKeyStore.publishedCopyState(context)"))
        val store = File("src/main/java/network/conet/chat/BeamioChatWalletKeyStore.kt").readText(Charsets.UTF_8)
        val body = store.substringAfter("fun publishedCopyState").substringBefore("fun load").ifEmpty { store.substringAfter("fun publishedCopyState") }
        assertFalse("the observation does not write", body.contains(".edit()") || body.contains(".remove(") || body.contains(".clear("))
    }
}
