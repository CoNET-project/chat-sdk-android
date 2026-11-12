package network.conet.chat.nativekey

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source guard for the R5 cut-over (spec 25.20.2 R5). The module cannot run on the JVM (Android Context),
 * so these checks read its source. They do not replace device acceptance.
 */
class KeyPathGuardTest {
    private val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
    private val broker = File("src/main/java/network/conet/chat/BeamioConetChatSignBroker.kt").readText()

    @Test
    fun noSetLocalSignerRemainsInTheModuleOrBroker() {
        for (src in listOf(module, broker)) {
            assertFalse(src.contains("setLocalSigner"))
            assertFalse(src.contains("clearLocalSigner"))
            assertFalse(src.contains("hasLocalSigner"))
        }
    }

    @Test
    fun theModuleReadsNoWalletKeyFromThePayload() {
        assertFalse(module.contains("optString(\"privateKeyHex\""))
        assertFalse(module.contains("optString(\"walletPrivateKey\""))
    }

    @Test
    fun theModuleNoLongerWritesThePreUpgradeKeyStore() {
        assertFalse(module.contains("BeamioChatWalletKeyStore.save("))
    }

    @Test
    fun x21CommandsAreRefusedNotRouted() {
        assertTrue(module.contains("network.conet.chat.x21.X21Retired.ERROR"))
        assertFalse(module.contains("WalletTransferBridge"))
    }

    @Test
    fun walletCommandsAnswerFromTheNativeVaultOnly() {
        assertTrue(module.contains("NativeWalletCommands.walletAddress("))
        assertTrue(module.contains("NativeMessageSigner.sign("))
        assertTrue(module.contains("NativeImportHost.open()"))
        // The old reply codes are gone: no_key and locked are the answers.
        assertFalse(module.contains("native_key_missing"))
        assertFalse(module.contains("native_key_locked"))
        assertFalse(module.contains("native_key_unreadable"))
    }
}
