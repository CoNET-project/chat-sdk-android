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

    @Test
    fun noKeyGateRunsBeforeAnyDispatch() {
        // T-155: with no native record, the gate answers before a payload is read or a command runs.
        val gate = module.indexOf("NoKeyGate.route(type)")
        val dispatch = module.indexOf("dispatch(type, body)")
        assertTrue("gate call missing", gate >= 0)
        assertTrue("gate must come before dispatch", dispatch > gate)
        assertTrue(module.contains("NativeWalletVault.State.NoKey"))
    }

    @Test
    fun statusQueriesAnswerFromTheVaultStateInBothCases() {
        // AND-N4, AND-N5: walletStatus and passcodeStatus answer from the vault state, with or without a record.
        assertTrue(module.contains("NoKeyGate.walletStatusOf(state)"))
        assertTrue(module.contains("NoKeyGate.passcodeStatusOf(state)"))
    }

    @Test
    fun legacyKeyIsAdoptedBeforeTheGate() {
        // An upgraded install whose first command is `init` must keep its wallet: the legacy key is adopted first.
        val adopt = module.indexOf("NativeWallet.migrateLegacy(context)")
        val gate = module.indexOf("NoKeyGate.route(type)")
        assertTrue("adoption call missing", adopt >= 0)
        assertTrue("adoption must come before the gate", adopt < gate)
    }

    @Test
    fun mnemonicAndGateCodeNeverLog() {
        // The phrase and the derived key must not reach the log (25.26.3, 25.22.5).
        for (name in listOf("Bip39English.kt", "MnemonicDerivation.kt", "NativeImport.kt", "NoKeyGate.kt")) {
            val src = File("src/main/java/network/conet/chat/nativekey/$name").readText()
            assertFalse("$name logs", src.contains("Log."))
            assertFalse("$name prints", src.contains("println"))
        }
    }
}
