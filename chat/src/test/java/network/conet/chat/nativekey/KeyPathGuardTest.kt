package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
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
        }
        // `hasLocalSigner` is the one alias the owner approved for the application (§38): a @Deprecated delegate to
        // hasNativeSigner, in the broker only. The module never names it.
        assertFalse(module.contains("hasLocalSigner"))
        assertEquals(1, Regex("hasLocalSigner").findAll(broker).count())
        assertTrue(broker.contains("fun hasLocalSigner(): Boolean = hasNativeSigner()"))
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
        // The page-open decision (r3x) is shared with the vector harness: the module calls it, and the rules call the host.
        // r2.3 41(1): nativeImportOpen is no longer a bridge command, so the module does not call importOpen.
        assertFalse(module.contains("NativeOpenRules.importOpen("))
        assertTrue(module.contains("NativeOpenRules.accountCreateOpen("))
        val rules = File("src/main/java/network/conet/chat/nativekey/NativeOpenRules.kt").readText()
        assertTrue(rules.contains("NativeAccountCreateHost.open(reqId)"))
        assertTrue(module.contains("\"nativeAccountCreateOpen\" -> nativeAccountCreateOpenCommand(body)"))
        // The old reply codes are gone: no_key and locked are the answers.
        assertFalse(module.contains("native_key_missing"))
        assertFalse(module.contains("native_key_locked"))
        assertFalse(module.contains("native_key_unreadable"))
    }

    @Test
    fun noKeyGateRunsBeforeAnyDispatch() {
        // T-155: with no native record, the gate answers before a payload is read or a command runs.
        val gate = module.indexOf("NoKeyGate.route(type)")
        val dispatch = module.indexOf("dispatch(context, type, body)")
        assertTrue("gate call missing", gate >= 0)
        assertTrue("gate must come before dispatch", dispatch > gate)
        assertTrue(module.contains("NativeWalletVault.State.NoKey"))
    }

    @Test
    fun statusQueriesAnswerFromTheVaultStateInBothCases() {
        // AND-N4, AND-N5: walletStatus and passcodeStatus answer from the vault state, with or without a record.
        assertTrue(module.contains("NoKeyGate.walletStatusFor(statusGate, state, vaultForReason) {"))  // r2.5.17 31(3): the status gate, not the raw gate
        assertTrue(module.contains("BeamioShellRecordImport.flagsOf(context.applicationContext).accountAddress()"))
        // 0.2.28 follow-up (2026-11-20): passcodeStatus goes through the adoption guard, which answers from passcodeStatusFor(gate) once settled.
        assertTrue(module.contains("NoKeyGate.passcodeStatusWhileAdopting("))
    }

    @Test
    fun walletSigningRunsInNativeCodeNotInTheWebView() {
        // AND-K-c2, A-4: EIP-191, EIP-712 and the address use the native code; the host carries no wallet key.
        assertTrue(broker.contains("Eip191Signer.sign("))
        assertTrue(broker.contains("Eip712.signTypedData("))
        assertFalse(broker.contains("host."))
        assertFalse(broker.contains("BeamioOpenPgpHost"))
        val host = File("src/main/java/network/conet/chat/BeamioOpenPgpHost.kt").readText()
        assertFalse("WebView wallet key injection", host.contains("new ethers.Wallet("))
        assertFalse(host.contains("fun signEip191("))
        assertFalse(host.contains("fun signEip712("))
        assertFalse(host.contains("fun walletAddress("))
    }

    @Test
    fun pgpPrivateKeyIsNotHeldBySessionOrPgpStore() {
        // §36-B: the PGP private key lives in the native PGP record. The session does not hold it, and the PgpStore
        // never writes it.
        assertFalse(module.contains("var pgpPrivateKeyArmored"))
        assertFalse(module.contains("@Volatile var pgpPassphrase"))
        assertFalse(module.contains("s.pgpPrivateKeyArmored"))
        assertFalse(module.contains("kc.privateKeyArmor"))
        assertFalse(module.contains("pgp.privateKeyArmor"))
        val store = File("src/main/java/network/conet/chat/BeamioChatPgpStore.kt").readText()
        assertFalse(store.contains("putString(KEY_PRIVATE"))
        assertFalse(store.contains("hasUserPrivate"))
        assertFalse("C1: clearLegacyPrivateArmor is removed", store.contains("fun clearLegacyPrivateArmor("))
    }

    @Test
    fun initStoresAPgpKeyOnlyInTheNativeRecordAndIsMarkedForRemoval() {
        // The init fields are accepted until P-IMP-PGP is decided, then they are removed. Until then they go to the
        // native record only, after the wallet check.
        assertTrue(module.contains("storeInitPgp(ctx, reqId, s.eoa, pgpArmorInInit, pgpPassphraseInInit)"))
        // The record is the one of the account the init names (per-account records, §42).
        assertTrue(module.contains("NativeWallet.pgpFor(ctx, eoa).put(eoa, armor, passphrase)"))
        assertTrue(module.contains("P-IMP-PGP"))
    }

    @Test
    fun inboundDecryptionRunsInTheVaultAndTheWebViewHoldsNoPgpKey() {
        val listen = File("src/main/java/network/conet/chat/BeamioConetChatListenSession.kt").readText()
        assertTrue("inbound decrypt goes through the wallet (shipped armor first, then the vault)", listen.contains("NativeWallet.decryptInbound(app, armored)"))
        assertFalse(listen.contains("decryptInboundArmor"))
        val host = File("src/main/java/network/conet/chat/BeamioOpenPgpHost.kt").readText()
        assertFalse("WebView host still decrypts with a private key", host.contains("decryptInboundArmor"))
        assertFalse("WebView host still reads a private key", host.contains("openpgp.readPrivateKey"))
        assertFalse("WebView host still unlocks a key", host.contains("openpgp.decryptKey"))
        assertFalse("WebView host still takes an armor argument for a private key", host.contains("privateKeyArmor"))
    }

    @Test
    fun w2ToW4AreInProcessOnlyAndNotBridgeCommands() {
        // §25.37.4 補充 (r3al): W2, W3 and W4 are not bridge commands. They must not be dispatched from the bridge.
        for (cmd in listOf("deriveLocalKeys", "protocolKeys", "fragmentKeys")) {
            assertFalse("bridge dispatch for $cmd", module.contains("\"$cmd\" ->"))
        }
        assertTrue(module.contains("\"deriveSubkeys\" ->"))
    }

    @Test
    fun pgpIdentityCreateAnswersWaitingRegistrationAndWritesNothing() {
        // §25.37.4 b, §25.35.3: until the write path is approved, the bridge answers waiting_registration and writes no chain.
        assertTrue(module.contains("put(\"code\", \"waiting_registration\")"))
        assertFalse(module.contains("\"pgpIdentityCreate\" -> pgpIdentityCreateNotSupported"))
    }

    @Test
    fun identityPublicIsDecidedInItsHandlerBeforeTheTable() {
        // r3ae §25.48.2: the gate runs inside the handler, and the name is never on the allowed list.
        val handler = module.indexOf("identityPublicCommand(body)")
        val table = module.indexOf("NoKeyGate.route(type)")
        assertTrue("handler call missing", handler >= 0)
        assertTrue("handler must come before the table", handler < table)
        assertFalse(NoKeyGate.route("identityPublic") == NoKeyGate.Route.PASS)
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
        for (name in listOf("Bip39English.kt", "MnemonicDerivation.kt", "NativeImport.kt", "NoKeyGate.kt", "Eip712.kt", "Eip191Signer.kt", "NativePgp.kt", "NativePgpVault.kt", "NativeOpenRules.kt", "NativeAccountCreate.kt", "NativeDerivation.kt", "NativeDerivationCommands.kt", "IdentityPublic.kt")) {
            val src = File("src/main/java/network/conet/chat/nativekey/$name").readText()
            assertFalse("$name logs", src.contains("Log."))
            assertFalse("$name prints", src.contains("println"))
        }
    }
}
