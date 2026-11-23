package network.conet.chat.nativekey

import network.conet.chat.BeamioConetChatProtocol
import network.conet.chat.BuildConfig
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * walletCredential on the window channel (spec 25.52Y.38 第 2、3、4、6 项; 25.52Y.44). The SDK's own declaration is checked
 * first; a build that does not declare wallet.credential.v1 answers not_trusted without reading the vault. The phrase is answered with a
 * hardware-wrapped blob that unseals only for its account. A key-only account is unavailable (W-L5). No eoaPrivateKey, no PGP.
 */
class WalletCredentialBridgeTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
    private val otherPhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    private val otherEoa = MnemonicDerivation.deriveKey(otherPhrase)!!.let { WalletAddress.fromPrivateKey(it) }!!

    private fun phraseVault(): NativeWalletVault {
        val v = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        v.importMnemonicKey(eoa, MnemonicDerivation.deriveKey(phrase)!!, phrase)
        return v
    }

    private fun keyOnlyVault(): NativeWalletVault {
        val v = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        v.importKey(eoa, MnemonicDerivation.deriveKey(phrase)!!)
        return v
    }

    private fun request(extra: Map<String, Any> = emptyMap()): JSONObject {
        val b = JSONObject().put("type", "walletCredential").put("reqId", "w1")
        for ((k, v) in extra) b.put(k, v)
        return b
    }

    private fun answer(v: NativeWalletVault, body: JSONObject, declared: Boolean = true, gate: NoKeyGate.Gate = NoKeyGate.Gate.G1): JSONObject =
        WalletCredentialBridge.answer(declared, body) { v to gate }

    private fun errorOf(r: JSONObject) = r.getString("error")

    /** Not declared (a non-QA build): not_trusted, and the vault is never read. */
    @Test
    fun aBuildThatDoesNotDeclareTheCapabilityAnswersNotTrustedWithoutReadingTheVault() {
        val r = WalletCredentialBridge.answer(declared = false, body = request()) {
            throw AssertionError("the vault must not be read when the capability is not declared")
        }
        assertEquals("not_trusted", errorOf(r))
        assertFalse(r.getBoolean("ok"))
    }

    /** Declared, with a phrase account: the phrase and a blob, the eoa, and no key field. */
    @Test
    fun aDeclaredRequestReturnsThePhraseAndABlobForAPhraseAccount() {
        val r = answer(phraseVault(), request())
        assertTrue(r.getBoolean("ok"))
        val result = r.getJSONObject("result")
        assertEquals(eoa, result.getString("eoa"))
        assertEquals("mnemonic", result.getString("credentialKind"))
        assertEquals(phrase, result.getString("mnemonic"))
        assertTrue(result.getString("blob").isNotEmpty())
        assertFalse("no eoaPrivateKey in the answer", result.has("eoaPrivateKey"))
    }

    /** The blob unseals (mode unseal) to the phrase of the same account. */
    @Test
    fun theBlobUnsealsToThePhraseOfTheSameAccount() {
        val v = phraseVault()
        val blob = (answer(v, request()).getJSONObject("result")).getString("blob")
        val r = answer(v, request(mapOf("mode" to "unseal", "blob" to blob)))
        assertTrue(r.getBoolean("ok"))
        assertEquals(phrase, r.getJSONObject("result").getString("mnemonic"))
        assertEquals(eoa, r.getJSONObject("result").getString("eoa"))
    }

    /** A blob sealed for another account does not unseal here (the AAD binds the account). */
    @Test
    fun aBlobForAnotherAccountDoesNotUnseal() {
        val v = phraseVault()
        val foreign = v.sealBlob(otherEoa, otherPhrase.toByteArray(Charsets.UTF_8))!!
        assertEquals("unavailable", errorOf(answer(v, request(mapOf("mode" to "unseal", "blob" to foreign)))))
    }

    /** A key-only account (W-L5): unavailable, with no blob and no key. */
    @Test
    fun aKeyOnlyAccountIsUnavailableWithNoKeyOrBlob() {
        assertEquals("unavailable", errorOf(answer(keyOnlyVault(), request())))
    }

    /** A key-named field is refused by name, and no value is echoed. */
    @Test
    fun aKeyNamedFieldIsKeyOverBridgeRefused() {
        assertEquals("key_over_bridge_refused", errorOf(answer(phraseVault(), request(mapOf("eoaPrivateKey" to "0x00")))))
        assertEquals("key_over_bridge_refused", errorOf(answer(phraseVault(), request(mapOf("mnemonic" to "abandon")))))
    }

    /** The request shape: an extra name, a bad mode, an unseal without a blob, or a blob without unseal, is bad_request. */
    @Test
    fun aMalformedRequestIsBadRequest() {
        val v = phraseVault()
        assertEquals("bad_request", errorOf(answer(v, request(mapOf("note" to "x")))))
        assertEquals("bad_request", errorOf(answer(v, request(mapOf("mode" to "other")))))
        assertEquals("bad_request", errorOf(answer(v, request(mapOf("mode" to "unseal")))))
        assertEquals("bad_request", errorOf(answer(v, request(mapOf("blob" to "00")))))
    }

    /** G0 (no record) is no_key. */
    @Test
    fun g0IsNoKey() {
        val v = NativeWalletVault(NativeTestWrap(), NativeTestFiles())
        assertEquals("no_key", errorOf(answer(v, request(), gate = NoKeyGate.Gate.G0)))
    }

    /** The bridge: an undeclared build answers not_trusted; a declared build answers the phrase; the name is on the window channel only. */
    @Test
    fun theWindowBridgeRoutesWalletCredentialBehindTheDeclaration() {
        val v = phraseVault()
        val undeclared = ShellRecordBridge(
            account = { ShellRecordAccount.NotReady }, migrating = { false }, outcome = { null },
            walletCredential = { v to NoKeyGate.Gate.G1 }, walletCredentialDeclared = false,
        ).handle(ShellOrigin.EMBEDDED_PAGE, request(), 64)
        assertEquals("not_trusted", errorOf(undeclared))
        val declared = ShellRecordBridge(
            account = { ShellRecordAccount.NotReady }, migrating = { false }, outcome = { null },
            walletCredential = { v to NoKeyGate.Gate.G1 }, walletCredentialDeclared = true,
        ).handle(ShellOrigin.EMBEDDED_PAGE, request(), 64)
        assertEquals(phrase, declared.getJSONObject("result").getString("mnemonic"))
        assertFalse(network.conet.chat.BridgeCommandTable.isRegistered("walletCredential"))
        assertTrue("walletCredential" in network.conet.chat.BridgeCommandTable.WINDOW_CHANNEL)
    }

    /** The SDK declares wallet.credential.v1 exactly when this build is a QA build (-PchatWalletCredentialQa=true). */
    @Test
    fun theCapabilityIsDeclaredOnlyInAQaBuild() {
        assertEquals(BuildConfig.WALLET_CREDENTIAL_QA, BeamioConetChatProtocol.CAPABILITIES.contains("wallet.credential.v1"))
        assertEquals(BuildConfig.WALLET_CREDENTIAL_QA, WalletCredentialBridge.sdkDeclares())
    }
}
