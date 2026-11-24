package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import java.io.File
import java.math.BigInteger
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * The BeamioTag and recover payload of a new account: the native layer signs and seals it in the format the PWA's `createRecover` writes, so
 * the existing restore opens it. Synthetic phrase and password only; no network and no production account.
 */
class AccountRegisterPayloadTest {
    private val random = SecureRandom()
    private val phraseText = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val phrase = phraseText.toByteArray(Charsets.UTF_8)
    private val key = MnemonicDerivation.deriveKey(phraseText)!!
    private val eoa = WalletAddress.fromPrivateKey(key)!!
    private val password = "correct horse".toByteArray(Charsets.UTF_8)

    /** Cheap, deterministic key derivation for most tests (the Argon2id one runs in its own test). */
    private val cheap: (ByteArray, RecoveryRecord.Stored) -> ByteArray = { p, s -> MessageDigest.getInstance("SHA-256").digest(p + s.salt) }

    private fun build(name: String = "qa.tag_1", pw: ByteArray = password, k: ByteArray = key, ph: ByteArray = phrase, kdf: (ByteArray, RecoveryRecord.Stored) -> ByteArray = cheap) =
        AccountRegisterPayload.build(name, pw, eoa, k, ph, random, kdf)

    private fun ok(b: AccountRegisterPayload.Built) = b as AccountRegisterPayload.Built.Ok

    @Test
    fun theChecksumFormMatchesTheEip55Vector() {
        assertEquals("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", AccountRegisterPayload.checksum("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"))
        assertEquals("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", AccountRegisterPayload.checksum("0xFB6916095CA1DF60BB79CE92CE3EA74C37C5D359"))
    }

    @Test
    fun theSignatureIsEip191OverTheLowerCaseWalletExactlyAsReturnedAndRecoversTheAccount() {
        val p = ok(build())
        // The server verifies checkSign(wallet, signMessage, wallet): the signed string is the wallet string as the page forwards it.
        assertEquals(eoa.lowercase(), p.wallet)
        val sig = ConetChatCryptoUtil.hexToBytes(p.signMessage.removePrefix("0x"))!!
        assertEquals(65, sig.size)
        val hash = Eip191Signer.hashMessage(p.wallet.toByteArray(Charsets.UTF_8))
        val pub = Eip191Signer.recoverPublicKey(hash, BigInteger(1, sig.copyOfRange(0, 32)), BigInteger(1, sig.copyOfRange(32, 64)), (sig[64].toInt() and 0xFF) - 27)!!
        val recovered = "0x" + ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256(pub.copyOfRange(1, pub.size))).takeLast(40)
        assertEquals(eoa.lowercase(), recovered)
    }

    @Test
    fun theTwoRecoverRecordsOpenWithTheCodeAndWithThePasswordInTheFormatTheRestoreReads() {
        val p = ok(build())
        assertEquals(2, p.recover.size)
        assertEquals("0x" + ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256(p.recoverCode.toByteArray())), p.recover[0].hash)
        assertEquals("0x" + ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256("qa.tag_1".toByteArray())), p.recover[1].hash)
        fun open(i: Int, secret: ByteArray): RecoveryRecord.Opened {
            val parsed = RecoveryRecord.parse(p.recover[i].encrypto)!!
            return RecoveryRecord.open(parsed.stored, parsed.imgBase64, secret, cheap)
        }
        val byCode = open(0, p.recoverCode.toByteArray()) as RecoveryRecord.Opened.Ok
        val byPassword = open(1, password) as RecoveryRecord.Opened.Ok
        assertEquals(phraseText, String(byCode.phrase, Charsets.UTF_8))
        assertEquals(phraseText, String(byPassword.phrase, Charsets.UTF_8))
        assertTrue("a wrong password does not open it", open(1, "wrong".toByteArray()) is RecoveryRecord.Opened.WrongPassword)
        assertTrue("the password does not open the code's record", open(0, password) is RecoveryRecord.Opened.WrongPassword)
    }

    @Test
    fun theRealArgonRecordOpensWithThePasswordAndTheCode() {
        val p = ok(build(kdf = { pw, s -> RecoveryRecord.argon2idKey(pw, s) }))
        val parsed = RecoveryRecord.parse(p.recover[1].encrypto)!!
        assertEquals(32 * 1024, parsed.stored.m)
        assertEquals(3, parsed.stored.t)
        assertEquals(1, parsed.stored.p)
        assertEquals(16, parsed.stored.salt.size)
        val byPassword = RecoveryRecord.open(parsed.stored, parsed.imgBase64, password) as RecoveryRecord.Opened.Ok
        assertEquals(phraseText, String(byPassword.phrase, Charsets.UTF_8))
        val parsedCode = RecoveryRecord.parse(p.recover[0].encrypto)!!
        val byCode = RecoveryRecord.open(parsedCode.stored, parsedCode.imgBase64, p.recoverCode.toByteArray()) as RecoveryRecord.Opened.Ok
        assertEquals(phraseText, String(byCode.phrase, Charsets.UTF_8))
    }

    @Test
    fun theRecordShapeIsTheStoredAndImgJsonInBase64() {
        val json = JSONObject(String(Base64.getDecoder().decode(ok(build()).recover[0].encrypto), Charsets.UTF_8))
        assertEquals(setOf("stored", "img"), json.keys().asSequence().toSet())
        val stored = json.getJSONObject("stored")
        assertEquals(setOf("algo", "v", "m", "t", "p", "salt", "hash"), stored.keys().asSequence().toSet())
        assertEquals("argon2id", stored.getString("algo"))
        assertEquals(19, stored.getInt("v"))
    }

    @Test
    fun theRecoverCodeIs22Base58CharactersTheRestoreAccepts() {
        val seen = HashSet<String>()
        repeat(200) {
            val code = AccountRegisterPayload.newRecoverCode(random)
            assertEquals(22, code.length)
            assertTrue(code.all { it in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" })
            assertNotNull("the existing restore accepts it", RecoveryCode.normalize(code.toByteArray()))
            seen += code
        }
        assertEquals("not repeated", 200, seen.size)
    }

    @Test
    fun badInputIsRefusedBeforeAnythingIsSigned() {
        assertEquals("bad_request", (build(name = "ab") as AccountRegisterPayload.Built.Refused).code)
        assertEquals("bad_request", (build(name = "has space") as AccountRegisterPayload.Built.Refused).code)
        assertEquals("bad_request", (build(name = "x".repeat(27)) as AccountRegisterPayload.Built.Refused).code)
        assertEquals("bad_request", (build(pw = ByteArray(0)) as AccountRegisterPayload.Built.Refused).code)
        assertEquals("bad_request", (build(pw = ByteArray(2000) { 65 }) as AccountRegisterPayload.Built.Refused).code)
        assertEquals("a leading @ is dropped", "tag_ok", ok(build(name = "@tag_ok")).accountName)
        // A phrase that does not derive the account key is refused: nothing is signed or sealed.
        val other = "legal winner thank year wave sausage worth useful legal winner thank yellow".toByteArray()
        assertEquals("phrase_mismatch", (build(ph = other) as AccountRegisterPayload.Built.Refused).code)
        assertEquals("phrase_mismatch", (build(k = ByteArray(32).also { it[31] = 9 }) as AccountRegisterPayload.Built.Refused).code)
    }

    @Test
    fun noPlainSecretIsInTheAnswerExceptTheRecoverCodeTheUserMustSee() {
        val p = ok(build())
        val whole = JSONObject().put("accountName", p.accountName).put("wallet", p.wallet).put("signMessage", p.signMessage)
            .put("recover", JSONArray().also { a -> p.recover.forEach { a.put(JSONObject().put("hash", it.hash).put("encrypto", it.encrypto)) } }).toString()
        assertFalse(whole.contains(phraseText))
        assertFalse(whole.contains(String(password)))
        assertFalse(whole.contains(p.recoverCode))
        assertFalse(whole.contains(ConetChatCryptoUtil.toHex(key)))
        assertNotEquals("each call has its own salt and code", p.recoverCode, ok(build()).recoverCode)
    }

    // ---- the registry decision before submitting ---------------------------------------------------------------------------------------

    @Test
    fun theRegistryDecisionNeverSubmitsTwiceAndNeverTreatsAFailureAsFree() {
        assertTrue(AccountRegisterPayload.decide(eoa) { null } is AccountRegisterPayload.Registry.Free)
        assertTrue(AccountRegisterPayload.decide(eoa) { eoa.lowercase() } is AccountRegisterPayload.Registry.AlreadyRegistered)
        assertTrue("any case of the same address is the same account", AccountRegisterPayload.decide(eoa) { AccountRegisterPayload.checksum(eoa) } is AccountRegisterPayload.Registry.AlreadyRegistered)
        assertTrue(AccountRegisterPayload.decide(eoa) { "0x" + "11".repeat(20) } is AccountRegisterPayload.Registry.Taken)
        assertTrue(AccountRegisterPayload.decide(eoa) { throw IllegalStateException("network_error") } is AccountRegisterPayload.Registry.Unreadable)
    }

    private fun registryRpc(owner: String, ownerOnEndpointB: String = owner) = { second: Boolean ->
        AddressPgpRead.Rpc { method, params ->
            when (method) {
                "eth_blockNumber" -> "0x10"
                "eth_getBlockByNumber" -> JSONObject().put("number", "0x10").put("hash", "0x" + "ab".repeat(32))
                "eth_call" -> "0x" + (if (second) ownerOnEndpointB else owner).removePrefix("0x").padStart(64, '0')
                else -> null
            }
        }
    }

    @Test
    fun theOwnerIsReadAtOneBlockOnBothEndpointsAndADisagreementIsAFailure() {
        val config = RegistryConfig("0x" + "22".repeat(20), listOf(RegistryEndpoint("https://a.test", 1000), RegistryEndpoint("https://b.test", 1000)))
        val owner = "0x" + "ab".repeat(20)
        fun read(a: String, b: String): String? {
            val make = registryRpc(a, b)
            return AccountRegistryRead.ownerAgreed(config, { ep -> make(ep.url.contains("b.test")) }, "qa.tag")
        }
        assertEquals(owner, read(owner, owner))
        assertNull("the zero address is no owner", read("0x" + "00".repeat(20), "0x" + "00".repeat(20)))
        try {
            read(owner, "0x" + "cd".repeat(20))
            throw AssertionError("a disagreement must throw")
        } catch (e: IllegalStateException) {
            assertEquals("network_error", e.message)
        }
        assertTrue(AccountRegistryRead.callDataOwnerByAccountName("qa.tag").startsWith(AddressPgpRead.selector("getOwnerByAccountName(string)")))
    }

    // ---- the server's verifyMessage(wallet, signMessage) logic ----------------------------------------------------------

    /** What the server does: `ethers.verifyMessage(message, sig)` recovers the address, compared in lower case with the wallet. */
    private fun recoveredAddress(message: String, signature: String): String {
        val sig = ConetChatCryptoUtil.hexToBytes(signature.removePrefix("0x"))!!
        val hash = Eip191Signer.hashMessage(message.toByteArray(Charsets.UTF_8))
        val pub = Eip191Signer.recoverPublicKey(hash, BigInteger(1, sig.copyOfRange(0, 32)), BigInteger(1, sig.copyOfRange(32, 64)), (sig[64].toInt() and 0xFF) - 27)!!
        return "0x" + ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256(pub.copyOfRange(1, pub.size))).takeLast(40)
    }

    @Test
    fun theServerSideCheckPassesForTheReturnedWalletAndFailsIfThePageChangesItsCase() {
        val p = ok(build())
        // checkSign(wallet, signMessage, wallet): the signed text is the wallet string as sent; the address comparison is case-insensitive.
        assertEquals(p.wallet.lowercase(), recoveredAddress(p.wallet, p.signMessage).lowercase())
        assertEquals(eoa.lowercase(), recoveredAddress(p.wallet, p.signMessage))
        // A page that rewrites the case (a checksum wallet, an upper-case one) or trims/pads it sends a different string: the recovered address is
        // another one and the check fails. That is why the page must forward the wallet exactly.
        for (changed in listOf(AccountRegisterPayload.checksum(eoa), p.wallet.uppercase().replace("0X", "0x"), " " + p.wallet, p.wallet + " ")) {
            assertNotEquals("a changed wallet string breaks the check: '$changed'", p.wallet.lowercase(), recoveredAddress(changed, p.signMessage).lowercase())
        }
    }
}
