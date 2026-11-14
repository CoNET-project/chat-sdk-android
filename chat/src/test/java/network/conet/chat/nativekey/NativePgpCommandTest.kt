package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The C4 `pgpSign` command (`NativeWalletCommands.pgpSign`), with the gate decisions for its name (spec 25.22.2,
 * 25.26.4c). The page gets the armored signature only. No key or passphrase appears in any answer. The registry is
 * empty by default: until the interface owner lists the purposes, every purpose is refused (T-125).
 */
class NativePgpCommandTest {
    private val vectors = JSONObject(
        String(File(System.getenv("PGP_NATIVE_VECTORS") ?: "../spec/pgp-native-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val purpose = "syntheticvector"
    private val registry = setOf(purpose)
    private val message = "document to sign"
    private val messageB64 = ConetChatCryptoUtil.base64Encode(message.toByteArray(Charsets.UTF_8))

    private fun ecc() = vectors.getJSONObject("keys").getJSONObject("ecc-pass")

    private fun vaultWithKey(): NativePgpVault {
        val vault = NativePgpVault(NativeTestWrap(), NativeTestFiles(), SYN_EOA)
        assertEquals(NativePgpVault.Put.OK, vault.put("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa", ecc().getString("privateArmored"), ecc().getString("passphrase")))
        return vault
    }

    @Test
    fun withTheDefaultRegistryEveryPurposeIsRefused() {
        val vault = vaultWithKey()
        val out = NativeWalletCommands.pgpSign(vault, purpose, messageB64, NativePgp.SIG_BINARY_DOCUMENT)
        assertEquals("purpose_not_registered", out.code)
        assertNull(out.value)
    }

    @Test
    fun aRegisteredPurposeReturnsOnlyAnArmoredSignature() {
        val vault = vaultWithKey()
        for (type in listOf(NativePgp.SIG_BINARY_DOCUMENT, NativePgp.SIG_CANONICAL_TEXT)) {
            val out = NativeWalletCommands.pgpSign(vault, purpose, messageB64, type, registry)
            assertEquals("type $type", "ok", out.code)
            val sig = out.value!!
            assertTrue(sig.startsWith("-----BEGIN PGP SIGNATURE-----"))
            // The answer carries no key material and no passphrase.
            assertFalse(sig.contains("PRIVATE KEY"))
            assertFalse(sig.contains(ecc().getString("passphrase")))
            assertNull(out.address)
            assertTrue(vault.verifySignature(purpose, message.toByteArray(Charsets.UTF_8), sig))
        }
    }

    @Test
    fun certificationAndUnknownTypesAreRefusedEvenForARegisteredPurpose() {
        val vault = vaultWithKey()
        assertEquals("sig_type_not_allowed", NativeWalletCommands.pgpSign(vault, purpose, messageB64, 0x10, registry).code)
        assertEquals("sig_type_not_allowed", NativeWalletCommands.pgpSign(vault, purpose, messageB64, 0x13, registry).code)
        assertEquals("sig_type_not_allowed", NativeWalletCommands.pgpSign(vault, purpose, messageB64, -1, registry).code)
    }

    @Test
    fun purposeIdsOutsideTheShapeAreRefused() {
        val vault = vaultWithKey()
        for (bad in listOf("", "../x", "a b", "unknownPurpose", "1starts-with-digit")) {
            assertEquals(bad, "purpose_not_registered", NativeWalletCommands.pgpSign(vault, bad, messageB64, 0x00, registry).code)
        }
    }

    @Test
    fun aMissingOrOversizedMessageIsRefused() {
        val vault = vaultWithKey()
        assertEquals("bad_request", NativeWalletCommands.pgpSign(vault, purpose, null, 0x00, registry).code)
        val big = ConetChatCryptoUtil.base64Encode(ByteArray(NativeWalletCommands.PGP_SIGN_MAX_BYTES + 1))
        assertEquals("too_long", NativeWalletCommands.pgpSign(vault, purpose, big, 0x00, registry).code)
    }

    @Test
    fun withoutARecordTheAnswerIsNoPgpKey() {
        val vault = NativePgpVault(NativeTestWrap(), NativeTestFiles(), SYN_EOA)
        assertEquals("no_pgp_key", NativeWalletCommands.pgpSign(vault, purpose, messageB64, 0x00, registry).code)
    }

    @Test
    fun aLockedRecordAnswersPgpLocked() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val vault = NativePgpVault(wrap, files, SYN_EOA)
        assertEquals(NativePgpVault.Put.OK, vault.put("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa", ecc().getString("privateArmored"), ecc().getString("passphrase")))
        files.map[NativePgpVault.markName(SYN_EOA)] = "0".repeat(64).toByteArray(Charsets.US_ASCII)
        wrap.opens = 0
        val out = NativeWalletCommands.pgpSign(vault, purpose, messageB64, 0x00, registry)
        // Function-level "locked does not sign" (25.52BT.3, CB.3): the refusal is pgp_locked, no signature value is returned, and no key is
        // opened (unwrapped) while the record is locked.
        assertEquals("pgp_locked", out.code)
        org.junit.Assert.assertNull("no signature value while locked", out.value)
        assertEquals("no key is opened while locked", 0, wrap.opens)
    }

    @Test
    fun aLockedRecordRefusesBeforeTheParameters() {
        // 25.52CI.1 (r3eh): the lock is judged first. A locked record refuses with pgp_locked before the message, the signature type, the purpose
        // and any key read.
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val vault = NativePgpVault(wrap, files, SYN_EOA)
        assertEquals(NativePgpVault.Put.OK, vault.put("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa", ecc().getString("privateArmored"), ecc().getString("passphrase")))
        files.map[NativePgpVault.markName(SYN_EOA)] = "0".repeat(64).toByteArray(Charsets.US_ASCII)
        wrap.opens = 0
        assertEquals("pgp_locked", NativeWalletCommands.pgpSign(vault, purpose, "!!not base64", 0x10, registry).code)
        assertEquals("pgp_locked", NativeWalletCommands.pgpSign(vault, "notRegistered", messageB64, 0x10, registry).code)
        assertEquals("no key is opened while locked", 0, wrap.opens)
    }

    @Test
    fun signedBytesAreTheLabelThenTheMessageWithTextCanonicalisation() {
        // 25.52CD.3 (R737): the signed stream is the UTF-8 label, then the message (NativePgp.signDocument; verifyDocument in the same order).
        // Signature type 0x01 is a text signature: the stream is canonical, so a LF in the label is hashed as CRLF.
        val secret = requireNotNull(NativePgp.parseSecret(ecc().getString("privateArmored")))
        val pass = ecc().getString("passphrase")
        val msg = "M".toByteArray(Charsets.UTF_8)
        val sig = NativePgp.signDocument(secret, pass, "L", msg, 0x01)
        org.junit.Assert.assertTrue("signed", sig.ok)
        val armored = requireNotNull(sig.value)
        org.junit.Assert.assertTrue("label then message", NativePgp.verifyDocument(secret, "L", msg, armored))
        org.junit.Assert.assertFalse("message then label is another stream", NativePgp.verifyDocument(secret, "M", "L".toByteArray(Charsets.UTF_8), armored))
        val lf = NativePgp.signDocument(secret, pass, "beamio.pgp.x.v1\n", msg, 0x01)
        org.junit.Assert.assertTrue("a LF in the label verifies as CRLF", NativePgp.verifyDocument(secret, "beamio.pgp.x.v1\r\n", msg, requireNotNull(lf.value)))
    }

    @Test
    fun binarySignatureHashesExactlyTheLabelThenTheMessage() {
        // 25.27.9 (r3ej, D) and 25.27.4: the binary type 0x00 hashes the bytes as they are. The LF of the label is not canonicalised, so the
        // stream is label || message, with no separator.
        val secret = requireNotNull(NativePgp.parseSecret(ecc().getString("privateArmored")))
        val pass = ecc().getString("passphrase")
        val msg = "M".toByteArray(Charsets.UTF_8)
        val sig = NativePgp.signDocument(secret, pass, "beamio.pgp.x.v1\n", msg, 0x00)
        org.junit.Assert.assertTrue("signed", sig.ok)
        val armored = requireNotNull(sig.value)
        org.junit.Assert.assertTrue("label LF then message", NativePgp.verifyDocument(secret, "beamio.pgp.x.v1\n", msg, armored))
        org.junit.Assert.assertFalse("the CRLF form is another stream", NativePgp.verifyDocument(secret, "beamio.pgp.x.v1\r\n", msg, armored))
        val two = NativePgp.signDocument(secret, pass, "L", "M".toByteArray(Charsets.UTF_8), 0x00)
        org.junit.Assert.assertTrue("label L then message M is the stream LM", NativePgp.verifyDocument(secret, "LM", ByteArray(0), requireNotNull(two.value)))
    }

    @Test
    fun aTextSignatureWithACRIsRefusedAfterThePurposeAndBeforeAnyKeyIsOpened() {
        // 25.27.6 step 2a (r3em, CM.2): a text signature (0x01) whose message holds a CR is message_contains_cr. The purpose is judged first,
        // and no key is opened for the refusal. The binary type 0x00 is not affected by a CR.
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val vault = NativePgpVault(wrap, files, SYN_EOA)
        assertEquals(NativePgpVault.Put.OK, vault.put("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa", ecc().getString("privateArmored"), ecc().getString("passphrase")))
        val withCr = "YQ0KYg==" // "a\r\nb"
        wrap.opens = 0
        assertEquals("message_contains_cr", NativeWalletCommands.pgpSign(vault, purpose, withCr, 0x01, registry).code)
        assertEquals("the purpose is judged first", "purpose_not_registered", NativeWalletCommands.pgpSign(vault, "notRegistered", withCr, 0x01, registry).code)
        assertEquals("no key is opened for the refusal", 0, wrap.opens)
        assertTrue("the binary type is not refused for a CR", NativeWalletCommands.pgpSign(vault, purpose, withCr, 0x00, registry).code != "message_contains_cr")
    }

    @Test
    fun theGateDecidesThePgpSignNameByState() {
        // G0 no_key, G1 not_ready, G2 dispatch (the handler runs only in G2).
        // 25.52BP.1 (r3dm): pgpSign is not a bridge name. The module answers unknown_command for it before the gate, in every state.
        assertFalse("pgpSign is not registered", network.conet.chat.BridgeCommandTable.isRegistered("pgpSign"))
    }
}
