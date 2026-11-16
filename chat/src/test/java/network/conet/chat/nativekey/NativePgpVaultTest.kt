package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The native PGP record (NativePgpVault) and its operations, with the vault's test doubles for the Keystore and the
 * files. Covers: the record (put, state, readback, rollback, forget, marker), inbound decryption through the vault
 * (C3), document signatures (C4) with the refusals of §25.22.2 (T-124 to T-126), the no-key and locked states, and the
 * rule that no key or passphrase appears in any output.
 */
class NativePgpVaultTest {
    private val vectors = JSONObject(
        String(File(System.getenv("PGP_NATIVE_VECTORS") ?: "../spec/pgp-native-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
    private val purpose = "syntheticvector"
    private val registry = setOf(purpose)

    private fun key(id: String) = vectors.getJSONObject("keys").getJSONObject(id)
    private fun decryptCase(id: String): JSONObject {
        val cases = vectors.getJSONArray("decrypt")
        return (0 until cases.length()).map { cases.getJSONObject(it) }.first { it.getString("id") == id }
    }

    private fun fresh(): Triple<NativePgpVault, NativeTestWrap, NativeTestFiles> {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        return Triple(NativePgpVault(wrap, files, SYN_EOA), wrap, files)
    }

    private fun putEccWithPassphrase(vault: NativePgpVault) =
        vault.put(eoa, key("ecc-pass").getString("privateArmored"), key("ecc-pass").getString("passphrase"))

    @Test
    fun noRecordMeansNoKeyAndNoDecryption() {
        val (vault, _, _) = fresh()
        assertTrue(vault.state() is NativePgpVault.State.NoKey)
        val out = vault.decryptInbound(decryptCase("D-1").getString("armor"))
        assertEquals("no_pgp_key", out.code)
        assertEquals(null, out.value)
        val sig = vault.sign(purpose, NativePgp.SIG_BINARY_DOCUMENT, "x".toByteArray(), registry)
        assertEquals("no_pgp_key", sig.code)
    }

    @Test
    fun putStoresTheKeyAndReportsItsFingerprint() {
        val (vault, _, files) = fresh()
        assertEquals(NativePgpVault.Put.OK, putEccWithPassphrase(vault))
        val st = vault.state()
        assertTrue(st is NativePgpVault.State.Ready)
        assertEquals(key("ecc-pass").getString("fingerprint"), (st as NativePgpVault.State.Ready).fingerprint)
        // The record is sealed: neither the key armor nor the passphrase is stored in clear.
        for (stored in files.map.values) {
            val text = String(stored, Charsets.UTF_8)
            assertFalse(text.contains("BEGIN PGP PRIVATE KEY"))
            assertFalse(text.contains(key("ecc-pass").getString("passphrase")))
        }
    }

    @Test
    fun inboundDecryptionUsesTheVaultKey() {
        val (vault, _, _) = fresh()
        putEccWithPassphrase(vault)
        val ok = vault.decryptInbound(decryptCase("D-1").getString("armor"))
        assertTrue(ok.ok)
        assertEquals(decryptCase("D-1").getJSONObject("expect").getString("text"), ok.value)
        // A message for another recipient is refused, and the key is not returned.
        val other = vault.decryptInbound(decryptCase("D-7").getString("armor"))
        assertEquals("not_recipient", other.code)
        assertEquals(null, other.value)
    }

    @Test
    fun aWrongPassphraseStoredInTheRecordIsRefused() {
        val (vault, _, _) = fresh()
        assertEquals(NativePgpVault.Put.OK, vault.put(eoa, key("ecc-pass").getString("privateArmored"), "not-the-passphrase"))
        assertEquals("bad_passphrase", vault.decryptInbound(decryptCase("D-1").getString("armor")).code)
    }

    @Test
    fun badKeyAndBadAccountAreRefusedAndNothingIsStored() {
        val (vault, _, files) = fresh()
        assertEquals(NativePgpVault.Put.BAD_KEY, vault.put(eoa, "not a key", ""))
        assertEquals(NativePgpVault.Put.BAD_KEY, vault.put(eoa, key("ecc-pass").getString("publicArmored"), ""))
        assertEquals(NativePgpVault.Put.BAD_EOA, vault.put("0xABC", key("ecc-pass").getString("privateArmored"), ""))
        assertTrue(files.map.isEmpty())
        assertTrue(vault.state() is NativePgpVault.State.NoKey)
    }

    @Test
    fun writeFailureRollsBackToNothing() {
        val (vault, _, files) = fresh()
        files.failWrite = NativePgpVault.recName(SYN_EOA)
        assertEquals(NativePgpVault.Put.STORE_FAILED, putEccWithPassphrase(vault))
        assertTrue(vault.state() is NativePgpVault.State.NoKey)
    }

    @Test
    fun readbackFailureRollsBackAndKeepsThePreviousRecord() {
        val (vault, wrap, _) = fresh()
        assertEquals(NativePgpVault.Put.OK, putEccWithPassphrase(vault))
        val before = vault.decryptInbound(decryptCase("D-1").getString("armor"))
        assertTrue(before.ok)
        // The next readback sees other bytes once, so the new record is rolled back to the previous one.
        var armed = true
        wrap.openOverride = { plain -> if (armed) { armed = false; ByteArray(32) { 1 } } else plain }
        assertEquals(NativePgpVault.Put.READBACK_FAILED, vault.put(eoa, key("ecc-nopass").getString("privateArmored"), ""))
        assertTrue(vault.state() is NativePgpVault.State.Ready)
        assertTrue(vault.decryptInbound(decryptCase("D-1").getString("armor")).ok)
    }

    @Test
    fun aRecordWithoutItsMarkerIsKeptAndReportedLocked() {
        // Rewritten 2026-11-16 (project ruling: a read never deletes user data). The earlier assertion removed the record on read.
        val (vault, _, files) = fresh()
        assertEquals(NativePgpVault.Put.OK, putEccWithPassphrase(vault))
        files.delete(NativePgpVault.markName(SYN_EOA))
        val st = vault.state()
        assertTrue(st is NativePgpVault.State.Locked && (st as NativePgpVault.State.Locked).reason == "marker_missing")
        assertTrue(files.map.containsKey(NativePgpVault.recName(SYN_EOA)))
        // A second read changes nothing either.
        assertTrue(vault.state() is NativePgpVault.State.Locked)
        assertTrue(files.map.containsKey(NativePgpVault.recName(SYN_EOA)))
    }

    @Test
    fun aMarkerMismatchIsLockedAndNothingDecrypts() {
        val (vault, _, files) = fresh()
        assertEquals(NativePgpVault.Put.OK, putEccWithPassphrase(vault))
        files.map[NativePgpVault.markName(SYN_EOA)] = "0".repeat(64).toByteArray(Charsets.US_ASCII)
        val st = vault.state()
        assertTrue(st is NativePgpVault.State.Locked)
        assertEquals("marker_mismatch", (st as NativePgpVault.State.Locked).reason)
        assertEquals("pgp_locked", vault.decryptInbound(decryptCase("D-1").getString("armor")).code)
    }

    @Test
    fun forgetRemovesTheRecord() {
        val (vault, _, files) = fresh()
        putEccWithPassphrase(vault)
        vault.forget()
        assertTrue(vault.state() is NativePgpVault.State.NoKey)
        assertTrue(files.map.isEmpty())
    }

    @Test
    fun signingRefusesAnUnregisteredPurposeAndAnyCertificationType() {
        val (vault, _, _) = fresh()
        putEccWithPassphrase(vault)
        val msg = "document".toByteArray()
        // T-125: a purposeId outside the enumeration is refused, with no signature.
        assertEquals("purpose_not_registered", vault.sign("unknownPurpose", NativePgp.SIG_BINARY_DOCUMENT, msg, registry).code)
        assertEquals("purpose_not_registered", vault.sign("bad purpose!", NativePgp.SIG_BINARY_DOCUMENT, msg, registry).code)
        // T-126: certification signatures 0x10 and 0x13 are refused.
        assertEquals("sig_type_not_allowed", vault.sign(purpose, 0x10, msg, registry).code)
        assertEquals("sig_type_not_allowed", vault.sign(purpose, 0x13, msg, registry).code)
        // Nothing is registered by default.
        assertEquals("purpose_not_registered", vault.sign(purpose, NativePgp.SIG_BINARY_DOCUMENT, msg).code)
    }

    @Test
    fun documentSignaturesVerifyOnlyForTheirPurposeAndMessage() {
        val (vault, _, _) = fresh()
        putEccWithPassphrase(vault)
        val msg = "document".toByteArray()
        for (type in listOf(NativePgp.SIG_BINARY_DOCUMENT, NativePgp.SIG_CANONICAL_TEXT)) {
            val out = vault.sign(purpose, type, msg, registry)
            assertTrue("sig type $type ${out.code}", out.ok)
            val sig = out.value!!
            assertTrue(sig.startsWith("-----BEGIN PGP SIGNATURE-----"))
            // No key or passphrase in the output.
            assertFalse(sig.contains("PRIVATE KEY"))
            assertFalse(sig.contains(key("ecc-pass").getString("passphrase")))
            assertTrue(vault.verifySignature(purpose, msg, sig))
            assertFalse(vault.verifySignature(purpose, "other".toByteArray(), sig))
            assertFalse(vault.verifySignature("otherPurpose", msg, sig))
        }
    }

    @Test
    fun openPgpJsSignaturesVerifyThroughTheVault() {
        // Interop: a detached signature made by openpgp.js over the same domain label verifies natively.
        val (vault, _, _) = fresh()
        putEccWithPassphrase(vault)
        val s = vectors.getJSONArray("signatures").getJSONObject(0)
        assertTrue(vault.verifySignature(s.getString("purpose"), s.getString("message").toByteArray(), s.getString("armoredSignature")))
    }

    @Test
    fun errorOutputsCarryCodesOnly() {
        val (vault, _, _) = fresh()
        putEccWithPassphrase(vault)
        // D-6 uses the same armor as D-1, which the vault's key (with its correct passphrase) opens, so it is not listed.
        for (id in listOf("D-7", "D-9")) {
            val out = vault.decryptInbound(decryptCase(id).getString("armor"))
            assertFalse(out.ok)
            assertEquals(null, out.value)
            assertFalse(out.code.contains("BEGIN"))
        }
    }
}
