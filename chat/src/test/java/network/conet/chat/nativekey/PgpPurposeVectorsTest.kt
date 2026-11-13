package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * spec 25.27 (r3i) against `interface/protocol/pgp-purpose-vectors.v1.json` (copy at `spec/`, sha256 pinned below).
 *
 * No purpose is registered (`REGISTERED_PURPOSES` is empty), so every purposeId is refused: the three candidate names,
 * the invalid ids and the unregistered names, for every signature type in the matrix. A vault that holds a real key is
 * used, so each refusal comes from the purpose or signature-type rule and not from a missing key. No case produces a
 * signature. Group A checks the native domain tag bytes against the vector (T-170).
 */
class PgpPurposeVectorsTest {
    private val raw = File(System.getenv("PGP_PURPOSE_VECTORS") ?: "../spec/pgp-purpose-vectors.v1.json").readBytes()
    private val vectors = JSONObject(String(raw, Charsets.UTF_8))
    private val keys = JSONObject(
        String(File(System.getenv("PGP_NATIVE_VECTORS") ?: "../spec/pgp-native-vectors.v1.json").readBytes(), Charsets.UTF_8),
    ).getJSONObject("keys").getJSONObject("ecc-pass")
    private val message = "document to sign"
    private val messageB64 = ConetChatCryptoUtil.base64Encode(message.toByteArray(Charsets.UTF_8))

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
    private fun sha256Hex(b: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(b))
    private fun sigType(s: String): Int = s.removePrefix("0x").toInt(16)

    private fun vaultWithKey(): NativePgpVault {
        val vault = NativePgpVault(NativeTestWrap(), NativeTestFiles())
        assertEquals(
            NativePgpVault.Put.OK,
            vault.put("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa", keys.getString("privateArmored"), keys.getString("passphrase")),
        )
        return vault
    }

    @Test
    fun vectorFileIsTheR3iVersionAndNoPurposeIsRegistered() {
        assertEquals(
            "vector file must be the r3i copy in SHA256-CURRENT",
            "c55610e0b0596d79d8bb03ae88fa9ba10809f12d65f5a4e593de1acf579a4ef1",
            sha256Hex(raw),
        )
        assertEquals(0, vectors.getJSONArray("registeredPurposes").length())
        assertTrue("REGISTERED_PURPOSES must be empty until the purposes are listed", NativePgpVault.REGISTERED_PURPOSES.isEmpty())
        assertEquals(0, vectors.getJSONArray("positiveSignatureCases").length())
    }

    @Test
    fun theCandidateNamesAreNotRegisteredAndKeepTheirDomainTags() {
        val candidates = vectors.getJSONArray("candidates")
        assertEquals(3, candidates.length())
        for (i in 0 until candidates.length()) {
            val c = candidates.getJSONObject(i)
            assertEquals(false, c.getBoolean("registered"))
            assertTrue(c.getString("purposeId") !in NativePgpVault.REGISTERED_PURPOSES)
        }
    }

    @Test
    fun everyRefusalCaseIsRefusedForEveryCandidateAndSignatureType() {
        val vault = vaultWithKey()
        val cases = vectors.getJSONArray("refusalCases")
        assertEquals("42 cases: 3 candidates by 14 signature types", 42, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val expect = c.getJSONObject("expect")
            val out = NativeWalletCommands.pgpSign(vault, c.getString("purposeId"), messageB64, sigType(c.getString("sigType")))
            assertEquals(c.getString("id"), expect.getString("code"), out.code)
            assertNull(c.getString("id"), out.value)
        }
    }

    @Test
    fun signatureTypeIsJudgedBeforeThePurpose() {
        // spec 25.27.6 order 1: a certification type is refused as a type even for a candidate purpose.
        val vault = vaultWithKey()
        assertEquals("sig_type_not_allowed", NativeWalletCommands.pgpSign(vault, "chatEnvelope", messageB64, 0x02).code)
        assertEquals("sig_type_not_allowed", NativeWalletCommands.pgpSign(vault, "chatEnvelope", messageB64, 0x13).code)
        assertEquals("purpose_not_registered", NativeWalletCommands.pgpSign(vault, "chatEnvelope", messageB64, 0x00).code)
    }

    @Test
    fun everyInvalidPurposeIdIsRefusedAndItsBytesMatchTheVector() {
        val vault = vaultWithKey()
        val cases = vectors.getJSONArray("invalidCases")
        assertEquals(9, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val id = c.getString("purposeId")
            // The vector names the exact bytes. The test sends those bytes, so an escape cannot change the input.
            assertEquals(c.getString("id"), c.getString("purposeIdBytesHex"), hex(id.toByteArray(Charsets.UTF_8)))
            val out = NativeWalletCommands.pgpSign(vault, id, messageB64, sigType(c.getString("sigType")))
            assertEquals(c.getString("id"), c.getJSONObject("expect").getString("code"), out.code)
            assertNull(c.getString("id"), out.value)
        }
    }

    @Test
    fun theNativeDomainTagAndSignedPayloadMatchGroupA() {
        val sample = ConetChatCryptoUtil.hexToBytes(vectors.getJSONArray("domainCases").getJSONObject(0).getString("sampleMessageHex"))!!
        val cases = vectors.getJSONArray("domainCases")
        assertEquals(3, cases.length())
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val tag = NativePgpVault.domainLabel(c.getString("purposeId")).toByteArray(Charsets.UTF_8)
            // The vector's "\\n" in domainTagUtf8 is a display form. The hex carries the real newline byte (0x0a).
            assertEquals(c.getString("id"), c.getString("domainTagHex"), hex(tag))
            assertEquals(c.getString("id"), c.getInt("domainTagBytes"), tag.size)
            assertEquals(c.getString("id"), c.getString("domainTagSha256"), sha256Hex(tag))
            assertEquals(c.getString("id"), c.getString("sampleMessageHex"), hex(sample))
            val payload = tag + sample
            assertEquals(c.getString("id"), c.getString("signedPayloadHex"), hex(payload))
            assertEquals(c.getString("id"), c.getInt("signedPayloadBytes"), payload.size)
            assertEquals(c.getString("id"), c.getString("signedPayloadSha256"), sha256Hex(payload))
        }
    }
}
