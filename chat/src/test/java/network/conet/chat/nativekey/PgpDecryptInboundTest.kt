package network.conet.chat.nativekey

import network.conet.chat.nativekey.NoKeyGate.Gate
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Date

/**
 * `pgpDecryptInbound` (spec 25.34, A1) on the JVM, against the interface owner's vectors
 * (`spec/pgp-bridge-command-vectors.v1.json`, cases A-01 to A-16) and the real native vault. Synthetic keys only:
 * the P-1 key from `pgp-backup-compat-vectors`. Nothing here reads a network, a chain, or a real account.
 */
class PgpDecryptInboundTest {
    private val bridge = JSONObject(
        String(File(System.getenv("PGP_BRIDGE_VECTORS") ?: "../spec/pgp-bridge-command-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val backup = JSONObject(
        String(File(System.getenv("PGP_BACKUP_VECTORS") ?: "../spec/pgp-backup-compat-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val account = bridge.getJSONObject("account").getString("eoa").lowercase()
    private val recipient = bridge.getJSONObject("recipient")
    private val p1 = backup.getJSONArray("positives").getJSONObject(0)
    private val privateArmor = p1.getJSONObject("pgp").getString("privateArmor")

    private fun vaultWithRecipientKey(): NativePgpVault {
        val vault = NativePgpVault(NativeTestWrap(), NativeTestFiles(), account)
        assertEquals(NativePgpVault.Put.OK, vault.put(account, privateArmor, ""))
        return vault
    }

    private fun sourceOf(vault: NativePgpVault) = object : PgpDecryptInbound.Source {
        override fun subkeyKeyIdHex(): String? = vault.identity()?.subkeyKeyId
        override fun decryptLiteral(armoredMessage: String): NativePgp.LiteralResult =
            vault.decryptInboundLiteral(armoredMessage)
    }

    @Test
    fun vectorFileIsThePinnedBatch() {
        val sha = MessageDigest.getInstance("SHA-256")
            .digest(File(System.getenv("PGP_BRIDGE_VECTORS") ?: "../spec/pgp-bridge-command-vectors.v1.json").readBytes())
            .joinToString("") { "%02x".format(it) }
        assertEquals("40ac9784730ddbdda5ed5cce96269973f833db90acd6c9073e890367a77280d6", sha)
    }

    @Test
    fun theVaultKeyIsTheSpecRecipient() {
        val id = vaultWithRecipientKey().identity()!!
        assertEquals(recipient.getString("primaryFingerprint").uppercase(), id.fingerprint.uppercase())
        assertEquals(recipient.getString("subkeyKeyID").uppercase(), id.subkeyKeyId.uppercase())
    }

    /** Every A-case: the gate cases answer from the gate alone; the others run [PgpDecryptInbound.answer]. */
    @Test
    fun everyACaseMatchesTheSpecVector() {
        val source = sourceOf(vaultWithRecipientKey())
        val cases = bridge.getJSONArray("cases")
        var checked = 0
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (c.getString("group") != "A") continue
            checked++
            val id = c.getString("id")
            val req = materialize(c.getJSONObject("request"))
            val ack = c.getJSONObject("expect").getJSONObject("ack")
            val expectedError = if (ack.getBoolean("ok")) null else ack.getString("error")
            when (c.getString("gate")) {
                "G0" -> assertEquals(id, expectedError, PgpDecryptInbound.gateRefusal(Gate.G0, locked = false))
                "G1" -> assertEquals(id, expectedError, PgpDecryptInbound.gateRefusal(Gate.G1, locked = false))
                "G2_locked" -> assertEquals(id, expectedError, PgpDecryptInbound.gateRefusal(Gate.G2, locked = true))
                else -> {
                    if (PgpDecryptInbound.reqIdOf(req) == null) {
                        // A-16: the module answers bad_request with reqId null before anything else.
                        assertEquals(id, "bad_request", expectedError)
                        assertTrue(id, ack.isNull("reqId"))
                        continue
                    }
                    val answer = PgpDecryptInbound.answer(req, account, source)
                    if (expectedError != null) {
                        assertEquals(id, expectedError, answer.error)
                        continue
                    }
                    assertTrue("$id: ${answer.error}", answer.ok)
                    val got = answer.result!!
                    val exp = ack.getJSONObject("result")
                    assertEquals(id, exp.getString("plaintext"), got.getString("plaintext"))
                    assertSignal(id, exp.get("signal"), got.get("signal"))
                }
            }
        }
        assertEquals(16, checked)
    }

    /** The vectors write a long armor as `armoredMessageRepeat: {char, count}`. This expands it to the real field. */
    private fun materialize(req: JSONObject): JSONObject {
        if (!req.has("armoredMessageRepeat")) return req
        val r = req.getJSONObject("armoredMessageRepeat")
        val out = JSONObject(req.toString())
        out.remove("armoredMessageRepeat")
        out.put("armoredMessage", r.getString("char").repeat(r.getInt("count")))
        return out
    }

    private fun assertSignal(id: String, exp: Any?, got: Any?) {
        if (exp == null || exp == JSONObject.NULL) {
            assertTrue("$id: signal must be null", got == null || got == JSONObject.NULL)
            return
        }
        val e = exp as JSONObject
        val g = got as JSONObject
        for (k in listOf("kind", "type", "callId", "sessionId")) assertEquals("$id $k", e.getString(k), g.getString(k))
        assertEquals("$id rejectReason", e.optString("rejectReason", ""), g.optString("rejectReason", ""))
    }

    @Test
    fun aBinaryLiteralThatIsNotUtf8IsRefused() {
        val source = sourceOf(vaultWithRecipientKey())
        val armor = encryptLiteral(publicArmor(), byteArrayOf(0xFF.toByte(), 0xFE.toByte(), 0x41), PGPLiteralData.BINARY)
        val answer = PgpDecryptInbound.answer(request(armor), account, source)
        assertEquals("plaintext_not_utf8", answer.error)
    }

    @Test
    fun aBinaryLiteralThatIsUtf8IsAccepted() {
        val source = sourceOf(vaultWithRecipientKey())
        val text = "{\"sendId\":\"binary-ok\"}"
        val armor = encryptLiteral(publicArmor(), text.toByteArray(Charsets.UTF_8), PGPLiteralData.BINARY)
        val answer = PgpDecryptInbound.answer(request(armor), account, source)
        assertTrue(answer.ok)
        assertEquals(text, answer.result!!.getString("plaintext"))
        assertTrue(answer.result!!.isNull("signal"))
    }

    @Test
    fun theArmorLimitIsJudgedBeforeTheArmorIsParsed() {
        val source = sourceOf(vaultWithRecipientKey())
        val atLimit = PgpDecryptInbound.answer(request("A".repeat(PgpDecryptInbound.MAX_ARMOR_BYTES)), account, source)
        assertEquals("not_openpgp_message", atLimit.error)
        val over = PgpDecryptInbound.answer(request("A".repeat(PgpDecryptInbound.MAX_ARMOR_BYTES + 1)), account, source)
        assertEquals("payload_too_large", over.error)
    }

    @Test
    fun aForbiddenFieldIsRefusedAtAnyDepthWithoutItsValue() {
        val body = request("x").put("extra", JSONObject().put("inner", JSONObject().put("MNEMONIC", "secret words")))
        val answer = PgpDecryptInbound.answer(body, account, sourceOf(vaultWithRecipientKey()))
        assertEquals("key_over_bridge_refused", answer.error)
        assertFalse(answer.toString().contains("secret words"))
    }

    @Test
    fun aMessageForAnotherAccountIsAccountMismatch() {
        val answer = PgpDecryptInbound.answer(
            request("x").put("accountKey", "0x0000000000000000000000000000000000000001:default"),
            account,
            sourceOf(vaultWithRecipientKey()),
        )
        assertEquals("account_mismatch", answer.error)
    }

    @Test
    fun theGateRefusesBeforeAnyPayloadIsRead() {
        assertEquals("no_key", PgpDecryptInbound.gateRefusal(Gate.G0, locked = false))
        assertEquals("not_ready", PgpDecryptInbound.gateRefusal(Gate.G1, locked = false))
        // A record whose material is not available answers not_ready, never locked; the passcode package case
        // adds the top-level reason passcode_not_provided in the ack (NoKeyGate.lockedAck).
        assertEquals("not_ready", PgpDecryptInbound.gateRefusal(Gate.G1, locked = true))
        assertEquals("not_ready", PgpDecryptInbound.gateRefusal(Gate.G2, locked = true))
        assertNull(PgpDecryptInbound.gateRefusal(Gate.G2, locked = false))
    }

    @Test
    fun reqIdIsAStringOrANonNegativeIntegerAndIsEchoedAsSent() {
        assertEquals("a1-01", PgpDecryptInbound.reqIdOf(JSONObject().put("reqId", "a1-01")))
        assertEquals(5, PgpDecryptInbound.reqIdOf(JSONObject().put("reqId", 5)))
        assertNull(PgpDecryptInbound.reqIdOf(JSONObject().put("reqId", -1)))
        assertNull(PgpDecryptInbound.reqIdOf(JSONObject().put("reqId", JSONObject().put("x", 1))))
        assertNull(PgpDecryptInbound.reqIdOf(JSONObject()))
    }

    private fun publicArmor(): String =
        NativePgpKeyGen.publicArmorOf(privateArmor) ?: error("no public armor for the synthetic key")

    private fun request(armor: String): JSONObject = JSONObject()
        .put("type", "pgpDecryptInbound")
        .put("reqId", 1)
        .put("accountKey", "$account:default")
        .put("armoredMessage", armor)

    /** bcpg encryption of a literal of [format] to [publicArmor] (AES-256, integrity protected, zlib). */
    private fun encryptLiteral(publicArmor: String, bytes: ByteArray, format: Char): String {
        val ring = PGPPublicKeyRing(PGPUtil.getDecoderStream(publicArmor.toByteArray(Charsets.UTF_8).inputStream()), BcKeyFingerprintCalculator())
        val key: PGPPublicKey = ring.publicKeys.asSequence().toList().first { !it.isMasterKey && it.isEncryptionKey }
        val random = SecureRandom()
        val compressedOut = ByteArrayOutputStream()
        val compressor = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZLIB)
        val cOut: OutputStream = compressor.open(compressedOut)
        val lOut: OutputStream = PGPLiteralDataGenerator().open(cOut, format, "", bytes.size.toLong(), Date())
        lOut.write(bytes)
        lOut.close()
        compressor.close()
        val armoredOut = ByteArrayOutputStream()
        val armorOut = ArmoredOutputStream.builder().clearHeaders().build(armoredOut)
        val encryptor = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true).setSecureRandom(random),
        )
        encryptor.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(key).setSecureRandom(random))
        val eOut: OutputStream = encryptor.open(armorOut, compressedOut.size().toLong())
        eOut.write(compressedOut.toByteArray())
        eOut.close()
        armorOut.close()
        return armoredOut.toString(Charsets.UTF_8.name())
    }
}
