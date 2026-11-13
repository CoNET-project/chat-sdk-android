package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * AddressPGP read-only access (spec 25.36) on the JVM. The RPC is a fake, so no endpoint is contacted. The ABI encodings
 * are built here by hand, so decode is checked against the standard layout, not against itself.
 */
class AddressPgpReadTest {
    private val eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
    private val contract = "0x684b0ac760cEE9c9b85de36d69746420648Cf9e2"
    private val armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----"

    private fun word(v: Long): ByteArray = ByteArray(32).also { w ->
        for (i in 0 until 8) w[31 - i] = ((v shr (8 * i)) and 0xFF).toByte()
    }

    private fun encodeString(s: String): ByteArray {
        val b = s.toByteArray(Charsets.UTF_8)
        val pad = (32 - b.size % 32) % 32
        return word(b.size.toLong()) + b + ByteArray(pad)
    }

    private fun hex(bytes: ByteArray): String = "0x" + bytes.joinToString("") { "%02x".format(it) }

    private fun encodeRecord(a: String, p: String, c: String, exists: Boolean): String {
        val sa = encodeString(a)
        val sp = encodeString(p)
        val sc = encodeString(c)
        val head = word(128) + word(128L + sa.size) + word(128L + sa.size + sp.size) + word(if (exists) 1 else 0)
        return hex(head + sa + sp + sc)
    }

    private fun encodeOneString(s: String): String = hex(word(32) + encodeString(s))

    @Test
    fun selectorsAreTheKeccakOfTheSignatures() {
        assertEquals("0x70a08231", AddressPgpRead.selector("balanceOf(address)"))
    }

    @Test
    fun callDataCarriesTheSelectorAndAPaddedAddress() {
        val data = AddressPgpRead.encodeCall(AddressPgpRead.SIG_PGP_KEYS, eoa)
        assertEquals(AddressPgpRead.selector(AddressPgpRead.SIG_PGP_KEYS), data.substring(0, 10))
        assertEquals(74, data.length)
        assertTrue(data.endsWith("0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda94"))
    }

    @Test
    fun aRecordRoundTripsThroughTheStandardLayout() {
        val rec = AddressPgpRead.decodeRecord(encodeRecord("123456", armor, "", true))!!
        assertEquals(AddressPgpRead.Record("123456", armor, "", true), rec)
    }

    @Test
    fun anAbsentRecordDecodesAsNotExisting() {
        val rec = AddressPgpRead.decodeRecord(encodeRecord("", "", "", false))!!
        assertFalse(rec.exists)
        assertEquals("", rec.publicKeyArmored)
    }

    @Test
    fun anEmptyBackupIsAnEmptyStringNotAFailure() {
        assertEquals("", AddressPgpRead.decodeString(encodeOneString("")))
        assertEquals("ciphertext", AddressPgpRead.decodeString(encodeOneString("ciphertext")))
    }

    @Test
    fun malformedAnswersDecodeAsNull() {
        assertNull(AddressPgpRead.decodeRecord("0x"))
        assertNull(AddressPgpRead.decodeString("0x"))
        assertNull(AddressPgpRead.decodeRecord("0xzz"))
        // A string offset past the end of the data.
        assertNull(AddressPgpRead.decodeString(hex(word(4096))))
    }

    /** Fake JSON-RPC: records every call and answers from the given table. */
    private class FakeRpc(
        private val block: String = "0x2a",
        private val recordHex: String,
        private val backupHex: String,
    ) : AddressPgpRead.Rpc {
        val calls = mutableListOf<Pair<String, JSONArray>>()

        override fun call(method: String, params: JSONArray): Any? {
            calls += method to params
            return when (method) {
                "eth_blockNumber" -> block
                "eth_call" -> {
                    val data = params.getJSONObject(0).getString("data")
                    when (data.substring(0, 10)) {
                        AddressPgpRead.selector(AddressPgpRead.SIG_PGP_KEYS) -> recordHex
                        AddressPgpRead.selector(AddressPgpRead.SIG_ENCRYPTED_BACKUP) -> backupHex
                        else -> error("unexpected selector")
                    }
                }
                else -> error("unexpected method $method")
            }
        }
    }

    @Test
    fun theRecordAndTheBackupAreReadAtOneBlockAndTheBackupCarriesFrom() {
        val rpc = FakeRpc(recordHex = encodeRecord("123456", armor, "", true), backupHex = encodeOneString("cipher"))
        val snap = AddressPgpRead.snapshot(rpc, contract, eoa).getOrThrow()
        assertEquals(42L, snap.block)
        assertEquals("123456", snap.record.pgpKeyId)
        assertEquals("cipher", snap.backupText)
        val ethCalls = rpc.calls.filter { it.first == "eth_call" }.map { it.second }
        assertEquals(2, ethCalls.size)
        assertEquals("0x2a", ethCalls[0].getString(1))
        assertEquals("0x2a", ethCalls[1].getString(1))
        assertEquals(eoa, ethCalls[1].getJSONObject(0).getString("from"))
        assertEquals(contract, ethCalls[0].getJSONObject(0).getString("to"))
    }

    @Test
    fun onlyTheTwoViewSelectorsAreEverSent() {
        val rpc = FakeRpc(recordHex = encodeRecord("", "", "", false), backupHex = encodeOneString(""))
        AddressPgpRead.snapshot(rpc, contract, eoa).getOrThrow()
        val sent = rpc.calls.filter { it.first == "eth_call" }.map { it.second.getJSONObject(0).getString("data").substring(0, 10) }
        assertEquals(
            setOf(AddressPgpRead.selector(AddressPgpRead.SIG_PGP_KEYS), AddressPgpRead.selector(AddressPgpRead.SIG_ENCRYPTED_BACKUP)),
            sent.toSet(),
        )
    }

    @Test
    fun aTransportFailureIsSourceUnavailableNotAbsence() {
        val failing = AddressPgpRead.Rpc { _, _ -> error("timeout") }
        val r = AddressPgpRead.snapshot(failing, contract, eoa)
        assertTrue(r.isFailure)
        assertEquals(AddressPgpRead.SOURCE_UNAVAILABLE, r.exceptionOrNull()!!.message)
    }

    @Test
    fun aMalformedRecordIsSourceUnavailableNotNoRecord() {
        val rpc = FakeRpc(recordHex = "0x", backupHex = encodeOneString(""))
        val r = AddressPgpRead.snapshot(rpc, contract, eoa)
        assertEquals(AddressPgpRead.SOURCE_UNAVAILABLE, r.exceptionOrNull()!!.message)
    }

    @Test
    fun theHttpTransportAcceptsOnlyHttps() {
        try {
            AddressPgpRead.HttpRpc("http://rpc.example.invalid")
            fail("plain http must be refused")
        } catch (_: IllegalArgumentException) {
        }
    }
}
