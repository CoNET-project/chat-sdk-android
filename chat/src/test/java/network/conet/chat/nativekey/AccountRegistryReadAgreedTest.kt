package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * `AccountRegistryRead.readAgreed` (draft r2.5.20 第 7 版, the same rule as the binding lookup): the name-record reads of the recovery path. Both
 * endpoints at one block, the same hash, and the same text; a single empty answer is never "no record".
 */
class AccountRegistryReadAgreedTest {
    private val registry = "0x" + "11".repeat(20)
    private val ep1 = RegistryEndpoint("https://rpc1.conet.network", 12_000)
    private val ep2 = RegistryEndpoint("https://publicrpc.conet.network", 12_000)
    private val config = RegistryConfig(registry, listOf(ep1, ep2))
    private val data = AccountRegistryRead.callDataByAccountName("alice")
    private val hash = "0x" + "cd".repeat(32)

    private fun word(v: Long): ByteArray = ByteArray(32).also { w ->
        for (i in 0 until 8) w[31 - i] = ((v shr (8 * i)) and 0xFF).toByte()
    }

    /** The `string` return of a call: the offset word and the string (an empty string for "no record"). */
    private fun textHex(s: String): String {
        val b = s.toByteArray(Charsets.UTF_8)
        val padded = b + ByteArray((32 - b.size % 32) % 32)
        return "0x" + (word(32) + word(b.size.toLong()) + padded).joinToString("") { "%02x".format(it) }
    }

    /** One node: block [block] with [hash], and the text of the call, or a failure of the named call. */
    private inner class Node(
        val block: String? = "0x64",
        val hash: String = "0x" + "cd".repeat(32),
        val text: String? = "",
        val failOn: String? = null,
    ) : AddressPgpRead.Rpc {
        override fun call(method: String, params: JSONArray): Any? {
            if (failOn == method) error("down")
            return when (method) {
                "eth_blockNumber" -> block ?: error("down")
                "eth_getBlockByNumber" -> JSONObject().put("number", block ?: error("down")).put("hash", hash)
                "eth_call" -> textHex(text ?: error("down"))
                else -> error("unexpected $method")
            }
        }
    }

    private fun read(a: Node, b: Node): String? = AccountRegistryRead.readAgreed(config, { ep -> if (ep == ep1) a else b }, data)

    @Test
    fun bothEmptyAtOneBlockIsNoRecord() {
        assertNull(read(Node(text = ""), Node(text = "")))
    }

    @Test
    fun bothAgreeOnTheText() {
        assertEquals("alice-record", read(Node(text = "alice-record"), Node(text = "alice-record")))
    }

    @Test
    fun aSingleEmptyAnswerIsNotNoRecord() {
        assertThrows(IllegalStateException::class.java) { read(Node(text = ""), Node(text = "x")) }
        assertThrows(IllegalStateException::class.java) { read(Node(text = "x"), Node(text = "")) }
    }

    @Test
    fun aDisagreementIsAnError() {
        assertThrows(IllegalStateException::class.java) { read(Node(text = "a"), Node(text = "b")) }
    }

    @Test
    fun anEndpointAtAnotherBlockIsAnError() {
        assertThrows(IllegalStateException::class.java) { read(Node(block = "0x64"), Node(block = "0x65", text = "")) }
    }

    @Test
    fun aHashMismatchIsAnError() {
        assertThrows(IllegalStateException::class.java) { read(Node(text = ""), Node(text = "", hash = "0x" + "11".repeat(32))) }
    }

    @Test
    fun aFailedCallOrBlockReadIsAnError() {
        assertThrows(IllegalStateException::class.java) { read(Node(text = ""), Node(failOn = "eth_call")) }
        assertThrows(IllegalStateException::class.java) { read(Node(text = ""), Node(failOn = "eth_getBlockByNumber")) }
        assertThrows(IllegalStateException::class.java) { read(Node(block = null), Node()) }
    }

    @Test
    fun aSingleEndpointConfigurationIsAnErrorNeverNoRecord() {
        val one = RegistryConfig(registry, listOf(ep1))
        assertThrows(IllegalStateException::class.java) { AccountRegistryRead.readAgreed(one, { Node(text = "") }, data) }
    }
}
