package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The live registry reader (§25.52HH.1, HH.4, HI.2 and HI.3). The transport is a fake: no network. The ABI words are built here from the
 * `Account` layout of AccountRegistry.sol (12 head words, `exists` the tenth, `accountName` the first offset).
 */
class ChainRegistryReaderTest {

    private fun word(n: Int): String = "%064x".format(n)

    /** An `Account` tuple with the given existence and name, in the `getAccount` return encoding. */
    private fun accountHex(exists: Boolean, name: String): String {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val nameData = nameBytes.joinToString("") { "%02x".format(it) }.padEnd(((nameBytes.size + 31) / 32) * 64, '0')
        val head = StringBuilder()
        head.append(word(12 * 32)) // accountName offset, from the tuple start
        for (i in 1..8) head.append(word(0))
        head.append(word(if (exists) 1 else 0)) // exists (the tenth word)
        head.append(word(0)) // pgpKeyID offset (not read here)
        head.append(word(0)) // pgpKey offset (not read here)
        val tail = word(nameBytes.size) + nameData
        return "0x" + word(32) + head + tail
    }

    private fun ownerHex(addr: String?): String = "0x" + word(0).let { if (addr == null) it else "0".repeat(24) + addr.removePrefix("0x") }

    private class Fake(
        private val answer: (String, String, Long) -> EthCallResult,
    ) : EthTransport {
        var lastTimeout: Long? = null
        var calls = 0
        override fun call(url: String, to: String, data: String, timeoutMs: Long): EthCallResult {
            calls++
            lastTimeout = timeoutMs
            return answer(url, data, timeoutMs)
        }
    }

    private val eoa = "0x" + "ab".repeat(20)
    private val url = "https://rpc1.conet.network"

    private fun reader(t: EthTransport, now: Long = 0L) =
        ChainRegistryReader(transport = t, registry = "0x" + "11".repeat(20), endpoints = listOf(RegistryEndpoint(url, 12_000)), nowMs = { now })

    private val backup = "https://publicrpc.conet.network"

    private fun twoEndpoints(t: EthTransport, now: Long = 0L) =
        ChainRegistryReader(
            transport = t,
            registry = "0x" + "11".repeat(20),
            endpoints = listOf(RegistryEndpoint(url, 12_000), RegistryEndpoint(backup, 12_000)),
            nowMs = { now },
        )

    @Test
    fun aPrimaryNoRecordIsFinalAndTheBackupIsNeverQueried() {
        val urls = mutableListOf<String>()
        val t = Fake { u, _, _ -> urls += u; EthCallResult.Reverted("0xfaba8ebe") }
        assertTrue(twoEndpoints(t).readAccount(eoa, 10_000L) is RegistryRead.Absent)
        assertEquals(listOf(url), urls)
    }

    @Test
    fun aPrimaryTimeoutQueriesTheBackupWithinTheTotal() {
        val urls = mutableListOf<String>()
        val t = Fake { u, _, _ -> urls += u; if (u == url) EthCallResult.Failed(RawOutcome.TIMEOUT) else EthCallResult.Value(ownerHex("ab".repeat(20))) }
        val r = twoEndpoints(t).readOwner("alice", 10_000L) as RegistryRead.Found
        assertEquals("0x" + "ab".repeat(20), r.eoa)
        assertEquals(listOf(url, backup), urls)
    }

    @Test
    fun whenBothEndpointsFailTheResultIsInvalidNotAbsent() {
        val t = Fake { _, _, _ -> EthCallResult.Failed(RawOutcome.RPC_ERROR) }
        val r = twoEndpoints(t).readOwner("alice", 10_000L)
        assertTrue(r is RegistryRead.Invalid)
        assertEquals(2, t.calls)
    }

    @Test
    fun eachEndpointReadIsCappedAtFourSeconds() {
        val t = Fake { _, _, _ -> EthCallResult.Failed(RawOutcome.TIMEOUT) }
        twoEndpoints(t, now = 0L).readAccount(eoa, 10_000L)
        assertEquals(2, t.calls)
        assertEquals(4_000L, t.lastTimeout)
    }

    @Test
    fun anExactAccountNotFoundRevertIsAbsent() {
        val t = Fake { _, _, _ -> EthCallResult.Reverted("0xfaba8ebe") }
        assertTrue(reader(t).readAccount(eoa, 10_000L) is RegistryRead.Absent)
    }

    @Test
    fun aBoundAccountIsFoundWithoutAnEoa() {
        val t = Fake { _, _, _ -> EthCallResult.Value(accountHex(true, "alice")) }
        val r = reader(t).readAccount(eoa, 10_000L)
        assertTrue(r is RegistryRead.Found)
        assertEquals(null, (r as RegistryRead.Found).eoa)
    }

    @Test
    fun anAccountThatDoesNotExistIsNotAbsentButInvalid() {
        val t = Fake { _, _, _ -> EthCallResult.Value(accountHex(false, "")) }
        val r = reader(t).readAccount(eoa, 10_000L)
        assertEquals("exists_false", (r as RegistryRead.Invalid).reason)
    }

    @Test
    fun anExistingAccountWithAnEmptyNameIsInvalid() {
        val t = Fake { _, _, _ -> EthCallResult.Value(accountHex(true, "")) }
        assertEquals("semantic_failed", ((reader(t).readAccount(eoa, 10_000L)) as RegistryRead.Invalid).reason)
    }

    @Test
    fun aTimeoutOrTransportFailureIsInvalidNeverAbsent() {
        val t = Fake { _, _, _ -> EthCallResult.Failed(RawOutcome.TIMEOUT) }
        assertEquals("timeout", ((reader(t).readAccount(eoa, 10_000L)) as RegistryRead.Invalid).reason)
        val t2 = Fake { _, _, _ -> EthCallResult.Failed(RawOutcome.CONNECTION_REFUSED) }
        assertEquals("rpc_error", ((reader(t2).readOwner("alice", 10_000L)) as RegistryRead.Invalid).reason)
    }

    @Test
    fun aZeroOwnerIsAbsentAndAnOwnerIsFound() {
        val zero = Fake { _, _, _ -> EthCallResult.Value(ownerHex(null)) }
        assertTrue(reader(zero).readOwner("alice", 10_000L) is RegistryRead.Absent)
        val addr = "ab".repeat(20)
        val bound = Fake { _, _, _ -> EthCallResult.Value(ownerHex(addr)) }
        val r = reader(bound).readOwner("alice", 10_000L) as RegistryRead.Found
        assertEquals("0x$addr", r.eoa)
    }

    @Test
    fun highBitsInTheOwnerWordAreSemanticFailure() {
        val bad = "0x" + "1" + "0".repeat(63)
        val t = Fake { _, _, _ -> EthCallResult.Value(bad) }
        assertEquals("semantic_failed", ((reader(t).readOwner("alice", 10_000L)) as RegistryRead.Invalid).reason)
    }

    @Test
    fun aTruncatedOwnerWordIsDecodeFailure() {
        val t = Fake { _, _, _ -> EthCallResult.Value("0x" + "00".repeat(31)) }
        assertEquals("decode_failed", ((reader(t).readOwner("alice", 10_000L)) as RegistryRead.Invalid).reason)
    }

    @Test
    fun aPassedDeadlineIsBudgetExceededAndNoCallIsMade() {
        val t = Fake { _, _, _ -> EthCallResult.Value(accountHex(true, "alice")) }
        val r = reader(t, now = 20_000L).readAccount(eoa, deadlineMs = 10_000L)
        assertEquals("budget_exceeded", (r as RegistryRead.Invalid).reason)
        assertEquals(0, t.calls)
    }

    @Test
    fun eachReadIsCappedAtFourSecondsAndNeverPastTheTotal() {
        val t = Fake { _, _, _ -> EthCallResult.Failed(RawOutcome.TIMEOUT) }
        reader(t, now = 0L).readAccount(eoa, deadlineMs = 10_000L)
        assertEquals(4_000L, t.lastTimeout)
        reader(t, now = 8_000L).readAccount(eoa, deadlineMs = 10_000L)
        assertEquals(2_000L, t.lastTimeout)
    }

    @Test
    fun onlyTheCurrentPrimaryEndpointIsCalled() {
        var seen = ""
        val t = Fake { u, _, _ -> seen = u; EthCallResult.Failed(RawOutcome.TIMEOUT) }
        reader(t).readOwner("alice", 10_000L)
        assertEquals(url, seen)
        assertEquals(1, t.calls)
    }

    @Test
    fun theEnvelopeIsSortedIntoRevertValueAndFailure() {
        assertTrue(HttpEthTransport.parse("""{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"x","data":"0xfaba8ebe"}}""") is EthCallResult.Reverted)
        assertTrue(HttpEthTransport.parse("""{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}""") is EthCallResult.Failed)
        assertTrue(HttpEthTransport.parse("not json") is EthCallResult.Failed)
        assertTrue(HttpEthTransport.parse("""{"jsonrpc":"2.0","id":1}""") is EthCallResult.Failed)
        assertTrue(HttpEthTransport.parse("""{"jsonrpc":"2.0","id":1,"result":"0x00"}""") is EthCallResult.Value)
    }

    @Test
    fun theAddressArgumentMustBeLowerCaseHex() {
        assertEquals(null, ChainRegistryReader.addressWord("0xAB" + "ab".repeat(19)))
        assertEquals(64, ChainRegistryReader.addressWord(eoa)!!.length)
    }
}
