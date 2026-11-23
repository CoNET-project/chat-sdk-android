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

    private val hash = "0x" + "cd".repeat(32)

    /**
     * Both endpoints answer at block 100 (0x64) with one hash unless the case changes it. [answer] is the eth_call answer per url; [block] and
     * [tagOf] change the block reads per url.
     */
    private class Fake(
        private val block: (String) -> BlockRef? = { BlockRef("0x64", "0x" + "cd".repeat(32)) },
        private val tagOf: (String) -> String? = { "0x64" },
        private val answer: (String, String, Long) -> EthCallResult,
    ) : EthTransport {
        var lastTimeout: Long? = null
        var calls = 0
        val tags = mutableListOf<String>()
        val blockReads = mutableListOf<String>()
        override fun call(url: String, to: String, data: String, blockTag: String, timeoutMs: Long): EthCallResult {
            calls++
            tags += blockTag
            lastTimeout = timeoutMs
            return answer(url, data, timeoutMs)
        }
        override fun blockNumber(url: String, timeoutMs: Long): String? = tagOf(url)
        override fun blockByNumber(url: String, blockTag: String, timeoutMs: Long): BlockRef? {
            blockReads += url
            return block(url)
        }
    }

    private val eoa = "0x" + "ab".repeat(20)
    private val url = "https://rpc1.conet.network"

    private val backup = "https://publicrpc.conet.network"

    /** The agreed reader: two endpoints (draft r2.5.20 第 7 版). */
    private fun reader(t: EthTransport, now: Long = 0L) = twoEndpoints(t, now)

    private fun twoEndpoints(t: EthTransport, now: Long = 0L) =
        ChainRegistryReader(
            transport = t,
            registry = "0x" + "11".repeat(20),
            endpoints = listOf(RegistryEndpoint(url, 12_000), RegistryEndpoint(backup, 12_000)),
            nowMs = { now },
        )

    /** Draft r2.5.20 第 7 版: a single AccountNotFound is not absence; the other endpoint must say the same at the same block. */
    @Test
    fun aSingleNoRecordIsLookupUnavailableNotAbsence() {
        val t2 = Fake { u, _, _ -> if (u == url) EthCallResult.Reverted("0xfaba8ebe") else EthCallResult.Value(ownerHex("ab".repeat(20))) }
        assertTrue("a single absence is never absence", twoEndpoints(t2).readAccount(eoa, 10_000L) is RegistryRead.Invalid)
        val t3 = Fake { u, _, _ -> if (u == url) EthCallResult.Reverted("0xfaba8ebe") else EthCallResult.Failed(RawOutcome.TIMEOUT) }
        assertTrue(twoEndpoints(t3).readAccount(eoa, 10_000L) is RegistryRead.Invalid)
    }

    @Test
    fun bothNoRecordAtOneBlockIsAbsence() {
        val t = Fake { _, _, _ -> EthCallResult.Reverted("0xfaba8ebe") }
        assertTrue(twoEndpoints(t).readAccount(eoa, 10_000L) is RegistryRead.Absent)
        assertEquals(listOf("0x64", "0x64"), t.tags)
        assertEquals(listOf(url, backup), t.blockReads)
    }

    @Test
    fun aTimeoutOnEitherEndpointIsLookupUnavailable() {
        val t = Fake { u, _, _ -> if (u == url) EthCallResult.Failed(RawOutcome.TIMEOUT) else EthCallResult.Value(ownerHex("ab".repeat(20))) }
        assertTrue(twoEndpoints(t).readOwner("alice", 10_000L) is RegistryRead.Invalid)
    }

    @Test
    fun bothEndpointsAgreeOnAFoundOwner() {
        val addr = "ab".repeat(20)
        val t = Fake { _, _, _ -> EthCallResult.Value(ownerHex(addr)) }
        assertEquals("0x$addr", (twoEndpoints(t).readOwner("alice", 10_000L) as RegistryRead.Found).eoa)
    }

    @Test
    fun differentOwnersOnTheTwoEndpointsAreInvalid() {
        val t = Fake { u, _, _ -> EthCallResult.Value(ownerHex(if (u == url) "ab".repeat(20) else "cd".repeat(20))) }
        assertEquals("disagree", (twoEndpoints(t).readOwner("alice", 10_000L) as RegistryRead.Invalid).reason)
    }

    /** Draft RP-05 for the registry: B answers another block than N (even with A's hash): invalid. */
    @Test
    fun anEndpointAtAnotherBlockIsInvalid() {
        val t = Fake(answer = { _, _, _ -> EthCallResult.Reverted("0xfaba8ebe") }, block = { u -> if (u == url) BlockRef("0x64", hash) else BlockRef("0x65", hash) })
        assertEquals("block_mismatch", (twoEndpoints(t).readAccount(eoa, 10_000L) as RegistryRead.Invalid).reason)
        assertEquals(0, t.calls)
    }

    /** RP-08 analogue: both answer block 99 while N is 100: invalid. */
    @Test
    fun theBlockNumberMustBeTheBlockOfA() {
        val t = Fake(answer = { _, _, _ -> EthCallResult.Reverted("0xfaba8ebe") }, tagOf = { "0x63" }, block = { BlockRef("0x63", hash) })
        assertTrue(twoEndpoints(t).readAccount(eoa, 10_000L) is RegistryRead.Absent)
        assertEquals("both calls are at the block of A", listOf("0x63", "0x63"), t.tags)
    }

    /** Same number, different hash on the endpoints: invalid. */
    @Test
    fun aHashMismatchIsInvalid() {
        val t = Fake(answer = { _, _, _ -> EthCallResult.Reverted("0xfaba8ebe") }, block = { u -> BlockRef("0x64", if (u == url) hash else "0x" + "11".repeat(32)) })
        assertEquals("hash_mismatch", (twoEndpoints(t).readAccount(eoa, 10_000L) as RegistryRead.Invalid).reason)
    }

    @Test
    fun aFailedBlockReadIsLookupUnavailable() {
        val t = Fake(answer = { _, _, _ -> EthCallResult.Reverted("0xfaba8ebe") }, block = { u -> if (u == url) BlockRef("0x64", hash) else null })
        assertTrue(twoEndpoints(t).readAccount(eoa, 10_000L) is RegistryRead.Invalid)
    }

    @Test
    fun aSingleEndpointConfigurationIsInvalidNeverAbsent() {
        val t = Fake { _, _, _ -> EthCallResult.Reverted("0xfaba8ebe") }
        val one = ChainRegistryReader(transport = t, registry = "0x" + "11".repeat(20), endpoints = listOf(RegistryEndpoint(url, 12_000)), nowMs = { 0L })
        assertTrue(one.readAccount(eoa, 10_000L) is RegistryRead.Invalid)
        assertEquals(0, t.calls)
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

    /** The real answer of the current registry for a registered account (RealRegistryFixture, read-only from rpc1): the record decodes as bound. */
    @Test
    fun aRealRegisteredAccountDecodesAsFoundOnTheCurrentRegistry() {
        val t = Fake { _, _, _ -> EthCallResult.Value(RealRegistryFixture.GET_ACCOUNT_RESULT) }
        val r = reader(t).readAccount(RealRegistryFixture.REGISTERED_ACCOUNT, 10_000L)
        assertTrue(r is RegistryRead.Found)
        assertEquals(RegistryMapping.map(BindingKind.EOA, RawOutcome.BOUND).javaClass, r.javaClass)
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
    fun bothEndpointsAreReadAtTheSameBlock() {
        val urls = mutableListOf<String>()
        val t = Fake { u, _, _ -> urls += u; EthCallResult.Failed(RawOutcome.TIMEOUT) }
        reader(t).readOwner("alice", 10_000L)
        assertEquals(listOf(url, backup), urls)
        assertEquals(listOf("0x64", "0x64"), t.tags)
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
