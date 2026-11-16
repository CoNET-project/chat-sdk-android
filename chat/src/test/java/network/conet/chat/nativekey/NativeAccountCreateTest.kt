package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.math.BigInteger

/**
 * Native account creation (spec r3w §25.46, acceptance T-237 to T-240). `native-account-create-vectors.v1.json` is not yet
 * authored by the interface owner (§25.46.9), so these cases follow the spec text and use the BIP-39 reference vectors.
 */
class NativeAccountCreateTest {
    private val payloads = mutableListOf<JSONObject>()
    private val zeroEntropy = ByteArray(16)
    private val abandonAbout =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val eoaOfAbandon = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

    private fun scalar(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        val n = minOf(raw.size, 32)
        System.arraycopy(raw, raw.size - n, out, 32 - n, n)
        return out
    }

    private val keyA = scalar(BigInteger.ONE)
    private val eoaA = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"

    @Before
    fun setUp() {
        payloads.clear()
        NativeAccountCreateHost.resetForTests()
        NativeAccountCreateHost.launcher = null
        NativeAccountCreateHost.events = { payloads.add(it) }
    }

    @After
    fun tearDown() {
        NativeAccountCreateHost.events = null
        NativeAccountCreateHost.pageClosed()
        NativeAccountCreateHost.launcher = null
    }

    private fun keysOf(o: JSONObject): Set<String> = o.keys().asSequence().map { it.toString() }.toSet()

    // ---- T-237: gate -------------------------------------------------------------------------

    @Test
    fun g0OpensTheRegisteredPageAndAnswersOk() {
        var opened = 0
        NativeAccountCreateHost.launcher = { opened++; true }
        val r = NativeOpenRules.accountCreateOpen(listOf("type", "reqId", "account"), "A-1", "alice", NoKeyGate.Gate.G0, NativeOpenRules.accountHost)
        assertTrue(r.ok)
        assertEquals(1, opened)
    }

    @Test
    fun g1AndG2AnswerNotAvailableAndDoNotOpenThePage() {
        var opened = 0
        NativeAccountCreateHost.launcher = { opened++; true }
        for (g in listOf(NoKeyGate.Gate.G1, NoKeyGate.Gate.G2)) {
            val r = NativeOpenRules.accountCreateOpen(listOf("type", "reqId", "account"), "A-1", "alice", g, NativeOpenRules.accountHost)
            assertEquals("not_available", r.error)
        }
        assertEquals(0, opened)
    }

    @Test
    fun anUnregisteredPageIsNotSupportedInEveryGate() {
        NativeAccountCreateHost.launcher = null
        for (g in NoKeyGate.Gate.values()) {
            val r = NativeOpenRules.accountCreateOpen(listOf("type", "reqId", "account"), "A-1", "alice", g, NativeOpenRules.accountHost)
            assertEquals("not_supported", r.error)
        }
    }

    @Test
    fun aPageThatRefusesOrThrowsIsNotAvailable() {
        NativeAccountCreateHost.launcher = { false }
        assertEquals(
            "not_available",
            NativeOpenRules.accountCreateOpen(listOf("type", "reqId", "account"), "A-1", "alice", NoKeyGate.Gate.G0, NativeOpenRules.accountHost).error,
        )
        NativeAccountCreateHost.launcher = { throw IllegalStateException("no activity") }
        assertEquals(
            "not_available",
            NativeOpenRules.accountCreateOpen(listOf("type", "reqId", "account"), "A-1", "alice", NoKeyGate.Gate.G0, NativeOpenRules.accountHost).error,
        )
    }

    // ---- T-238: input and reply ----------------------------------------------------------------

    @Test
    fun anExtraFieldIsBadRequest() {
        NativeAccountCreateHost.launcher = { true }
        val r = NativeOpenRules.accountCreateOpen(listOf("type", "reqId", "mode", "account"), "A-1", "alice", NoKeyGate.Gate.G0, NativeOpenRules.accountHost)
        assertEquals("bad_request", r.error)
    }

    @Test
    fun aCredentialOrKeyFieldIsRefusedBeforeAnyOtherCheck() {
        NativeAccountCreateHost.launcher = { true }
        for (field in listOf("password", "privateKeyHex", "mnemonic", "recoveryCode")) {
            val r = NativeOpenRules.accountCreateOpen(
                listOf("type", "reqId", "extra", field, "account"), "A-1", "alice", NoKeyGate.Gate.G0, NativeOpenRules.accountHost,
            )
            assertEquals("key_over_bridge_refused", r.error)
        }
    }

    @Test
    fun aMissingReqIdIsBadRequestAndAStringReqIdIsEchoed() {
        NativeAccountCreateHost.launcher = { true }
        assertEquals(
            "bad_request",
            NativeOpenRules.accountCreateOpen(listOf("type", "account"), null, "alice", NoKeyGate.Gate.G0, NativeOpenRules.accountHost).error,
        )
        val r = NativeOpenRules.accountCreateOpen(listOf("type", "reqId", "account"), "N-1", "alice", NoKeyGate.Gate.G0, NativeOpenRules.accountHost)
        assertEquals("N-1", NativeOpenRules.ackPayload("N-1", r).get("reqId"))
        assertTrue(NativeOpenRules.ackPayload("N-1", r).getBoolean("ok"))
    }

    @Test
    fun anAccountIsRequiredAndMustBeABeamioTagOrACanonicalEoa() {
        // §25.52Z.2: BeamioTag 1 to 64 visible ASCII, not starting with 0x; EOA 0x plus 40 lowercase hex. Else bad_request.
        NativeAccountCreateHost.launcher = { true }
        val fields = listOf("type", "reqId", "account")
        val good = listOf("alice", "0x9858effd232b4033e47d90003d41ec34ecaeda94", "a".repeat(64))
        for (acc in good) {
            val r = NativeOpenRules.accountCreateOpen(fields, "N-A", acc, NoKeyGate.Gate.G0, NativeOpenRules.accountHost)
            assertTrue(acc, r.ok)
        }
        val bad: List<Any?> = listOf(
            null, "", "a".repeat(65), "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "0x1234", "0xabc", "has space", 42,
        )
        for (acc in bad) {
            val r = NativeOpenRules.accountCreateOpen(fields, "N-A", acc, NoKeyGate.Gate.G0, NativeOpenRules.accountHost)
            assertEquals(acc.toString(), "bad_request", r.error)
        }
    }

    @Test
    fun aSuccessfulOpenAcksPageOpenedAndTheOtherCommandsDoNot() {
        NativeAccountCreateHost.launcher = { true }
        val ok = NativeOpenRules.accountCreateOpen(
            listOf("type", "reqId", "account"), "N-P", "alice", NoKeyGate.Gate.G0, NativeOpenRules.accountHost,
        )
        val payload = NativeOpenRules.ackPayload("N-P", ok)
        assertEquals("opened", payload.getString("page"))
        assertFalse(payload.has("error"))
        val refused = NativeOpenRules.ackPayload("N-R", NativeOpenRules.Reply("not_available"))
        assertFalse(refused.has("page"))
    }

    // ---- T-239: generation, write, readback, rollback ---------------------------------------

    @Test
    fun theBip39PhraseMatchesTheReferenceVectors() {
        assertEquals(abandonAbout, NativeAccountCreate.phraseOf(zeroEntropy))
        assertEquals(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            NativeAccountCreate.phraseOf(ByteArray(16) { 0x7f }),
        )
    }

    @Test
    fun aNewVaultGetsAKeyAndTheLowercaseAddressOfTheDerivedAccount() {
        val files = NativeTestFiles()
        val vault = NativeWalletVault(NativeTestWrap(), files)
        val r = NativeAccountCreate.create(vault, memoryAccountPgpK(), zeroEntropy)
        assertEquals(NativeAccountCreate.Code.OK, r.code)
        assertEquals(eoaOfAbandon, r.eoa)
        assertEquals(eoaOfAbandon, (vault.state() as NativeWalletVault.State.Ready).eoa)
        val key = vault.unlock()!!
        assertEquals(eoaOfAbandon, WalletAddress.fromPrivateKey(key))
        key.fill(0)
    }

    @Test
    fun aCallerEntropyArrayIsNotModified() {
        val entropy = ByteArray(16) { 3 }
        NativeAccountCreate.create(NativeWalletVault(NativeTestWrap(), NativeTestFiles()), memoryAccountPgpK(), entropy)
        assertArrayEquals(ByteArray(16) { 3 }, entropy)
    }

    @Test
    fun anExistingRecordIsNeverOverwritten() {
        val files = NativeTestFiles()
        val vault = NativeWalletVault(NativeTestWrap(), files)
        assertEquals(NativeWalletVault.Import.OK, vault.importKey(eoaA, keyA))
        val before = files.map.mapValues { it.value.copyOf() }
        val r = NativeAccountCreate.create(vault, memoryAccountPgpK(), zeroEntropy)
        assertEquals(NativeAccountCreate.Code.ALREADY_EXISTS, r.code)
        // 25.52X.4 (rc2.2-qa): the readable existing key's public lower-case EOA is carried on already_exists.
        assertEquals(eoaA, r.eoa)
        assertEquals(eoaA, (vault.state() as NativeWalletVault.State.Ready).eoa)
        assertEquals(before.keys, files.map.keys)
        for ((k, v) in before) assertArrayEquals(v, files.map[k])
    }

    @Test
    fun aLockedRecordIsAlreadyExistsToo() {
        val files = NativeTestFiles()
        val vault = NativeWalletVault(NativeTestWrap(), files)
        assertEquals(NativeWalletVault.Import.OK, vault.importKey(eoaA, keyA))
        files.map[NativeWalletVault.MARK] = byteArrayOf(1, 2, 3)
        assertTrue(vault.state() is NativeWalletVault.State.Locked)
        assertEquals(NativeAccountCreate.Code.ALREADY_EXISTS, NativeAccountCreate.create(vault, memoryAccountPgpK(), zeroEntropy).code)
        assertTrue(files.map.containsKey(NativeWalletVault.REC))
    }

    @Test
    fun aFailedWriteRollsBackAndLeavesNoKey() {
        val files = NativeTestFiles()
        files.failWrite = NativeWalletVault.REC
        val vault = NativeWalletVault(NativeTestWrap(), files)
        val r = NativeAccountCreate.create(vault, memoryAccountPgpK(), zeroEntropy)
        assertEquals(NativeAccountCreate.Code.WRITE_FAILED, r.code)
        assertNull(r.eoa)
        assertTrue(vault.state() is NativeWalletVault.State.NoKey)
        assertTrue(files.map.isEmpty())
    }

    @Test
    fun aFailedWrappingRollsBackAndLeavesNoKey() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap().apply { failSeal = true }
        val vault = NativeWalletVault(wrap, files)
        assertEquals(NativeAccountCreate.Code.WRITE_FAILED, NativeAccountCreate.create(vault, memoryAccountPgpK(), zeroEntropy).code)
        assertTrue(vault.state() is NativeWalletVault.State.NoKey)
        assertTrue(files.map.isEmpty())
    }

    @Test
    fun aFailedReadbackRollsBackAndLeavesNoKey() {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap().apply { openOverride = { ByteArray(32) { 7 } } }
        val vault = NativeWalletVault(wrap, files)
        val r = NativeAccountCreate.create(vault, memoryAccountPgpK(), zeroEntropy)
        assertEquals(NativeAccountCreate.Code.READBACK_FAILED, r.code)
        assertTrue(vault.state() is NativeWalletVault.State.NoKey)
        assertTrue(files.map.isEmpty())
    }

    // ---- T-240: result and boundaries ---------------------------------------------------------

    @Test
    fun aFailureKeepsThePageOpenAndAnOkEndsIt() {
        NativeAccountCreateHost.launcher = { true }
        assertTrue(NativeAccountCreateHost.open("A-1"))
        NativeAccountCreateHost.finish(NativeAccountCreate.Code.WRITE_FAILED, null)
        assertEquals(1, payloads.size)
        assertEquals(setOf("type", "reqId", "code"), keysOf(payloads[0]))
        assertEquals("nativeAccountCreateResult", payloads[0].getString("type"))
        assertEquals("A-1", payloads[0].get("reqId"))
        assertEquals("write_failed", payloads[0].getString("code"))

        // The page is still open after a failure, so a retry can succeed.
        NativeAccountCreateHost.finish(NativeAccountCreate.Code.OK, eoaOfAbandon)
        assertEquals(2, payloads.size)
        assertEquals(setOf("type", "reqId", "code", "eoa"), keysOf(payloads[1]))
        assertEquals(eoaOfAbandon, payloads[1].getString("eoa"))

        // ok ends the page: nothing more is sent when it closes.
        NativeAccountCreateHost.pageClosed()
        assertEquals(2, payloads.size)
    }

    @Test
    fun aPageClosedBeforeAnyResultSendsCancelledOnce() {
        NativeAccountCreateHost.launcher = { true }
        NativeAccountCreateHost.open("A-2")
        NativeAccountCreateHost.pageClosed()
        NativeAccountCreateHost.pageClosed()
        assertEquals(1, payloads.size)
        assertEquals("cancelled", payloads[0].getString("code"))
        assertEquals("A-2", payloads[0].get("reqId"))
        assertFalse(payloads[0].has("eoa"))
    }

    @Test
    fun aPageClosedAfterAFailureSendsNothingMore() {
        NativeAccountCreateHost.launcher = { true }
        NativeAccountCreateHost.open("A-3")
        NativeAccountCreateHost.finish(NativeAccountCreate.Code.READBACK_FAILED, null)
        NativeAccountCreateHost.pageClosed()
        assertEquals(1, payloads.size)
        assertEquals("readback_failed", payloads[0].getString("code"))
    }

    @Test
    fun resultsCarryOnlyThePublicAddressAndCodeNeverKeyMaterial() {
        NativeAccountCreateHost.launcher = { true }
        NativeAccountCreateHost.open("A-4")
        NativeAccountCreateHost.finish(NativeAccountCreate.Code.OK, eoaOfAbandon)
        val allowedKeys = setOf("type", "reqId", "code", "eoa")
        val forbidden = listOf("mnemonic", "phrase", "privateKey", "key", "seed", "recoveryCode", "pin", "password", "hash", "img", "stored")
        for (p in payloads) {
            assertTrue(keysOf(p).all { it in allowedKeys })
            assertTrue(keysOf(p).none { k -> forbidden.any { k.equals(it, ignoreCase = true) } })
            for (k in keysOf(p)) {
                val v = p.get(k).toString()
                assertFalse("value of $k looks like a phrase", v.contains(' '))
                assertFalse("value of $k looks like a 32-byte key", Regex("0x[0-9a-fA-F]{64}").containsMatchIn(v))
            }
        }
    }

    @Test
    fun aLauncherThatThrowsLeavesNoPageOpenForResults() {
        NativeAccountCreateHost.launcher = { throw IllegalStateException("no activity") }
        assertFalse(NativeAccountCreateHost.open("A-5"))
        NativeAccountCreateHost.pageClosed()
        assertTrue(payloads.isEmpty())
    }
}
