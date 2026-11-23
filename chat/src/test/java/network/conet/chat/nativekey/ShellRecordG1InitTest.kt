package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The G1 -> G2 transition of `shellRecordRead` with a native record and a valid page copy (spec 25.26.4c, 25.52AD.4 第 2 步; the
 * independent review gap of E9.11.33 r2-amend6). Before a successful init the session gate is closed, so the answer is `not_ready`
 * (G1, notReadyReason `g1_uninitialized`). After the init the same request answers `ok`.
 *
 * Limits (not covered here): [NativeSessionState.markReady] simulates the init, it does not run handleInit; the snapshot refresh path
 * (VaultSnapshotRefresh) is not covered. The reason assertion uses NoKeyGate.notReadyReasonOf, not the shellRecordRead envelope. The account is resolved by the same pure
 * resolver the shell uses; the session flag is the one the module sets on a successful init.
 */
class ShellRecordG1InitTest {
    private val eoa = DerivedAccount.ADDRESS
    private val wrap = NativeTestWrap()
    private val device = NativeTestFiles()

    @Before
    fun startWithoutASession() {
        NativeSessionState.reset()
    }

    @After
    fun endWithoutASession() {
        NativeSessionState.reset()
    }

    /** The native record holds the EOA key; the page copy holds the same account key (the state after a successful import). */
    private fun vaultWithRecordAndCopy(): Pair<NativeWalletVault.State, SealedPageRecordStore> {
        val store = SealedPageRecordStore(wrap, device, "$eoa:default")
        val profiles = JSONArray().put(JSONObject().put("keyID", eoa).put("address", eoa).put("privateKeyArmor", DerivedAccount.KEY))
        store.write(JSONObject().put("rev", 1).put("schemaVersion", 2).put("profiles", profiles))
        return NativeWalletVault.State.Ready(eoa) to store
    }

    private fun bridge(vault: NativeWalletVault.State, store: SealedPageRecordStore): ShellRecordBridge = ShellRecordBridge(
        account = {
            ShellRecordAccounts.resolve(
                vault = vault,
                sessionReady = NativeSessionState.isReady(),
                sessionGate = true,
                bound = null,
                copyNames = { device.map.keys.toList() },
                storeOf = { store },
                persisted = { null },
            )
        },
        migrating = { false },
        outcome = { null },
        flags = NoDeviceFlags,
    )

    /** The raw answer, before the vocabulary view: the envelope shape is asserted, not only the code (ShellAckView maps `error` to `code`). */
    private fun readRaw(bridge: ShellRecordBridge): JSONObject = bridge.handle(
        ShellOrigin.EMBEDDED_PAGE,
        JSONObject().put("type", "shellRecordRead").put("reqId", "g1"),
        0,
    )

    /** G1: an error envelope `ok:false, error:not_ready` with no `result`; not a business result `{ok:true, result:{code:not_ready}}`. */
    private fun assertNotReadyRaw(bridge: ShellRecordBridge) {
        val raw = readRaw(bridge)
        assertEquals("not_ready", raw.getString("error"))
        assertEquals(false, raw.getBoolean("ok"))
        assertFalse("no result on an error envelope", raw.has("result"))
    }

    /** G2 with a valid copy: `ok:true` and `result.code == "ok"`. */
    private fun assertOkRaw(bridge: ShellRecordBridge) {
        val raw = readRaw(bridge)
        assertEquals("ack", raw.getString("type"))
        assertEquals(true, raw.getBoolean("ok"))
        assertEquals("ok", raw.getJSONObject("result").getString("code"))
    }

    @Test
    fun beforeInitTheValidCopyIsNotReadyG1() {
        val (vault, store) = vaultWithRecordAndCopy()
        // The gate before init: a record with no successful init is G1, and the reason is g1_uninitialized.
        assertEquals(NoKeyGate.Gate.G1, NoKeyGate.gateOf(vault, NativeSessionState.isReady()))
        assertEquals("g1_uninitialized", NoKeyGate.notReadyReasonOf(vault))
        assertNotReadyRaw(bridge(vault, store))
    }

    @Test
    fun afterASuccessfulInitTheSameRequestAnswersOk() {
        val (vault, store) = vaultWithRecordAndCopy()
        assertNotReadyRaw(bridge(vault, store))
        // The module sets the session flag only after a successful init (NativeSessionState.markReady).
        NativeSessionState.markReady("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa")
        assertEquals(NoKeyGate.Gate.G2, NoKeyGate.gateOf(vault, NativeSessionState.isReady()))
        assertOkRaw(bridge(vault, store))
    }

    @Test
    fun aClearedSessionReturnsTheSameRequestToNotReady() {
        val (vault, store) = vaultWithRecordAndCopy()
        NativeSessionState.markReady("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa")
        assertOkRaw(bridge(vault, store))
        // G2 -> G1 on destroy or clear (25.26.4c): the record and the copy stay, the answer is not_ready again.
        NativeSessionState.reset()
        assertTrue("the record is still there", vault is NativeWalletVault.State.Ready)
        assertNotReadyRaw(bridge(vault, store))
    }
}
