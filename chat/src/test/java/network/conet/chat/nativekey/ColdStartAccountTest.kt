package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * R488: the bound account survives a cold start. The address is persisted beside the pointer (`account_address.v1`), and a cold start restores it
 * before the copy is searched (§25.52T.4, §25.52AD.2). The device has two copies in these cases, one of them the copy of another account, so the
 * copy search finds no single account, and only the persisted address can answer.
 *
 * Each "process" builds its own flags and bridge over the same device storage ([device]) and the same Keystore key ([wrap]). The restart keeps
 * the storage and the key, and drops the bound account that lives in memory.
 */
class ColdStartAccountTest {
    private val a1 = DerivedAccount.ADDRESS
    private val a2 = DerivedAccount.ADDRESS2
    private val wrap = NativeTestWrap()
    private val device = NativeTestFiles()

    private fun storeOf(eoa: String): SealedPageRecordStore = SealedPageRecordStore(wrap, device, eoa.lowercase() + ":default")

    private fun heldRecord(rev: Int, eoa: String): JSONObject = JSONObject().put("rev", rev).put("schemaVersion", 2)
        .put("profiles", JSONArray().put(JSONObject().put("keyID", eoa).put("privateKeyArmor", if (eoa == a2) DerivedAccount.KEY2 else DerivedAccount.KEY)))
        .put("mnemonicPhrase", "M")

    /** One process: the account resolution as the shell runs it under G0 (no vault record), with [bound] as this process's import. */
    private fun process(flags: DeviceFlags, bound: String?): ShellRecordBridge = ShellRecordBridge(
        account = {
            ShellRecordAccounts.resolve(
                vault = NativeWalletVault.State.NoKey,
                sessionReady = false,
                sessionGate = true,
                bound = bound,
                copyNames = { device.map.keys.toList() },
                storeOf = { eoa -> storeOf(eoa) },
                persisted = { flags.accountAddress() },
            )
        },
        migrating = { false },
        outcome = { null },
        flags = flags,
    )

    private fun read(bridge: ShellRecordBridge): JSONObject = bridge.handle(
        ShellOrigin.EMBEDDED_PAGE,
        JSONObject().put("type", "shellRecordRead").put("reqId", "r"),
        0,
    ).v()

    private fun write(bridge: ShellRecordBridge, rev: Int, eoa: String = a1): JSONObject = bridge.handle(
        ShellOrigin.EMBEDDED_PAGE,
        JSONObject().put("type", "shellRecordWrite").put("reqId", "w$rev").put("record", heldRecord(rev, eoa)),
        0,
    ).v()

    @Test
    fun coldStartReadAndWriteHitTheOriginalAccount() {
        // Before the restart: the account is bound and its copy is held. A stale copy of another account is on the device too.
        storeOf(a1).write(heldRecord(1, a1))
        storeOf(a2).write(heldRecord(1, a2))
        val before = DeviceFlagFiles(device)
        before.setAccountPointer()
        assertEquals(2, write(process(before, bound = a1), rev = 1).getInt("rev"))
        // The write in this process persisted the address (R488).
        assertEquals(a1, DeviceFlagFiles(device).accountAddress())

        // The restart: nothing bound in memory. The read and the write still reach the original account.
        val cold = process(DeviceFlagFiles(device), bound = null)
        val r = read(cold)
        assertEquals("ok", r.getString("code"))
        assertEquals(2, r.getJSONObject("record").getInt("rev"))
        assertEquals(3, write(cold, rev = 2).getInt("rev"))
        assertEquals(3, storeOf(a1).read()!!.getInt("rev"))
        assertEquals("the other account is not touched", 1, storeOf(a2).read()!!.getInt("rev"))
    }

    @Test
    fun withTwoCopiesTheCopySearchFindsNoAccountWithoutTheAddress() {
        storeOf(a1).write(heldRecord(1, a1))
        storeOf(a2).write(heldRecord(1, a2))
        val flags = DeviceFlagFiles(device)
        assertEquals(ShellRecordAccount.Unknown, ShellRecordAccounts.resolve(
            vault = NativeWalletVault.State.NoKey, sessionReady = false, sessionGate = true, bound = null,
            copyNames = { device.map.keys.toList() }, storeOf = { eoa -> storeOf(eoa) }, persisted = { flags.accountAddress() },
        ))
        // With the address persisted, the same two copies give the bound account.
        flags.setAccountAddress(a1)
        assertEquals("ok", read(process(DeviceFlagFiles(device), bound = null)).getString("code"))
    }

    @Test
    fun theAddressFileRoundTripsAndAMalformedOneIsIgnored() {
        assertNull(DeviceFlagFiles(device).accountAddress())
        DeviceFlagFiles(device).setAccountAddress(a1.uppercase().replace("0X", "0x"))
        assertEquals(a1, DeviceFlagFiles(device).accountAddress())
        device.write(DeviceFlagFiles.ADDRESS, "not an address".toByteArray(Charsets.UTF_8))
        assertNull(DeviceFlagFiles(device).accountAddress())
        assertNull(NoDeviceFlags.accountAddress())
    }

    @Test
    fun aDeviceWithOnlyThePointerAndOneCopyRecoversTheAddressOnTheFirstRead() {
        // An earlier build left the pointer and the copy but no address. The copy search finds the one account, and the first read that
        // holds its key persists the address, so the next cold start no longer depends on the search.
        storeOf(a1).write(heldRecord(1, a1))
        DeviceFlagFiles(device).setAccountPointer()
        assertEquals("ok", read(process(DeviceFlagFiles(device), bound = null)).getString("code"))
        assertEquals(a1, DeviceFlagFiles(device).accountAddress())
        assertTrue(DeviceFlagFiles(device).accountPointer())
    }
}
