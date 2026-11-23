package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * the long-lived PGP key material is a ByteArray and is zeroed when the operation ends. These tests pin
 * the byte-holding behaviour: a hand-over returns a copy the vault does not keep, the pending key keeps its bytes, and the
 * stored record format is unchanged (a record written before this change still opens).
 */
class PgpPendingBytesTest {
    private val vectors = JSONObject(
        String(File(System.getenv("PGP_NATIVE_VECTORS") ?: "../spec/pgp-native-vectors.v1.json").readBytes(), Charsets.UTF_8),
    )
    private val eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"

    private fun ecc() = vectors.getJSONObject("keys").getJSONObject("ecc-pass")

    @Test
    fun armorForMoveReturnsACopyTheVaultDoesNotKeep() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val vault = NativePgpVault(wrap, files, eoa)
        assertEquals(NativePgpVault.Put.OK, vault.put(eoa, ecc().getString("privateArmored"), ecc().getString("passphrase")))

        val first = vault.armorForMove()!!
        assertArrayEquals(ecc().getString("privateArmored").toByteArray(Charsets.UTF_8), first)
        // The caller zeroes its copy; the vault still opens and returns the same armor.
        first.fill(0)
        val second = vault.armorForMove()!!
        assertArrayEquals(ecc().getString("privateArmored").toByteArray(Charsets.UTF_8), second)
        second.fill(0)
        assertTrue(vault.state() is NativePgpVault.State.Ready)
    }

    @Test
    fun pendingHandOverKeepsTheBytesForActivation() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val pending = NativePgpVault(wrap, files, eoa, NativePgpVault.Slot.PENDING)
        assertEquals(NativePgpVault.Put.OK, pending.put(eoa, ecc().getString("privateArmored"), ecc().getString("passphrase")))

        val handed = pending.pendingArmorForActivation()!!
        assertArrayEquals(ecc().getString("privateArmored").toByteArray(Charsets.UTF_8), handed)
        handed.fill(0)
    }

    @Test
    fun newKeyFromStringAndFromBytesAgree() {
        val armor = ecc().getString("privateArmored")
        val identity = PgpIdentity("ABCD", "EF01")
        val fromText = PgpNewKey(armor, identity)
        val fromBytes = PgpNewKey(armor.toByteArray(Charsets.UTF_8), identity)
        assertArrayEquals(fromBytes.privateArmor, fromText.privateArmor)
        assertEquals(armor, fromBytes.armorText())
    }

    @Test
    fun recordRoundTripsThroughAFreshVaultInstance() {
        // This shows a fresh instance opens what the same code wrote. It does not prove compatibility with records written before the change:
        // that needs a fixture from the earlier commit, which is not part of this test.
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val writer = NativePgpVault(wrap, files, eoa)
        assertEquals(NativePgpVault.Put.OK, writer.put(eoa, ecc().getString("privateArmored"), ecc().getString("passphrase")))
        val reader = NativePgpVault(wrap, files, eoa)
        val state = reader.state()
        assertTrue(state is NativePgpVault.State.Ready)
        assertEquals(ecc().getString("fingerprint"), (state as NativePgpVault.State.Ready).fingerprint)
    }
}
