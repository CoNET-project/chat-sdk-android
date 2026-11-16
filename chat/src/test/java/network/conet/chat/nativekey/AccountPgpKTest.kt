package network.conet.chat.nativekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** K (§25.52Y.1): the account PGP item, its naming and format, and the binding local sources it feeds (HH.2, §25.48.4). */
class AccountPgpKTest {
    private val eoa = "0x" + "ab".repeat(20)
    private val other = "0x" + "cd".repeat(20)
    private val ws = "default"

    /** A map-backed store. */
    private class MemBackend : AccountPgpKBackend {
        val items = mutableMapOf<String, String>()
        var writeOk = true
        override fun get(name: String): String? = items[name]
        override fun put(name: String, value: String): Boolean {
            if (!writeOk) return false
            items[name] = value
            return true
        }
        override fun names(): Set<String> = items.keys.toSet()
    }

    /** A store that cannot be read: every call throws, as an unopenable encrypted store does. */
    private object BrokenBackend : AccountPgpKBackend {
        override fun get(name: String): String? = throw IllegalStateException("store unavailable")
        override fun put(name: String, value: String): Boolean = false
        override fun names(): Set<String> = throw IllegalStateException("store unavailable")
    }

    @Test
    fun itemNameHoldsTheEoaAndTheWorkspaceAndTheKPrefix() {
        val k = AccountPgpK(MemBackend())
        assertEquals("K.v1|" + eoa + "|" + ws, k.itemName(eoa.uppercase().replace("0X", "0x"), ws))
        assertTrue(k.itemName(eoa, ws).startsWith(AccountPgpK.PREFIX))
        // The legacy copy's file and keys are never a K name.
        assertFalse(k.itemName(eoa, ws).startsWith("pgp.v1."))
    }

    @Test
    fun writeThenReadRoundTripsTheJsonBody() {
        val backend = MemBackend()
        val k = AccountPgpK(backend)
        assertTrue(k.write(eoa, ws, keyId = "KID1", publicArmor = "PUB", privateArmor = "PRIV", createdAt = 1700000000L))
        val back = k.read(eoa, ws)!!
        assertEquals(eoa, back.getString("eoa"))
        assertEquals(ws, back.getString("workspace"))
        assertEquals("KID1", back.getString("keyId"))
        assertEquals("PUB", back.getString("publicKeyArmor"))
        assertEquals("PRIV", back.getString("privateKeyArmor"))
        assertEquals(1700000000L, back.getLong("createdAt"))
        assertTrue(k.existsFor(eoa, ws))
    }

    @Test
    fun aWriteThatDoesNotReadBackIsFalse() {
        val backend = MemBackend().apply { writeOk = false }
        assertFalse(AccountPgpK(backend).write(eoa, ws, "KID1", "PUB", "PRIV", 1L))
    }

    @Test
    fun absentIsNullAndNotPresent() {
        val k = AccountPgpK(MemBackend())
        assertNull(k.read(eoa, ws))
        assertFalse(k.existsFor(eoa, ws))
        assertFalse(k.existsAny())
    }

    @Test
    fun itemsAreKeyedByAccountAndWorkspace() {
        val k = AccountPgpK(MemBackend())
        k.write(eoa, ws, "KID1", "PUB", "PRIV", 1L)
        assertFalse(k.existsFor(other, ws))
        assertFalse(k.existsFor(eoa, "other-workspace"))
        assertTrue(k.existsAny())
    }

    @Test
    fun anItemThatNamesAnotherAccountIsRefused() {
        val backend = MemBackend()
        val k = AccountPgpK(backend)
        k.write(eoa, ws, "KID1", "PUB", "PRIV", 1L)
        // Some other item's body placed under this account's name: the read refuses it rather than returning it.
        backend.items[k.itemName(eoa, ws)] = """{"eoa":"$other","workspace":"$ws","keyId":"X","publicKeyArmor":"P","privateKeyArmor":"Q","createdAt":1}"""
        try {
            k.read(eoa, ws)
            fail("expected the mismatched item to be refused")
        } catch (_: IllegalStateException) {
            // expected
        }
    }

    @Test
    fun anUnreadableStoreThrowsAndIsNeverAbsent() {
        val k = AccountPgpK(BrokenBackend)
        try {
            k.existsFor(eoa, ws)
            fail("expected unreadable")
        } catch (_: IllegalStateException) {
        }
        try {
            k.existsAny()
            fail("expected unreadable")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun theBindingLocalSourcesTable() {
        // EOA path: a wallet key is positive; K present is positive; an unreadable K or keychain is unreadable; neither is none.
        val (a, ad) = BindingLocalSources.of(keyReady = true, vaultUnreadable = false, kState = BindingLocalSources.KState.ABSENT)
        assertEquals(LocalSource.POSITIVE, a)
        assertEquals(BindingDevice(kPresent = true, walletRecord = true), ad)

        val (b, bd) = BindingLocalSources.of(keyReady = false, vaultUnreadable = false, kState = BindingLocalSources.KState.PRESENT)
        assertEquals(LocalSource.POSITIVE, b)
        assertEquals(BindingDevice(kPresent = true, walletRecord = false), bd)

        val (c, _) = BindingLocalSources.of(keyReady = false, vaultUnreadable = false, kState = BindingLocalSources.KState.UNREADABLE)
        assertEquals(LocalSource.UNREADABLE, c)

        val (d, _) = BindingLocalSources.of(keyReady = false, vaultUnreadable = true, kState = BindingLocalSources.KState.ABSENT)
        assertEquals(LocalSource.UNREADABLE, d)

        val (e, ed) = BindingLocalSources.of(keyReady = false, vaultUnreadable = false, kState = BindingLocalSources.KState.ABSENT)
        assertEquals(LocalSource.NONE, e)
        assertEquals(BindingDevice(kPresent = false, walletRecord = false), ed)
    }
}
