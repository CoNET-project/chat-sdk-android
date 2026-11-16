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
        var removeOk = true
        override fun remove(name: String): Boolean {
            if (!removeOk) return false
            items.remove(name)
            return true
        }
    }

    /** A store that cannot be read: every call throws, as an unopenable encrypted store does. */
    private object BrokenBackend : AccountPgpKBackend {
        override fun get(name: String): String? = throw IllegalStateException("store unavailable")
        override fun put(name: String, value: String): Boolean = false
        override fun names(): Set<String> = throw IllegalStateException("store unavailable")
        override fun remove(name: String): Boolean = false
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
    fun writeIfAbsentWritesOnceAndNeverOverwrites() {
        val backend = MemBackend()
        val k = AccountPgpK(backend)
        assertEquals(AccountPgpKWrite.WRITTEN, k.writeIfAbsent(eoa, ws, "KID1", "PUB", "PRIV", 1L))
        assertEquals(AccountPgpKWrite.EXISTS, k.writeIfAbsent(eoa, ws, "KID2", "PUB2", "PRIV2", 2L))
        // The first item stands unchanged.
        assertEquals("KID1", k.read(eoa, ws)!!.getString("keyId"))
    }

    @Test
    fun aFailedWriteIsRemovedAndReportedFailed() {
        val backend = MemBackend().apply { writeOk = false }
        val k = AccountPgpK(backend)
        assertEquals(AccountPgpKWrite.FAILED, k.writeIfAbsent(eoa, ws, "KID1", "PUB", "PRIV", 1L))
        assertFalse(k.existsFor(eoa, ws))
    }

    @Test
    fun anExceptionInTheWriteIsAFailedWriteAndIsRemoved() {
        // The put succeeds and the read-back throws (the store cannot be read): the item is removed, and the write is FAILED.
        val backend = object : AccountPgpKBackend {
            val items = mutableMapOf<String, String>()
            override fun get(name: String): String? = throw IllegalStateException("read-back failed")
            override fun put(name: String, value: String): Boolean {
                items[name] = value
                return true
            }
            override fun names(): Set<String> = items.keys.toSet()
            override fun remove(name: String): Boolean {
                items.remove(name)
                return true
            }
        }
        val k = AccountPgpK(backend)
        assertEquals(AccountPgpKWrite.FAILED, k.writeIfAbsent(eoa, ws, "KID1", "PUB", "PRIV", 1L))
        assertTrue(backend.items.isEmpty())
    }

    @Test
    fun aFailedWriteWhoseRemovalAlsoFailsReportsResidue() {
        val backend = MemBackend().apply { writeOk = false; removeOk = false }
        val k = AccountPgpK(backend)
        assertEquals(AccountPgpKWrite.FAILED_RESIDUE, k.writeIfAbsent(eoa, ws, "KID1", "PUB", "PRIV", 1L))
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
        fun of(key: Boolean, vault: Boolean, active: Boolean, nonActive: Boolean, unreadable: Boolean) =
            BindingLocalSources.of(key, vault, active, nonActive, unreadable)
        // The wallet key is positive; an ACTIVE K is positive; an unreadable K or keychain is unreadable; nothing is none.
        val (a, ad) = of(key = true, vault = false, active = false, nonActive = false, unreadable = false)
        assertEquals(LocalSource.POSITIVE, a)
        assertEquals(BindingDevice(kPresent = true, walletRecord = true), ad)

        val (b, bd) = of(key = false, vault = false, active = true, nonActive = false, unreadable = false)
        assertEquals(LocalSource.POSITIVE, b)
        assertEquals(BindingDevice(kPresent = true, walletRecord = false), bd)

        // §25.52Z.3 第 7 项: a non-ACTIVE K is positive on the EOA path (BL-54), and counts in kPresent on the tag path (BL-53).
        val (c, cd) = of(key = false, vault = false, active = false, nonActive = true, unreadable = false)
        assertEquals(LocalSource.POSITIVE, c)
        assertEquals(BindingDevice(kPresent = true, walletRecord = false), cd)

        val (d, _) = of(key = false, vault = false, active = false, nonActive = false, unreadable = true)
        assertEquals(LocalSource.UNREADABLE, d)

        val (e, _) = of(key = false, vault = true, active = false, nonActive = false, unreadable = false)
        assertEquals(LocalSource.UNREADABLE, e)

        val (f, fd) = of(key = false, vault = false, active = false, nonActive = false, unreadable = false)
        assertEquals(LocalSource.NONE, f)
        assertEquals(BindingDevice(kPresent = false, walletRecord = false), fd)
    }
}
