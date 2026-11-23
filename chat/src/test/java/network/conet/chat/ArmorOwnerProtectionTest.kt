package network.conet.chat

import android.content.SharedPreferences
import network.conet.chat.nativekey.readLegacyOwnerEoa
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Option A (2026-11-20): while a legacy private armor exists, a web upsert never rewrites the owner EOA (KEY_EOA), which the
 * adoption compares; the web EOA goes to KEY_EOA_WEB. Without an armor the behaviour is unchanged.
 */
class ArmorOwnerProtectionTest {
    private val owner = "0x1111111111111111111111111111111111111111"
    private val other = "0x2222222222222222222222222222222222222222"
    private val armor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nTEST-FIXTURE\n-----END PGP PRIVATE KEY BLOCK-----"

    /** In-memory preference store (the same contract as the test double in BeamioChatPgpStoreEntriesTest). */
    private class FakePrefs(val values: MutableMap<String, String> = mutableMapOf()) : SharedPreferences {
        override fun getAll(): Map<String, *> = values.toMap()
        override fun getString(key: String?, defValue: String?): String? = values[key] ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
        override fun getInt(key: String?, defValue: Int): Int = defValue
        override fun getLong(key: String?, defValue: Long): Long = defValue
        override fun getFloat(key: String?, defValue: Float): Float = defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = defValue
        override fun contains(key: String?): Boolean = values.containsKey(key)
        override fun edit(): SharedPreferences.Editor = Editor()
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}

        private inner class Editor : SharedPreferences.Editor {
            private val pending = LinkedHashMap<String, String?>()
            override fun putString(key: String?, value: String?): SharedPreferences.Editor { pending[key!!] = value; return this }
            override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor = this
            override fun putInt(key: String?, value: Int): SharedPreferences.Editor = this
            override fun putLong(key: String?, value: Long): SharedPreferences.Editor = this
            override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = this
            override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = this
            override fun remove(key: String?): SharedPreferences.Editor { pending[key!!] = null; return this }
            override fun clear(): SharedPreferences.Editor = this
            override fun commit(): Boolean {
                for ((k, v) in pending) { if (v == null) values.remove(k) else values[k] = v }
                return true
            }
            override fun apply() { commit() }
        }
    }

    private fun body(eoa: String) = JSONObject().put("eoa", eoa)

    @Test
    fun withAnArmorAWebEoaDoesNotChangeTheOwner() {
        val prefs = FakePrefs(mutableMapOf("userPgpPrivateArmor" to armor, "recipientEoa" to owner))
        assertTrue(BeamioChatPgpStore.upsertInto(prefs, true, body(other)))
        assertEquals("the owner EOA is unchanged", owner, prefs.values["recipientEoa"])
        assertEquals("the web EOA is kept separately", other, prefs.values["recipientEoaWeb"])
        assertEquals("the armor is unchanged", armor, prefs.values["userPgpPrivateArmor"])
    }

    @Test
    fun aRestoreWithTheOriginalEoaStillFindsTheOwnerToAdopt() {
        val prefs = FakePrefs(mutableMapOf("userPgpPrivateArmor" to armor, "recipientEoa" to owner))
        BeamioChatPgpStore.upsertInto(prefs, true, body(other))
        // The adoption compares the stored owner (readLegacyOwnerEoa over KEY_EOA) with the restored wallet EOA.
        assertEquals("the owner the adoption compares is still the original EOA", owner, readLegacyOwnerEoa { prefs.getString("recipientEoa", "") })
    }

    @Test
    fun withoutAnArmorTheBehaviourIsUnchanged() {
        val prefs = FakePrefs()
        assertTrue(BeamioChatPgpStore.upsertInto(prefs, true, body(other)))
        assertEquals("the owner EOA is written as before (no armor)", other, prefs.values["recipientEoa"])
        assertEquals("the web-reported current account is always written", other, prefs.values["recipientEoaWeb"])
        assertEquals(other, BeamioChatPgpStore.loadFrom(prefs).eoa)
    }

    /** Single KEY_EOA meaning: the current account is the web EOA when present; the adoption owner is KEY_EOA alone. */
    @Test
    fun withAnArmorTheCurrentAccountIsTheWebEoaWhileTheAdoptionOwnerStaysKeyEoa() {
        val prefs = FakePrefs(mutableMapOf("userPgpPrivateArmor" to armor, "recipientEoa" to owner))
        BeamioChatPgpStore.upsertInto(prefs, true, body(other))
        assertEquals("consumers read the current account", other, BeamioChatPgpStore.loadFrom(prefs).eoa)
        assertEquals("the adoption owner is the armor owner (KEY_EOA)", owner, prefs.getString("recipientEoa", ""))
    }

    @Test
    fun withoutAnArmorTheCurrentAccountIsTheWrittenEoa() {
        val prefs = FakePrefs()
        BeamioChatPgpStore.upsertInto(prefs, true, body(other))
        assertEquals(other, BeamioChatPgpStore.loadFrom(prefs).eoa)
    }

    @Test
    fun withOnlyTheOwnerKeyTheCurrentAccountIsEmptyNeverTheOwner() {
        //  (2026-11-20): KEY_EOA is the armor owner; it is never the current account. Callers then use the native wallet.
        val prefs = FakePrefs(mutableMapOf("userPgpPrivateArmor" to armor, "recipientEoa" to owner))
        assertEquals("", BeamioChatPgpStore.loadFrom(prefs).eoa)
    }

    /** Armor present, the current account differs from the owner: the listen and the identity consumers see the web-reported current account. */
    @Test
    fun withAnArmorAndADifferentCurrentAccountTheConsumersSeeTheCurrentAccount() {
        val prefs = FakePrefs(mutableMapOf("userPgpPrivateArmor" to armor, "recipientEoa" to owner))
        BeamioChatPgpStore.upsertInto(prefs, true, body(other))
        val consumer = BeamioChatPgpStore.loadFrom(prefs).eoa
        assertEquals("listen and identity consumers read the current account", other, consumer)
        assertFalse("a consumer never reads the owner key", consumer == owner)
    }

    @Test
    fun theAdoptionReadsTheArmorOwnerNotTheCurrentAccount() {
        val src = java.io.File("src/main/java/network/conet/chat/nativekey/AndroidNativeWallet.kt").readText(Charsets.UTF_8)
        // 2026-11-22: the PGP adoption is stopped (no write into the native PGP vault), so it compares no owner and never reads the current account.
        assertFalse("the adoption never writes the native PGP vault", src.contains("pgpVault.put(eoa"))
        assertFalse("the adoption never reads the current account", src.contains("readLegacyOwnerEoa { BeamioChatPgpStore.load(app)"))
    }
}
