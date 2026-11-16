package network.conet.chat

import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

/**
 * Stored entry domains and the upsert write-back. A stored value that cannot be read is unknown: the upsert is refused and
 * nothing is written, so it is never replaced by an empty list. Synthetic data only; the public key body is a placeholder.
 */
class BeamioChatPgpStoreEntriesTest {

    private val publicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----"

    /** Minimal in-memory preference store; [commits] counts editor commits so a refused upsert is visible. */
    private class FakePrefs(val values: MutableMap<String, String> = mutableMapOf()) : SharedPreferences {
        var commits = 0

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

            override fun putString(key: String?, value: String?): SharedPreferences.Editor {
                pending[key!!] = value
                return this
            }

            override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor = this
            override fun putInt(key: String?, value: Int): SharedPreferences.Editor = this
            override fun putLong(key: String?, value: Long): SharedPreferences.Editor = this
            override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = this
            override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = this

            override fun remove(key: String?): SharedPreferences.Editor {
                pending[key!!] = null
                return this
            }

            override fun clear(): SharedPreferences.Editor = this

            override fun commit(): Boolean {
                commits++
                for ((k, v) in pending) {
                    if (v == null) values.remove(k) else values[k] = v
                }
                return true
            }

            override fun apply() {
                commit()
            }
        }
    }

    private fun body(vararg pairs: Pair<String, Any>): JSONObject =
        JSONObject().apply { pairs.forEach { put(it.first, it.second) } }

    @Test
    fun absentEntryDomainsReadAsEmptyAndUnreadableOnesAsUnknown() {
        assertTrue(BeamioChatPgpStore.parseStoredEntryDomains(null).isEmpty())
        assertTrue(BeamioChatPgpStore.parseStoredEntryDomains("[]").isEmpty())
        assertEquals(listOf("a.example"), BeamioChatPgpStore.parseStoredEntryDomains("[\"a.example\"]"))
        for (bad in listOf("not json", "", "{}", "[1,")) {
            try {
                BeamioChatPgpStore.parseStoredEntryDomains(bad)
                fail("an unreadable entry-domain value must throw, not read as empty: '$bad'")
            } catch (expected: IOException) {
                // expected: unknown
            }
        }
    }

    @Test
    fun anUpsertIsRefusedAndWritesNothingWhenTheStoredEntryDomainsAreUnreadable() {
        val prefs = FakePrefs(mutableMapOf("entryDomainsJson" to "not json"))
        val ok = BeamioChatPgpStore.upsertInto(
            prefs,
            true,
            body("publicKeyArmor" to publicKey, "entryDomains" to JSONArray()),
        )
        assertFalse(ok)
        assertEquals("no commit may follow an unreadable stored list", 0, prefs.commits)
        assertEquals("not json", prefs.values["entryDomainsJson"])
        assertFalse(prefs.values.containsKey("userPgpPublicArmor"))
    }

    @Test
    fun aReadableStoredListIsKeptWhenTheBodyOmitsIt() {
        val prefs = FakePrefs(mutableMapOf("entryDomainsJson" to "[\"a.example\"]"))
        assertTrue(BeamioChatPgpStore.upsertInto(prefs, true, body("publicKeyArmor" to publicKey)))
        assertEquals(1, prefs.commits)
        assertEquals("[\"a.example\"]", prefs.values["entryDomainsJson"])
        assertEquals(publicKey, prefs.values["userPgpPublicArmor"])
    }
}
