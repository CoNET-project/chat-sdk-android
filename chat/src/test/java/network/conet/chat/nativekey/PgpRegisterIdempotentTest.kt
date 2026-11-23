package network.conet.chat.nativekey

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * registerDirect of an identity already registered on the chain is idempotent: the second call is a noop, writes
 * nothing and leaves the version unchanged.
 */
class PgpRegisterIdempotentTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    /** A chain already holding one registration at version 1, which counts its writes. */
    private class RegisteredChain(var id: PgpIdentity?, var writes: Int = 0) : PgpRestoreChain {
        override fun chainReadable(): Boolean = true
        override fun backupReadable(): Boolean = true
        override fun version(): Long = 1L + writes
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = "backup"
        override fun write(identity: PgpIdentity, backupText: String) {
            id = identity
            writes++
        }
    }

    @Test
    fun aRepeatedRegistrationOfTheSameIdentityIsANoopEveryTime() {
        val p3 = identityOf("P3")
        val chain = RegisteredChain(p3)
        val files = NativeTestFiles()
        val m = PgpRestoreMachine(
            chain = chain,
            wallet = object : PgpRestoreWallet {
                override fun ready(): Boolean = true
                override fun passwordString(): String? = null
            },
            keys = object : PgpRestoreKeys {
                override fun newKey(deviceId: String): PgpNewKey = throw IllegalStateException("no key is generated")
            },
            ivFor = { ByteArray(12) { 1 } },
            devices = mapOf("A" to PgpRestoreDevice("A", account, NativeTestWrap(), files)),
        )
        val first = m.registerDirect(p3, "backup", expectedVersion = 1L, nativeConfirmed = true)
        assertEquals("noop", first.result)
        assertEquals("already_registered_same_key", first.code)
        val second = m.registerDirect(p3, "backup", expectedVersion = 1L, nativeConfirmed = true)
        assertEquals("the second call is also a noop", "noop", second.result)
        assertEquals("nothing is written", 0, chain.writes)
        assertEquals("the version is unchanged", 1L, chain.version())
    }
}
