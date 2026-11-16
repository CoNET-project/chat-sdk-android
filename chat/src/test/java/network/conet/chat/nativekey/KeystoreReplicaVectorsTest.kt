package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * The keystore replica group (spec r3rv, §25.52T.3 末段, §25.52W.4; vectors KR-01 to KR-07). Each case sets the native key store (`native_key`),
 * the legacy store (`legacy`), the pointer and the marker, then checks the read answer, the create write answer and the replica answer.
 *
 * The create write `allowed` (KR-03) is the creation transaction after the key is generated: the state is then a readable key, and the write
 * with the creation flow is checked as `ok`. A fresh install with no key (`none`) is not a bridge write; that path is the native creation flow.
 */
class KeystoreReplicaVectorsTest {
    private val doc = JSONObject(File(System.getenv("KEYSTORE_REPLICA_VECTORS") ?: "../spec/keystore-replica-vectors.v1.json").readText(Charsets.UTF_8))

    @Test
    fun theReplicaGroupHasSevenCases() {
        assertEquals(7, doc.getJSONArray("cases").length())
    }

    @Test
    fun everyReplicaCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("cases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            failures += runCase(c).map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }

    /** The production glue: the key bytes are zeroed after the answer, in every case, and the copy is built only when the rules hold. */
    @Test
    fun theProductionGlueZeroesTheKeyAndBuildsTheCopyOnlyWhenRulesHold() {
        val armorBytes = hexBytes(VectorSidecar.ARMOR_OF_ACCOUNT)
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "${VectorSidecar.ACCOUNT}:default")
        var captured: ByteArray? = null
        val ok = ShellReplica.fromUnlock(
            unlock = { armorBytes.copyOf().also { captured = it } },
            expectedEoa = VectorSidecar.ACCOUNT,
            outcome = ImportOutcome.ABSENT,
            pointerSet = false,
            store = store,
        )
        assertEquals(true, ok is ShellReplica.Answer.Ok)
        assertEquals(true, captured!!.all { it == 0.toByte() })
        assertEquals(VectorSidecar.ACCOUNT, store.read()!!.getJSONArray("profiles").getJSONObject(0).getString("keyID"))

        // A pointer that is set is not replicated, and the key is still zeroed.
        val files2 = NativeTestFiles()
        val store2 = SealedPageRecordStore(NativeTestWrap(), files2, "${VectorSidecar.ACCOUNT}:default")
        var captured2: ByteArray? = null
        val refused = ShellReplica.fromUnlock(
            unlock = { armorBytes.copyOf().also { captured2 = it } },
            expectedEoa = VectorSidecar.ACCOUNT,
            outcome = ImportOutcome.ABSENT,
            pointerSet = true,
            store = store2,
        )
        assertEquals(true, refused is ShellReplica.Answer.NotApplied)
        assertEquals(true, captured2!!.all { it == 0.toByte() })
        assertEquals(null, store2.read())
    }

    private fun runCase(c: JSONObject): List<String> {
        val st = c.getJSONObject("state")
        val expect = c.getJSONObject("expect")
        val out = mutableListOf<String>()

        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "${VectorSidecar.ACCOUNT}:default")
        val flags = DeviceFlagFiles(files)
        if (st.getBoolean("pointer")) flags.setAccountPointer()
        if (st.getBoolean("marker")) flags.setLegacyUnreadable()
        val vault = when (st.getString("native_key")) {
            "readable" -> NativeWalletVault.State.Ready(VectorSidecar.ACCOUNT)
            "unreadable" -> NativeWalletVault.State.Locked("unreadable")
            "none" -> NativeWalletVault.State.NoKey
            else -> throw IllegalArgumentException("unknown native_key")
        }
        val outcome = when (st.getString("legacy")) {
            "absent" -> ImportOutcome.ABSENT
            "unreadable" -> ImportOutcome.LEGACY_UNREADABLE
            "found" -> ImportOutcome.NOT_DONE
            "unread" -> null
            else -> throw IllegalArgumentException("unknown legacy")
        }
        fun bridgeFor(v: NativeWalletVault.State, creation: Boolean): ShellRecordBridge {
            val acc = ShellRecordAccounts.resolve(
                vault = v,
                sessionReady = true,
                sessionGate = false,
                bound = null,
                copyNames = { emptyList() },
                storeOf = { store },
            )
            return ShellRecordBridge(
                account = { acc },
                migrating = { false },
                outcome = { outcome },
                flags = flags,
                // The creation transaction (AK-42): the creation mode with the explicit choice.
                creationMode = { creation },
                explicitChoice = { creation },
            )
        }
        val creation = expect.optString("create_write") == "allowed"
        // KR-03: the create write is checked after the key is generated (a readable key), with the creation flow.
        val writeVault = if (creation) NativeWalletVault.State.Ready(VectorSidecar.ACCOUNT) else vault
        val bridge = bridgeFor(vault, creation = false)

        // The read answer: `absent`, `migrating`, or `error:<sub>`.
        val readWant = expect.getString("read")
        val readAck = bridge.handle(ShellOrigin.EMBEDDED_PAGE, JSONObject().put("type", "shellRecordRead").put("reqId", "r"), 0)
        val readGot = readCode(readAck)
        if (readGot != readWant) out += "read $readGot != $readWant"

        // The create write answer: `migrating`, or `allowed` (checked as ok with the creation flow).
        val writeBody = JSONObject().put("type", "shellRecordWrite").put("reqId", "w").put("record", JSONObject().put("rev", 0).put("schemaVersion", 1))
        val writeAck = bridgeFor(writeVault, creation).handle(ShellOrigin.EMBEDDED_PAGE, writeBody, writeBody.toString().toByteArray(Charsets.UTF_8).size)
        val writeWant = expect.getString("create_write")
        val writeGot = writeAck.optJSONObject("result")?.optString("code") ?: writeAck.optString("error")
        val writeExpect = if (writeWant == "allowed") "ok" else writeWant
        if (writeGot != writeExpect) out += "create_write $writeGot != $writeExpect"

        // The replica answer: `ok_same_eoa` (from the readable key, the EOA of the key) or `not_applied`.
        val key = if (vaultReadable(st)) hexBytes(VectorSidecar.ARMOR_OF_ACCOUNT) else null
        val replica = ShellReplica.answer(key, VectorSidecar.ACCOUNT, outcome, st.getBoolean("pointer"), store)
        val replicaWant = expect.getString("replica")
        val replicaGot = when (replica) {
            is ShellReplica.Answer.Ok -> if (replica.eoa == VectorSidecar.ACCOUNT) "ok_same_eoa" else "ok_other_eoa"
            ShellReplica.Answer.NotApplied -> "not_applied"
        }
        if (replicaGot != replicaWant) out += "replica $replicaGot != $replicaWant"
        return out
    }

    /** The code of a read ack: `absent`, `migrating`, `error:<sub>`, or the envelope error. */
    private fun readCode(ack: JSONObject): String {
        if (!ack.optBoolean("ok")) return "envelope:${ack.optString("error")}"
        val result = ack.getJSONObject("result")
        return when (val code = result.getString("code")) {
            "error" -> "error:${result.optString("sub")}"
            else -> code
        }
    }

    private fun vaultReadable(st: JSONObject): Boolean = st.getString("native_key") == "readable"

    private fun hexBytes(hex: String): ByteArray = hex.removePrefix("0x").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
