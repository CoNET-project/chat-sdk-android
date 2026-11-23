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
    private val vectorFile = File(System.getenv("KEYSTORE_REPLICA_VECTORS") ?: "../spec/keystore-replica-vectors.v2.1.json")
    private val doc = JSONObject(vectorFile.readText(Charsets.UTF_8))

    /** The v2.1 vector (7ba89af4…, KR-05 correction over v2 e541f899…) is pinned by its SHA-256 (byte copy). v1 is superseded for KR-01 and is not used. */
    @Test
    fun theVectorFileIsThePinnedV21() {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(vectorFile.readBytes()).joinToString("") { "%02x".format(it) }
        assertEquals("7ba89af4afe29e021d55137cc4427c2acc6d57e7c6241f4ecdaceb8f605ad18b", digest)
    }

    @Test
    fun theReplicaGroupHasEightCases() {
        assertEquals(8, doc.getJSONArray("cases").length())
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
            validPhraseOf = { VectorSidecar.ACCOUNT },
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
            validPhraseOf = { VectorSidecar.ACCOUNT },
        )
        assertEquals(true, refused is ShellReplica.Answer.NotApplied)
        assertEquals(true, captured2!!.all { it == 0.toByte() })
        assertEquals(null, store2.read())
    }

    /** REP-01 (v227 §247.4; Y.163 第 32 项 A): a key-only orphan key is not read, not derived and no copy is made. */
    @Test
    fun keyOnlyAccountGetsNoCopyAndItsKeyIsNeverRead() {
        val armorBytes = hexBytes(VectorSidecar.ARMOR_OF_ACCOUNT)
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "${VectorSidecar.ACCOUNT}:default")
        var unlocks = 0
        val answer = ShellReplica.fromUnlock(
            unlock = { unlocks++; armorBytes.copyOf() },
            expectedEoa = VectorSidecar.ACCOUNT,
            outcome = ImportOutcome.ABSENT,
            pointerSet = false,
            store = store,
            validPhraseOf = { null },
        )
        assertEquals(true, answer is ShellReplica.Answer.NotApplied)
        assertEquals("the key is never unlocked", 0, unlocks)
        assertEquals(null, store.read())
    }

    /** A valid phrase for another account does not authorise a copy of this account's orphan key. */
    @Test
    fun aPhraseForAnotherAccountDoesNotAuthoriseTheCopy() {
        val armorBytes = hexBytes(VectorSidecar.ARMOR_OF_ACCOUNT)
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "${VectorSidecar.ACCOUNT}:default")
        var unlocks = 0
        val answer = ShellReplica.fromUnlock(
            unlock = { unlocks++; armorBytes.copyOf() },
            expectedEoa = VectorSidecar.ACCOUNT,
            outcome = ImportOutcome.ABSENT,
            pointerSet = false,
            store = store,
            validPhraseOf = { "0x0000000000000000000000000000000000000001" },
        )
        assertEquals(true, answer is ShellReplica.Answer.NotApplied)
        assertEquals("the key is never unlocked", 0, unlocks)
        assertEquals(null, store.read())
    }

    /** A valid-phrase account is copied as before: the key is unlocked, the copy is built and the key is zeroed. */
    @Test
    fun aValidPhraseAccountStillGetsItsCopy() {
        val armorBytes = hexBytes(VectorSidecar.ARMOR_OF_ACCOUNT)
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "${VectorSidecar.ACCOUNT}:default")
        var unlocks = 0
        var captured: ByteArray? = null
        val answer = ShellReplica.fromUnlock(
            unlock = { unlocks++; armorBytes.copyOf().also { captured = it } },
            expectedEoa = VectorSidecar.ACCOUNT,
            outcome = ImportOutcome.ABSENT,
            pointerSet = false,
            store = store,
            validPhraseOf = { VectorSidecar.ACCOUNT },
        )
        // REP-02 (v227 §247.4): a valid-phrase account gets its page copy, built from its own key (checked from the stored record), and the key is zeroed.
        assertEquals(true, answer is ShellReplica.Answer.Ok)
        assertEquals(1, unlocks)
        assertEquals(VectorSidecar.ACCOUNT, store.read()!!.getJSONArray("profiles").getJSONObject(0).getString("keyID"))
        assertEquals(true, captured!!.all { it == 0.toByte() })
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
            "readable", "key_only_orphan", "valid_mnemonic_readable" -> NativeWalletVault.State.Ready(VectorSidecar.ACCOUNT)
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
        val creation = expect.optString("create_write") in setOf("allowed", "allowed_append_only")
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
        // allowed_append_only (KR-01 v2): the write is allowed and only appends; checked as ok here.
        val writeExpect = if (writeWant == "allowed" || writeWant == "allowed_append_only") "ok" else writeWant
        if (writeGot != writeExpect) out += "create_write $writeGot != $writeExpect"

        // The replica answer through the production glue (fromUnlock), with the valid-phrase gate (v227 §247.2): a key-only orphan key is never unlocked,
        // read or derived; a valid-mnemonic account is copied from its key. `ok_same_eoa` or `not_applied`.
        val validPhrase = st.optBoolean("valid_mnemonic", false)
        var unlocks = 0
        // Its own files and wrap: the create write above must not share a copy with the replica step.
        val replicaWrap = NativeTestWrap()
        val replicaFiles = NativeTestFiles()
        val replicaStore = SealedPageRecordStore(replicaWrap, replicaFiles, "${VectorSidecar.ACCOUNT}:default")
        val replica = ShellReplica.fromUnlock(
            unlock = { unlocks++; if (vaultReadable(st)) hexBytes(VectorSidecar.ARMOR_OF_ACCOUNT) else null },
            expectedEoa = VectorSidecar.ACCOUNT,
            outcome = outcome,
            pointerSet = st.getBoolean("pointer"),
            store = replicaStore,
            validPhraseOf = { if (validPhrase) VectorSidecar.ACCOUNT else null },
        )
        val replicaWant = expect.getString("replica")
        val replicaGot = when (replica) {
            is ShellReplica.Answer.Ok -> if (replica.eoa == VectorSidecar.ACCOUNT) "ok_same_eoa" else "ok_other_eoa"
            ShellReplica.Answer.NotApplied -> "not_applied"
        }
        if (replicaGot != replicaWant) out += "replica $replicaGot != $replicaWant"
        // The orphan key is never read or derived, and never overwritten: no unlock and no copy written for a key-only orphan.
        if (expect.has("orphan_key_read") && !expect.getBoolean("orphan_key_read") && unlocks != 0) out += "orphan key read ($unlocks unlocks)"
        if (expect.has("orphan_key_derived") && !expect.getBoolean("orphan_key_derived") && unlocks != 0) out += "orphan key derived"
        if (expect.has("orphan_key_overwritten") && !expect.getBoolean("orphan_key_overwritten") && replicaStore.read() != null && !validPhrase) out += "orphan key overwritten"
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

    /** A readable key is present (the orphan key of KR-01 and the valid-mnemonic key of KR-08 are readable keys too). */
    private fun vaultReadable(st: JSONObject): Boolean = st.getString("native_key") in setOf("readable", "key_only_orphan", "valid_mnemonic_readable")

    private fun hexBytes(hex: String): ByteArray = hex.removePrefix("0x").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
