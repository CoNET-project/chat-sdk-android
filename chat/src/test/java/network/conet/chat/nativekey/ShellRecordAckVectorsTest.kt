package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.io.IOException

/**
 * The ack group of the vectors (spec r3bp §25.52T.8: AK-01 to AK-16). Each case sets the legacy reader state (`legacy`), the account pointer
 * and the device marker (`pointer`, `marker`), then sends the request through the bridge and compares the ack.
 */
// The test account of the vectors, through the sidecar (25.52AL.3).
private val ACCOUNT: String = VectorSidecar.ACCOUNT

/** A wrapping key that is gone: nothing opens, so a stored record is unreadable (§25.52CH.1, a locked store). */
private object LockedKeyWrap : KeyWrap {
    override fun seal(aad: ByteArray, plain: ByteArray): ByteArray = throw IllegalStateException("locked")
    override fun open(aad: ByteArray, sealed: ByteArray): ByteArray? = null
    override fun deleteKey(): Boolean = false
}

class ShellRecordAckVectorsTest {
    private val doc = VectorSidecar.map(JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v3.1.json").readText(Charsets.UTF_8)))

    @Test
    fun theAckGroupHasTwentyEightCases() {
        assertEquals(64, doc.getJSONArray("ackCases").length())
    }

    @Test
    fun everyAckCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("ackCases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            val problems = runAck(c)
            VectorResultLog.record("ackCases", c.getString("id"), problems)
            failures += problems.map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }

    internal fun runAck(c: JSONObject, after: (SealedPageRecordStore, NativeTestFiles) -> List<String> = { _, _ -> emptyList() }): List<String> {
        val ctx = c.optJSONObject("ctx") ?: JSONObject()
        val files = NativeTestFiles()
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        c.optJSONObject("store")?.let { store.write(a1(it.getJSONObject("record")) as JSONObject) }
        val flags = DeviceFlagFiles(files)
        if (ctx.optBoolean("pointer")) flags.setAccountPointer()
        if (ctx.optBoolean("marker")) flags.setLegacyUnreadable()

        // The reader state of the case (§25.52W.7). A case without a legacy state has not read the legacy store: the write guard then answers
        // migrating (AK-23), and the read answers migrating (AK-18) or the marker's error (AK-07).
        val outcome: ImportOutcome? = when (ctx.opt("legacy") as? String) {
            "absent", "empty" -> ImportOutcome.ABSENT
            "unreadable" -> ImportOutcome.LEGACY_UNREADABLE
            "found" -> ImportOutcome.NOT_DONE
            null -> null
            else -> throw IllegalArgumentException("unknown legacy state")
        }
        val origin = when (ctx.optString("origin")) {
            "allowed" -> ShellOrigin.EMBEDDED_PAGE
            else -> ShellOrigin.OTHER
        }
        val body = if (c.optString("kind") == "read") {
            // A case that carries its own `req` (the shape vectors) is sent as written, with its top-level fields; otherwise the plain read.
            if (c.has("req")) a1(c.getJSONObject("req")) as JSONObject else JSONObject().put("type", "shellRecordRead").put("reqId", c.get("reqId"))
        } else {
            // The write request is the case's `req` as sent: an AK case without a reqId in `req` sends none (AK-13).
            val req = a1(c.getJSONObject("req")) as JSONObject
            JSONObject().put("type", "shellRecordWrite").also { b -> for (k in req.keys()) b.put(k, req.get(k)) }
        }
        val size = if (ctx.has("sizeBytes")) ctx.getInt("sizeBytes") else body.toString().toByteArray(Charsets.UTF_8).size
        // 25.52CH.1 (r3eg): a locked store cannot open its record, so a read of it fails (AK-38, AK-46): the page store is re-opened with a key that is gone.
        val bridgeStore = if (ctx.optBoolean("locked")) SealedPageRecordStore(LockedKeyWrap, files, "$ACCOUNT:default") else store
        val bridge = ShellRecordBridge(
            // §25.52Y.52: the account is modelled from the case ctx and resolved by the production rule.
            account = { accountFor(ctx, c, bridgeStore) },
            migrating = { false },
            outcome = { outcome },
            flags = flags,
            // AK-42: a creation transaction (creationTxn) is the creation mode with the explicit choice.
            creationMode = { ctx.optBoolean("creationMode") || ctx.optBoolean("creationTxn") },
            explicitChoice = { ctx.optBoolean("explicitChoice") },
        )
        val ack = bridge.handle(origin, body, size)

        val out = mutableListOf<String>()
        val expect = c.getJSONObject("expect")
        if (ack.getString("type") != expect.getString("type")) out += "type ${ack.getString("type")}"
        val wantId = expect.opt("reqId")
        val gotId = ack.opt("reqId")
        if (!(if (wantId == JSONObject.NULL) gotId == JSONObject.NULL else gotId == wantId)) out += "reqId $gotId != $wantId"
        if (ack.getBoolean("ok") != expect.getBoolean("ok")) out += "ok ${ack.getBoolean("ok")}"
        if (expect.has("error")) {
            if (ack.optString("error") != expect.getString("error")) out += "error ${ack.opt("error")}"
        }
        if (expect.has("result")) {
            val result = ack.optJSONObject("result") ?: JSONObject()
            val want = expect.getJSONObject("result")
            for (k in want.keys()) {
                if (ShellRecordVectorsTest.canon(result.opt(k)) != ShellRecordVectorsTest.canon(a1(want.get(k)))) {
                    out += "result.$k ${ShellRecordVectorsTest.canon(result.opt(k))} != ${ShellRecordVectorsTest.canon(want.get(k))}"
                }
            }
        }
        out += after(store, files)
        return out
    }

    /**
     * The account of a case (§25.52Y.52), resolved by the production rule [ShellRecordAccounts.resolve]. The native key list comes from the
     * ctx (`keys`; `nativeKey` alone is the single key `a1`), and a named account (`eoa`, `pointerAcct`) is the pointer. The page copy is named
     * for the account that holds the EOA key, so [ShellRecordAccounts.heldCopy] resolves an unknown account from the copy. `enumFailed` makes the
     * copy enumeration fail (AK-40, AK-41). ctx.locked is the storage lock (§25.52Y.53): it is not a vault state here.
     */
    private fun accountFor(ctx: JSONObject, c: JSONObject, store: SealedPageRecordStore): ShellRecordAccount {
        val keys: List<String> = when {
            ctx.has("keys") -> ctx.getJSONArray("keys").let { arr -> (0 until arr.length()).map { label(arr.getString(it)) } }
            ctx.optBoolean("nativeKey") || ctx.optBoolean("nativeMnemonic") -> listOf(ACCOUNT)
            else -> emptyList()
        }
        val vault: NativeWalletVault.State = keys.firstOrNull()?.let { NativeWalletVault.State.Ready(it) } ?: NativeWalletVault.State.NoKey
        val named = ctx.optString("eoa", ctx.optString("pointerAcct", ""))
        val bound = if (named.isEmpty()) null else label(named)
        val copy = c.optJSONObject("store")?.let { a1(it.getJSONObject("record")) as? JSONObject }
        val holder = copy?.let { r -> listOf(ACCOUNT, VectorSidecar.OTHER).firstOrNull { ShellRecordPolicy.accountHoldsEoaKey(r, it) } }
        val copyAccount = holder ?: ACCOUNT
        val copyNames = if (copy == null) emptyList() else listOf("page.v1." + copyAccount.removePrefix("0x") + ".default.rec")
        return ShellRecordAccounts.resolve(
            vault = vault,
            sessionReady = true,
            sessionGate = false,
            bound = bound,
            copyNames = {
                if (ctx.optBoolean("enumFailed")) throw IOException("enumeration failed (modelled)")
                copyNames
            },
            storeOf = { store },
            keys = keys,
            // v3.1 harness rule (AK-65): ctx.nativeKey seeds a private key only (key-only); ctx.nativeMnemonic seeds a valid phrase account. A key from
            // ctx.keys is a phrase account (as before).
            phraseHeld = !(ctx.optBoolean("nativeKey") && !ctx.optBoolean("nativeMnemonic") && !ctx.has("keys")),
        )
    }

    /** The account a vector label names: `a1` is the test account (key A), `a2` and `b2` are the second account (key B). */
    private fun label(name: String): String = when (name) {
        // The sidecar already turns an `eoa` of `a1` into the account's address (VectorSidecar.map), so both forms name the account.
        "a1", ACCOUNT -> ACCOUNT
        "a2", "b2", VectorSidecar.OTHER -> VectorSidecar.OTHER
        else -> throw IllegalArgumentException("unknown account label")
    }

    private fun a1(v: Any?): Any? = when (v) {
        "a1" -> ACCOUNT
        is JSONObject -> JSONObject().also { o -> for (k in v.keys().asSequence().toList()) o.put(k.toString(), a1(v.get(k.toString()))) }
        is org.json.JSONArray -> org.json.JSONArray().also { a -> for (i in 0 until v.length()) a.put(a1(v.get(i))) }
        else -> v
    }
}
