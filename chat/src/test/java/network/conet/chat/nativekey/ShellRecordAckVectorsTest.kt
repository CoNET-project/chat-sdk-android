package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * The ack group of the vectors (spec r3bp §25.52T.8: AK-01 to AK-16). Each case sets the legacy reader state (`legacy`), the account pointer
 * and the device marker (`pointer`, `marker`), then sends the request through the bridge and compares the ack.
 */
// The test account of the vectors, through the sidecar (25.52AL.3).
private val ACCOUNT: String = VectorSidecar.ACCOUNT

class ShellRecordAckVectorsTest {
    private val doc = VectorSidecar.map(JSONObject(File(System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json").readText(Charsets.UTF_8)))

    @Test
    fun theAckGroupHasTwentyEightCases() {
        assertEquals(62, doc.getJSONArray("ackCases").length())
    }

    @Test
    fun everyAckCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("ackCases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            failures += runAck(c).map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }

    private fun runAck(c: JSONObject): List<String> {
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
            JSONObject().put("type", "shellRecordRead").put("reqId", c.get("reqId"))
        } else {
            // The write request is the case's `req` as sent: an AK case without a reqId in `req` sends none (AK-13).
            val req = a1(c.getJSONObject("req")) as JSONObject
            JSONObject().put("type", "shellRecordWrite").also { b -> for (k in req.keys()) b.put(k, req.get(k)) }
        }
        val size = if (ctx.has("sizeBytes")) ctx.getInt("sizeBytes") else body.toString().toByteArray(Charsets.UTF_8).size
        val bridge = ShellRecordBridge(
            // §25.52Y.52: the account is modelled from the case ctx, and resolved by the production rule (ShellRecordAccounts.heldCopy).
            account = { accountFor(ctx, c, store) },
            migrating = { false },
            outcome = { outcome },
            flags = flags,
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
        return out
    }

    /** The vectors' label `a1` for the account's EOA (keyID values and the record's keys). */
    /** The account for a case (§25.52Y.52): unknown with acctUnknown unless a copy holds the EOA key; a named eoa or pointerAcct; else the copy's account. */
    private fun accountFor(ctx: JSONObject, c: JSONObject, store: SealedPageRecordStore): ShellRecordAccount {
        // The vault is locked and no account is bound (ShellRecordAccounts.resolve: Locked).
        if (ctx.optBoolean("locked")) return ShellRecordAccount.Locked
        val named = ctx.optString("eoa", ctx.optString("pointerAcct", ""))
        if (named.isNotEmpty()) return ShellRecordAccount.Ready(store, if (named == "a2") VectorSidecar.OTHER else ACCOUNT)
        if (ctx.optBoolean("acctUnknown")) {
            val held = c.optJSONObject("store")?.let { a1(it.getJSONObject("record")) as? JSONObject } ?: return ShellRecordAccount.Unknown
            val holder = listOf(ACCOUNT, VectorSidecar.OTHER).firstOrNull { ShellRecordPolicy.accountHoldsEoaKey(held, it) }
            return if (holder != null) ShellRecordAccount.Ready(store, holder) else ShellRecordAccount.Unknown
        }
        return if (c.has("store")) ShellRecordAccount.Ready(store, ACCOUNT) else ShellRecordAccount.Unknown
    }

    private fun a1(v: Any?): Any? = when (v) {
        "a1" -> ACCOUNT
        is JSONObject -> JSONObject().also { o -> for (k in v.keys().asSequence().toList()) o.put(k.toString(), a1(v.get(k.toString()))) }
        is org.json.JSONArray -> org.json.JSONArray().also { a -> for (i in 0 until v.length()) a.put(a1(v.get(i))) }
        else -> v
    }
}
