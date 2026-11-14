package network.conet.chat.nativekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.io.IOException
import java.util.concurrent.atomic.AtomicReference

/**
 * The SDK side of the page-record vectors (spec r3bb §25.52G.1, §25.52H.8; earlier §25.52D.14, §25.52E, §25.52F.9).
 *
 * Run here through the bridge ([ShellRecordBridge]) and the sealed store ([SealedPageRecordStore]), with the test Keystore
 * stand-in: the TR group (14 cases), the WM group (6 cases, the wallet-field merge). The RD (7), WR (2) and PW (3) groups are the
 * page's rules. The SDK cannot run the page's code, so they are checked here against a reference of the same rules, and the
 * native half of PW (the pre-write refusal) is checked against the bridge. The PWA must run the same vectors on its side.
 */
// The test accounts of the vectors, through the sidecar (25.52AL.3): key A and key B, generated per run.
private val ACCOUNT: String = VectorSidecar.ACCOUNT
private val OTHER: String = VectorSidecar.OTHER

class ShellRecordVectorsTest {
    private val bytes = File(
        System.getenv("PGP_MIGRATION_VECTORS") ?: "../spec/pgp-migration-vectors.v1.json",
    ).readBytes()
    private val doc = VectorSidecar.map(JSONObject(String(bytes, Charsets.UTF_8)))

    @Test
    fun theShellRecordGroupsMatchTheSpec() {
        assertEquals(47, doc.getJSONArray("shellRecordCases").length())  // r3cj: TR-47 added
        assertEquals(12, doc.getJSONArray("pageReadCases").length())
        assertEquals(2, doc.getJSONArray("pageWriteCases").length())
        assertEquals(5, doc.getJSONArray("pageRefuseCases").length())
        assertEquals(13, doc.getJSONArray("walletMergeCases").length())
        assertEquals(5, doc.getJSONArray("formatCases").length())
        assertEquals(2, doc.getJSONArray("canonicalCases").length())
    }

    @Test
    fun everyBridgeCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("shellRecordCases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            failures += runBridgeCase(c).map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun everyWalletMergeCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("walletMergeCases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            failures += runBridgeCase(c).map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun everyPageReadCaseMatchesTheReferenceRules() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("pageReadCases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            val (action, rev) = pageRead(c.getJSONObject("resp"))
            val expect = c.getJSONObject("expect")
            if (action != expect.getString("action")) failures += "${c.getString("id")}: action $action != ${expect.getString("action")}"
            if (expect.v().has("rev") && rev != expect.v().getInt("rev")) failures += "${c.getString("id")}: rev $rev != ${expect.v().getInt("rev")}"
        }
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun everyPageWriteCaseMatchesTheReferenceRules() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("pageWriteCases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            val resp = c.getJSONObject("resp")
            val expect = c.getJSONObject("expect")
            val action = if (resp.v().optString("code") == "ok" && resp.v().opt("rev") is Int) "accept" else "fail_closed"
            val reason = if (action == "fail_closed") "reread_required" else null
            if (action != expect.getString("action")) failures += "${c.getString("id")}: action $action != ${expect.getString("action")}"
            if (expect.v().has("reason") && reason != expect.v().getString("reason")) failures += "${c.getString("id")}: reason $reason"
            if (expect.v().has("rev") && resp.v().optInt("rev") != expect.v().getInt("rev")) failures += "${c.getString("id")}: rev"
        }
        assertEquals(emptyList<String>(), failures)
    }

    @Test
    fun everyPreSendCaseMatchesTheReferenceAndTheNativeRefusal() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("pageRefuseCases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            val record = c.v().getJSONObject("record")
            val expect = c.getJSONObject("expect")
            val id = c.getString("id")
            // Page reference (§25.52I.3, §25.52L.8): the header first (pgp_header), then a forbidden path (pgp_path), then a PGP public
            // field (pgp_field_not_allowed, PW-04). A copy without PGP fields is sent (PW-03).
            val publicFields = ShellRecordPolicy.pgpPublicIn(record)
            val (action, reason, names) = when {
                ShellRecordPolicy.hasPgpHeader(record) -> Triple("refuse", "pgp_header", emptyList())
                ShellRecordPolicy.forbiddenIn(record).isNotEmpty() ->
                    Triple("refuse", "pgp_path", ShellRecordPolicy.forbiddenIn(record))
                publicFields.isNotEmpty() -> Triple("refuse", "pgp_field_not_allowed", publicFields)
                else -> Triple("send", null, emptyList())
            }
            if (action != expect.getString("action")) failures += "$id: action $action"
            if (expect.v().has("reason") && reason != expect.v().opt("reason").takeIf { it != JSONObject.NULL }) failures += "$id: reason $reason"
            if (expect.v().has("names") && names.sorted() != expect.v().getJSONArray("names").toList().sorted()) failures += "$id: names $names"
            // Native half (§25.52E.5, §25.52L.8): the bridge refuses the same records; the PGP public fields come back as bad_request (TR-15).
            val nativeRefused = ShellRecordPolicy.preWriteRefusal(record) != null || ShellRecordPolicy.pgpPublicIn(record).isNotEmpty()
            if (nativeRefused != (action == "refuse")) failures += "$id: native refusal $nativeRefused"
        }
        assertEquals(emptyList<String>(), failures)
    }

    /** One bridge case: the store seeded from `store`, the request from `req`, the context from `ctx`, then the expectations. */
    /** The reader state of a case (§25.52W.7): `legacy` absent, empty, unreadable, found; no state means the legacy store was not read. */
    private fun legacyOutcome(ctx: JSONObject): ImportOutcome? = when (ctx.opt("legacy") as? String) {
        "absent", "empty" -> ImportOutcome.ABSENT
        "unreadable" -> ImportOutcome.LEGACY_UNREADABLE
        "found" -> ImportOutcome.NOT_DONE
        null -> null
        else -> throw IllegalArgumentException("unknown legacy state")
    }

    private fun runBridgeCase(c: JSONObject): List<String> {
        val ctx = c.optJSONObject("ctx") ?: JSONObject()
        val h = Harness(migrating = ctx.optBoolean("migrating"), outcome = legacyOutcome(ctx))
        c.optJSONObject("store")?.let { seed ->
            val record = mapLabels(seed.v().getJSONObject("record")) as JSONObject
            // TR-19: a stored copy whose read answer is larger than 2 MB once the envelope is counted.
            if (ctx.has("responseBytes")) record.put("padding", "x".repeat(ctx.getInt("responseBytes")))
            h.store.write(record)
        }
        val before = canon(h.store.readOrNull())
        // The write fault is armed after the seed, so the seed itself is never the failing write.
        h.files.failWrites = ctx.optBoolean("writeFailed")

        val origin = if (ctx.optString("origin") == "other") ShellOrigin.OTHER else ShellOrigin.EMBEDDED_PAGE
        // The wallet-merge cases carry no kind: they are all writes.
        val kind = c.optString("kind", "write")
        val body = JSONObject().put("type", if (kind == "read") "shellRecordRead" else "shellRecordWrite")
        (mapLabels(c.optJSONObject("req")) as? JSONObject)?.let { req -> for (k in req.keys()) body.put(k, req.get(k)) }
        if (!body.v().has("reqId") && kind == "read") body.put("reqId", "r0")
        val size = if (ctx.has("sizeBytes")) ctx.getInt("sizeBytes") else body.toString().toByteArray(Charsets.UTF_8).size
        val resp = h.bridge().handle(origin, body, size, nativeWrite = ctx.optBoolean("nativeWrite"))

        val out = mutableListOf<String>()
        val expect = c.getJSONObject("expect")
        if (resp.v().getString("code") != expect.v().getString("code")) out += "code ${resp.v().getString("code")} != ${expect.v().getString("code")}"
        if (expect.v().has("reqId")) {
            val want = expect.v().opt("reqId")
            val got = resp.v().opt("reqId")
            val same = if (want == JSONObject.NULL) got == JSONObject.NULL else got == want
            if (!same) out += "reqId $got != $want"
        }
        if (expect.v().has("rev") && resp.v().optInt("rev", -1) != expect.v().getInt("rev")) out += "rev ${resp.v().opt("rev")}"
        if (expect.v().has("currentRev") && resp.v().optInt("currentRev", -1) != expect.v().getInt("currentRev")) out += "currentRev"
        if (expect.v().has("reason") && resp.v().optString("reason") != expect.v().getString("reason")) out += "reason ${resp.v().opt("reason")}"
        if (expect.v().has("names")) {
            val got = resp.v().optJSONArray("names")?.toList()?.sorted() ?: emptyList()
            val want = expect.v().getJSONArray("names").toList().sorted()
            if (got != want) out += "names $got != $want"
        }
        if (expect.v().has("record")) {
            if (canon(resp.v().opt("record")) != canon(mapLabels(expect.get("record")))) out += "record ${resp.v().opt("record")}"
        }
        if (expect.v().has("walletFieldsRedacted") && resp.v().optBoolean("walletFieldsRedacted") != expect.getBoolean("walletFieldsRedacted")) {
            out += "walletFieldsRedacted"
        }
        if (expect.v().has("schemaVersion") && resp.v().optInt("schemaVersion", -1) != expect.v().getInt("schemaVersion")) out += "schemaVersion"
        if (expect.has("store")) {
            val after = h.store.readOrNull()
            val wantStore = expect.opt("store")
            if (wantStore == JSONObject.NULL) {
                if (canon(after) != before) out += "store changed: ${canon(after)}"
            } else {
                val want = wantStore as JSONObject
                if (canon(after) != canon(mapLabels(want.get("record")))) out += "store ${canon(after)} != ${canon(mapLabels(want.get("record")))}"
                if (after?.optInt("rev", -1) != want.v().getInt("rev")) out += "store rev"
            }
        }
        return out
    }

    @Test
    fun everyImportCaseMatchesItsExpectation() {
        val failures = mutableListOf<String>()
        val list = doc.getJSONArray("importCases")
        for (i in 0 until list.length()) {
            val c = list.getJSONObject(i)
            failures += runImportCase(c).map { "${c.getString("id")}: $it" }
        }
        assertEquals(emptyList<String>(), failures)
    }

    /**
     * IM-01 to IM-08 (§25.52K): the first-run import, its code, the store it leaves, and the read it leads to. The labels `A1` and `A2`
     * stand for the account and another address, so the record's keyIDs and the derived addresses are mapped to hex accounts first.
     */
    private fun runImportCase(c: JSONObject): List<String> {
        val init = c.getJSONObject("init")
        val files = FailingFiles(NativeTestFiles())
        val store = SealedPageRecordStore(NativeTestWrap(), files, "$ACCOUNT:default")
        val outcome = AtomicReference<ImportOutcome?>(null)
        val derivedLabel = init.optString("derivedAddr", "")
        val derived = if (derivedLabel.isEmpty()) null else mapLabel(derivedLabel)
        init.optJSONObject("store")?.let { store.write(mapLabels(it.v().getJSONObject("record")) as JSONObject) }
        var legacyState: Any = init.get("legacy")
        val flow = ShellImportFlow(
            storeFor = { store },
            addressOf = { derived },
            pgpStep = { _, _ -> },
            outcome = outcome,
        )
        val bridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store, ACCOUNT) },
            migrating = { false },
            outcome = { outcome.get() },
        )

        val out = mutableListOf<String>()
        val steps = c.getJSONArray("steps")
        for (i in 0 until steps.length()) {
            val step = steps.getJSONObject(i)
            step.opt("legacyNext")?.takeIf { it != JSONObject.NULL }?.let { legacyState = it }
            files.failWrites = step.getJSONObject("faults").optBoolean("writeFailed")
            val code = flow.run(ACCOUNT, toWallet(legacyState), null)
            val expect = step.getJSONObject("expect")
            if (code.wire != expect.getString("importCode")) out += "importCode ${code.wire} != ${expect.getString("importCode")}"
            if (expect.has("store")) {
                val got = store.readOrNull()
                val want = expect.opt("store")
                if (want == JSONObject.NULL) {
                    if (got != null) out += "store is present"
                } else {
                    want as JSONObject
                    if (canon(got) != canon(mapLabels(want.v().getJSONObject("record")))) out += "store ${canon(got)}"
                    if (got?.optInt("rev", -1) != want.v().getInt("rev")) out += "store rev"
                }
            }
            val readWant = expect.getJSONObject("read")
            val resp = bridge.handle(
                ShellOrigin.EMBEDDED_PAGE,
                JSONObject().put("type", "shellRecordRead").put("reqId", "i${i + 1}"),
                40,
            )
            if (resp.v().getString("code") != readWant.v().getString("code")) out += "read ${resp.v().getString("code")} != ${readWant.v().getString("code")}"
            if (readWant.v().has("sub") && resp.v().optString("sub") != readWant.v().getString("sub")) out += "read sub ${resp.v().opt("sub")}"
            if (readWant.v().has("schemaVersion") && resp.v().optInt("schemaVersion", -1) != readWant.v().getInt("schemaVersion")) out += "read schema"
            if (readWant.v().has("record") && canon(resp.v().opt("record")) != canon(mapLabels(readWant.get("record")))) {
                out += "read record ${canon(resp.v().opt("record"))}"
            }
        }
        return out
    }

    /** The legacy state of one import step: the reader's `unreadable` string, or the reader's JSON object (§25.52K.7). */
    private fun toWallet(state: Any): LegacyWalletRecord = when (state) {
        is String -> LegacyWalletRecord.Unreadable(state)
        is JSONObject -> when (state.v().getString("state")) {
            "absent", "empty" -> LegacyWalletRecord.Absent
            "unreadable" -> LegacyWalletRecord.Unreadable("unreadable")
            else -> LegacyWalletRecord.Found(mapLabels(state.v().getJSONObject("record")).toString().toByteArray(Charsets.UTF_8))
        }
        else -> throw IllegalArgumentException("unknown legacy state")
    }

    private fun mapLabel(label: String): String = when (label) {
        "A1", "a1" -> ACCOUNT
        "A2" -> OTHER
        else -> label
    }

    private fun mapLabels(v: Any?): Any? = when (v) {
        is String -> mapLabel(v)
        is JSONObject -> JSONObject().also { o -> for (k in v.keys().asSequence().toList()) o.put(k.toString(), mapLabels(v.get(k.toString()))) }
        is JSONArray -> JSONArray().also { a -> for (i in 0 until v.length()) a.put(mapLabels(v.get(i))) }
        else -> v
    }

    /** RD-01 to RD-07 as the page's reference: accept with the rev, accept absent, accept redacted, or fail closed. */
    private fun pageRead(resp: JSONObject): Pair<String, Int?> {
        val rec = resp.optJSONObject("record")
        return when {
            resp.v().optString("code") == "ok" && rec != null && rec.v().opt("rev") is Int -> {
                val rev = rec.v().getInt("rev")
                if (resp.v().optBoolean("walletFieldsRedacted")) "accept_redacted" to rev else "accept" to rev
            }
            resp.optString("code") == "error" && resp.optString("sub") == "needs_native_recovery" ->
                "unavailable_native_recovery" to null
            resp.v().optString("code") == "absent" -> "accept_absent" to null
            else -> "fail_closed" to null
        }
    }

    /** The bridge's own store and its bridge, with the migration flag as the context sets it. */
    private class Harness(private val migrating: Boolean, private val outcome: ImportOutcome?) {
        val files = FailingFiles(NativeTestFiles())
        private val wrap = NativeTestWrap()
        val store = SealedPageRecordStore(wrap, files, "$ACCOUNT:default")

        fun bridge(): ShellRecordBridge = ShellRecordBridge(
            account = { ShellRecordAccount.Ready(store, ACCOUNT) },
            migrating = { migrating },
            // The legacy store is confirmed absent for these cases, so a missing copy reads `absent` (§25.52K.4).
            outcome = { outcome },
        )
    }

    private fun SealedPageRecordStore.readOrNull(): JSONObject? = try {
        read()
    } catch (_: IOException) {
        null
    }

    private fun JSONArray.toList(): List<String> = (0 until length()).map { getString(it) }

    companion object {
        /** Canonical text of a JSON value: keys sorted at every depth, so two equal records compare equal. */
        fun canon(v: Any?): String = when {
            v == null || v == JSONObject.NULL -> "null"
            v is JSONObject -> v.keys().asSequence().map { it.toString() }.sorted()
                .joinToString(",", "{", "}") { k -> JSONObject.quote(k) + ":" + canon(v.get(k)) }
            v is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { canon(v.get(it)) }
            v is String -> JSONObject.quote(v)
            else -> v.toString()
        }
    }
}

/** A file store with a switch that fails every write, for TR-11. Reads and deletes pass through. */
internal class FailingFiles(private val inner: VaultFiles) : VaultFiles {
    var failWrites: Boolean = false

    override fun read(name: String): ByteArray? = inner.read(name)

    override fun write(name: String, bytes: ByteArray) {
        if (failWrites) throw IOException("injected write failure")
        inner.write(name, bytes)
    }

    override fun delete(name: String) = inner.delete(name)
}
