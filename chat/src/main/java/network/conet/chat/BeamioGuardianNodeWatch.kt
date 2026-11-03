package network.conet.chat

import android.content.Context
import android.util.Base64
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * CoNET DePIN node table, kept by the SDK from the chain (same rules as the
 * CoNET-SI node table watcher, `src/util/guardianNodes.ts`, and the iOS SDK).
 *
 * GuardianNodesInfoV6 emits only `deleteIPAddr`; adds and IP/PGP changes write
 * storage without an event. Each poll reads the contract's storage root
 * (`eth_getProof` → `storageHash`) at head − 2 blocks; only when it differs from
 * the root the current table was built from is the full table read, pinned to
 * that block, every page or nothing. Without `eth_getProof`, contract logs plus a
 * short block scan detect changes. A full read happens at least once a day. An
 * empty read, or a drop below half of a 20+ table without a confirming read 20
 * minutes later, is refused.
 *
 * The table is cached ([BeamioChatPgpStore.storeChainRoster]), so a push wake
 * starts from the cache and checks the chain in the background. Removed nodes
 * leave [BeamioEntryPool] at once; new ones enter only after a probe.
 * Polls only while the SDK is active (driven by the pool). Public RPC only.
 */
object BeamioGuardianNodeWatch {
    private const val TAG = "BeamioGuardian"
    private const val CONTRACT = "0xBC6b53065b5647261396d002bDBA0d3396E0722f"
    private const val GET_ALL_NODES = "4272c81e" // getAllNodes(uint256,uint256)
    private val RPCS = arrayOf("https://publicrpc.conet.network", "https://rpc1.conet.network")
    private const val CONFIRMATIONS = 2
    private const val POLL_MS = 30_000L
    private const val PAGE = 100
    private const val MAX_TX_SCAN_BLOCKS = 30
    private const val LOGS_CHUNK = 4_000
    private const val MIN_FULL_READ_MS = 60_000L
    private const val FORCE_FULL_READ_MS = 24 * 3600_000L
    private const val FAIL_BACKOFF_BASE_MS = 30_000L
    private const val FAIL_BACKOFF_MAX_MS = 15 * 60_000L
    private const val SHRINK_CONFIRM_MS = 20 * 60_000L
    private const val PREFS = "beamio_guardian_watch"

    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "conet-guardian-watch").apply { isDaemon = true }
    }
    private val running = AtomicBoolean(false)
    @Volatile private var lastPoll = 0L
    @Volatile private var lastFullRead = 0L
    @Volatile private var failures = 0
    @Volatile private var notBefore = 0L
    @Volatile private var proofUnsupported = false
    private var pendingShrink: Pair<Int, Long>? = null

    private data class Row(val node: BeamioChatPgpStore.SiNode, val armor: String)

    private sealed class Rpc {
        data class Ok(val value: Any) : Rpc()
        object Unsupported : Rpc()
        object Failed : Rpc()
    }

    /** From the pool's refresh while active. */
    internal fun tick(context: Context) {
        if (System.currentTimeMillis() - lastPoll < POLL_MS) return
        val ctx = context.applicationContext
        executor.execute { poll(ctx, "poll") }
    }

    /** Launch, foreground, push wake: check now (full read at once when no table is cached). */
    fun kick(context: Context) {
        val ctx = context.applicationContext
        executor.execute { poll(ctx, "kick") }
    }

    private fun poll(ctx: Context, reason: String) {
        if (System.currentTimeMillis() < notBefore) return
        if (!running.compareAndSet(false, true)) return
        lastPoll = System.currentTimeMillis()
        try {
            val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val head = blockNumber() ?: return fail("blockNumber")
            val target = (head - CONFIRMATIONS).coerceAtLeast(0L)
            val cached = BeamioChatPgpStore.loadSiNodes(ctx)
            val builtRoot = prefs.getString("root", "").orEmpty()
            val builtBlock = prefs.getLong("block", 0L)
            val builtAt = prefs.getLong("builtAt", 0L)

            var changed = cached.isEmpty() || builtRoot.isEmpty()
            var why = if (changed) "no table" else ""
            var root = ""
            if (!proofUnsupported) {
                when (val r = storageRoot(target)) {
                    is Rpc.Ok -> {
                        root = r.value as String
                        if (root != builtRoot) {
                            changed = true
                            if (why.isEmpty()) why = "storage root changed"
                        }
                    }
                    Rpc.Unsupported -> {
                        proofUnsupported = true
                        Log.i(TAG, "eth_getProof unsupported; using logs and block scan")
                    }
                    Rpc.Failed -> return fail("getProof")
                }
            }
            if (proofUnsupported && !changed && builtBlock > 0 && target > builtBlock) {
                when (contractTouched(builtBlock, target)) {
                    true -> { changed = true; why = "contract touched" }
                    false -> {}
                    null -> return fail("logs")
                }
            }
            if (!changed && System.currentTimeMillis() - builtAt > FORCE_FULL_READ_MS) {
                changed = true
                why = "daily read"
            }
            if (!changed) {
                failures = 0
                if (proofUnsupported) prefs.edit().putLong("block", target).apply()
                return
            }
            if (System.currentTimeMillis() - lastFullRead < MIN_FULL_READ_MS && cached.isNotEmpty()) return
            lastFullRead = System.currentTimeMillis()
            val rows = readAll(target) ?: return fail("getAllNodes")
            shrinkRefusal(cached.size, rows.size)?.let {
                Log.w(TAG, "table refused: $it")
                return
            }
            val nodes = rows.map { it.node }
            val mailbox = matchMailbox(ctx, rows)
            if (!BeamioChatPgpStore.storeChainRoster(ctx, nodes, mailbox)) return fail("store")
            if (root.isEmpty() && !proofUnsupported) (storageRoot(target) as? Rpc.Ok)?.let { root = it.value as String }
            prefs.edit().putString("root", root).putLong("block", target)
                .putLong("builtAt", System.currentTimeMillis()).apply()
            failures = 0
            val before = cached.map { it.ip }.toSet()
            val after = nodes.map { it.ip }.toSet()
            val removed = before - after
            Log.i(
                TAG,
                "table $reason ($why) block=$target count=${nodes.size} added=${(after - before).size} " +
                    "removed=${removed.size} mailbox=${if (mailbox == null) "unchanged" else "matched"}",
            )
            BeamioEntryPool.nodesChanged(removed)
        } catch (e: Exception) {
            fail("poll ${e.message}")
        } finally {
            running.set(false)
        }
    }

    private fun fail(what: String) {
        failures++
        val backoff = minOf(FAIL_BACKOFF_MAX_MS, FAIL_BACKOFF_BASE_MS shl (failures - 1).coerceAtMost(10))
        notBefore = System.currentTimeMillis() + backoff
        Log.w(TAG, "$what failed; retry in ${backoff / 1000}s")
    }

    private fun shrinkRefusal(before: Int, after: Int): String? {
        if (after == 0) return "empty read (current $before)"
        if (before < 20 || after >= before * 0.5) {
            pendingShrink = null
            return null
        }
        val p = pendingShrink
        if (p != null && p.first == after) {
            if (System.currentTimeMillis() - p.second >= SHRINK_CONFIRM_MS) {
                pendingShrink = null
                return null
            }
            return "shrink $before→$after awaiting confirmation"
        }
        pendingShrink = after to System.currentTimeMillis()
        return "shrink $before→$after; needs a second read in 20 min"
    }

    // ---- chain reads ---------------------------------------------------------------

    private fun hexQ(n: Long) = "0x" + n.toString(16)

    private fun blockNumber(): Long? =
        ((rpc("eth_blockNumber", JSONArray()) as? Rpc.Ok)?.value as? String)
            ?.removePrefix("0x")?.toLongOrNull(16)

    private fun storageRoot(block: Long): Rpc =
        when (val r = rpc("eth_getProof", JSONArray().put(CONTRACT).put(JSONArray()).put(hexQ(block)))) {
            is Rpc.Ok -> {
                val h = (r.value as? JSONObject)?.optString("storageHash").orEmpty()
                if (h.length == 66 && h.startsWith("0x")) Rpc.Ok(h.lowercase()) else Rpc.Failed
            }
            else -> r
        }

    private fun contractTouched(from: Long, to: Long): Boolean? {
        var a = from + 1
        while (a <= to) {
            val b = minOf(to, a + LOGS_CHUNK - 1)
            val filter = JSONObject().put("address", CONTRACT).put("fromBlock", hexQ(a)).put("toBlock", hexQ(b))
            val logs = (rpc("eth_getLogs", JSONArray().put(filter)) as? Rpc.Ok)?.value as? JSONArray ?: return null
            if (logs.length() > 0) return true
            a = b + 1
        }
        if (to - from > MAX_TX_SCAN_BLOCKS) return true
        for (n in (from + 1)..to) {
            val blk = (rpc("eth_getBlockByNumber", JSONArray().put(hexQ(n)).put(true)) as? Rpc.Ok)?.value as? JSONObject
                ?: return null
            val txs = blk.optJSONArray("transactions") ?: continue
            for (i in 0 until txs.length()) {
                if (txs.optJSONObject(i)?.optString("to")?.lowercase() == CONTRACT.lowercase()) return true
            }
        }
        return false
    }

    /** Every page at [block], or null. A partial list never reaches the table. */
    private fun readAll(block: Long): List<Row>? {
        val all = ArrayList<Row>()
        val seen = HashSet<String>()
        var start = 0
        repeat(100) {
            var page: List<Row>? = null
            for (attempt in 1..3) {
                val data = "0x$GET_ALL_NODES${start.toString(16).padStart(64, '0')}${PAGE.toString(16).padStart(64, '0')}"
                val call = JSONObject().put("to", CONTRACT).put("data", data)
                val hex = (rpc("eth_call", JSONArray().put(call).put(hexQ(block))) as? Rpc.Ok)?.value as? String
                val rows = hex?.takeIf { it.startsWith("0x") && it.length % 2 == 0 }
                    ?.removePrefix("0x")?.chunked(2)?.map { it.toInt(16).toByte() }?.toByteArray()
                    ?.let { decode(it) }
                if (rows != null) {
                    page = rows
                    break
                }
                Thread.sleep(1_000L * attempt)
            }
            val rows = page ?: return null
            if (rows.isEmpty()) return all
            rows.forEach { if (seen.add(it.node.ip)) all.add(it) }
            if (rows.size < PAGE) return all
            start += rows.size
        }
        return null
    }

    private fun rpc(method: String, params: JSONArray): Rpc {
        val payload = JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", method).put("params", params)
        for (endpoint in RPCS) {
            try {
                val conn = (URL(endpoint).openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = 12_000
                    readTimeout = 20_000
                    doOutput = true
                    setRequestProperty("content-type", "application/json")
                }
                conn.outputStream.use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
                val code = conn.responseCode
                val text = (if (code in 200..299) conn.inputStream else conn.errorStream)
                    ?.bufferedReader()?.use { it.readText() }.orEmpty()
                conn.disconnect()
                val obj = JSONObject(text)
                obj.optJSONObject("error")?.let { err ->
                    val msg = err.optString("message").lowercase()
                    if (err.optInt("code") == -32601 || "not found" in msg || "not supported" in msg || "does not exist" in msg) {
                        return Rpc.Unsupported
                    }
                    return@let
                }
                if (obj.has("error")) continue
                val result = obj.opt("result")
                if (result != null && result != JSONObject.NULL) return Rpc.Ok(result)
            } catch (_: Exception) {
            }
        }
        return Rpc.Failed
    }

    // ---- ABI ------------------------------------------------------------------------

    private fun decode(bytes: ByteArray): List<Row>? {
        val outer = u256(bytes, 0) ?: return null
        if (outer + 32 > bytes.size) return null
        val n = u256(bytes, outer) ?: return null
        if (n > 1000) return null
        if (n == 0) return emptyList()
        val heads = outer + 32
        val out = ArrayList<Row>()
        for (i in 0 until n) {
            val rel = u256(bytes, heads + 32 * i) ?: return null
            val tup = heads + rel
            if (tup + 32 * 5 > bytes.size) return null
            val pgp = readString(bytes, tup, 1) ?: return null
            val pgpKey = readString(bytes, tup, 2) ?: return null
            val ipRaw = readString(bytes, tup, 3) ?: return null
            val region = readString(bytes, tup, 4) ?: return null
            val ip = BeamioSiCipherPost.normalizeIp(ipRaw) ?: continue
            out.add(Row(BeamioChatPgpStore.SiNode(ip = ip, domain = pgpKey.trim().take(256), region = region.trim().take(64)), armorFromBase64(pgp)))
        }
        return out
    }

    private fun matchMailbox(ctx: Context, rows: List<Row>): String? {
        val route = normalizeArmor(BeamioChatPgpStore.loadRoutePublicArmor(ctx))
        if (!route.contains("BEGIN PGP PUBLIC KEY")) return null
        return rows.firstOrNull { normalizeArmor(it.armor) == route }?.node?.ip
    }

    private fun armorFromBase64(raw: String): String = try {
        String(Base64.decode(raw.filter { !it.isWhitespace() }, Base64.DEFAULT), Charsets.UTF_8)
    } catch (_: Exception) {
        ""
    }

    private fun normalizeArmor(raw: String) = raw.replace("\r\n", "\n").replace("\r", "\n").trim()

    private fun u256(bytes: ByteArray, off: Int): Int? {
        if (off < 0 || off + 32 > bytes.size) return null
        for (i in 0 until 24) if (bytes[off + i] != 0.toByte()) return null
        var v = 0L
        for (i in 24 until 32) v = (v shl 8) or (bytes[off + i].toLong() and 0xff)
        if (v > Int.MAX_VALUE) return null
        return v.toInt()
    }

    private fun readString(bytes: ByteArray, tup: Int, word: Int): String? {
        val rel = u256(bytes, tup + 32 * word) ?: return null
        val abs = tup + rel
        val len = u256(bytes, abs) ?: return null
        if (len >= 200_000 || abs + 32 + len > bytes.size) return null
        return String(bytes, abs + 32, len, Charsets.UTF_8)
    }
}
