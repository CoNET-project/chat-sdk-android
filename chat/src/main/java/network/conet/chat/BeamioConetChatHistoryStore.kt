package network.conet.chat

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Encrypted chat history: AES-GCM fragments on IPFS + a head pointer on the CoNET
 * `ChatIndexRegistry`. Model 1B: the EOA never leaves the PWA; the history master key is
 * derived from an EIP-191 signature requested through [BeamioConetChatSignBroker].
 *
 * Wire-compatible with the TypeScript `@conet.project/chat-sdk` history worker:
 * `master = keccak256(utf8(sign("beamio.chat.history.v1|chainId|eoa")))`,
 * `k_i = HKDF(master, "frag|seq|prevCid")`, index key `HKDF(master, "index-enc")`.
 */
class BeamioConetChatHistoryStore(
    eoa: String,
    private val chainId: Int,
    private val conetRpcUrl: String,
    ipfsBaseUrl: String,
    ipfsWriteBaseUrl: String?,
    apiBaseUrl: String,
    private val registryAddress: String,
    private val log: (level: String, message: String) -> Unit,
) {
    data class IndexRecord(
        val seq: Int,
        val cid: String,
        val prevCid: String,
        val ts: Long,
        val peer: String,
        val dir: String,
        val sendId: String,
        val preview: String?,
    )

    data class Entry(
        val seq: Int,
        val ts: Long,
        val peer: String,
        val dir: String,
        val sendId: String,
        val body: String,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("seq", seq)
            .put("ts", ts)
            .put("peer", peer)
            .put("dir", dir)
            .put("sendId", sendId)
            .put("body", body)
    }

    private data class Pointer(val indexHash: String, val ts: Long, val seq: Long)

    private val eoa = eoa.lowercase()
    private val ipfsRead = ipfsBaseUrl.trimEnd('/')
    private val ipfsWrite = (ipfsWriteBaseUrl?.takeIf { it.isNotBlank() } ?: ipfsBaseUrl).trimEnd('/')
    private val apiBase = apiBaseUrl.trimEnd('/')

    @Volatile
    private var master: ByteArray? = null
    @Volatile
    private var indexKey: ByteArray? = null
    private var genesisCid = ""
    private var selfSign = ""
    @Volatile
    private var ready = false
    private var records: MutableList<IndexRecord> = ArrayList()
    private var syncedIndexHash = ""

    /**
     * Immutable copy of [records], republished after every mutation on [queue].
     * [read] works from this snapshot so it never waits behind a slow append / head sync
     * (each of those can take several seconds of IPFS + RPC + pointer relay).
     */
    @Volatile
    private var snapshot: List<IndexRecord> = emptyList()

    /** True once the chain head has been adopted at least once in this process. */
    @Volatile
    private var everSynced = false

    /** Plaintext of entries decrypted or appended in this session (also used to re-append after a fork). */
    private val plain = ConcurrentHashMap<String, Entry>()
    private val emittedCids = HashSet<String>()

    private val loadLock = ReentrantLock()
    private val loadIdle = loadLock.newCondition()
    private var loadsInFlight = 0

    /** Serial lane for everything that mutates the chain (prepare / load / append / head sync). */
    private val queue = Executors.newSingleThreadExecutor { r ->
        Thread(r, "conet-chat-history").apply { isDaemon = true }
    }

    /** Read lane: global corpus reads, independent of [queue]. */
    private val readQueue = Executors.newSingleThreadExecutor { r ->
        Thread(r, "conet-chat-history-read").apply { isDaemon = true }
    }

    /** Bounded parallel IPFS fetch + decrypt for restore / read (TS worker decrypts the tail concurrently). */
    private val fetchPool: ExecutorService = Executors.newFixedThreadPool(FETCH_PARALLELISM) { r ->
        Thread(r, "conet-chat-history-fetch").apply { isDaemon = true }
    }

    fun isReady(): Boolean = ready

    fun destroy() {
        queue.shutdownNow()
        readQueue.shutdownNow()
        fetchPool.shutdownNow()
        master = null
        indexKey = null
        ready = false
    }

    private fun publishSnapshot() {
        snapshot = records.toList()
    }

    // ---- lifecycle ---------------------------------------------------------------

    fun prepare(completion: (Boolean) -> Unit) {
        queue.execute {
            try {
                val domain = "beamio.chat.history.v1|$chainId|$eoa"
                val domainSig = awaitSign { BeamioConetChatSignBroker.requestEip191(domain, completion = it) }
                selfSign = awaitSign { BeamioConetChatSignBroker.requestEip191(eoa, completion = it) }
                val masterBytes = ConetChatCryptoUtil.keccak256(domainSig.toByteArray(Charsets.UTF_8))
                master = masterBytes
                indexKey = ConetChatCryptoUtil.hkdf(masterBytes, "index-enc", 32)
                val genesis = ConetChatCryptoUtil.hkdf(masterBytes, FRAGMENT_GENESIS_INFO, 32)
                genesisCid = "0x" + ConetChatCryptoUtil.toHex(genesis)
                ready = true
                log("info", "[history] ready genesis=${shortCid(genesisCid)}")
                completion(true)
            } catch (e: Exception) {
                log("warn", "[history] prepare failed: ${e.message}")
                completion(false)
            }
        }
    }

    /**
     * Restore: sync the head pointer, then publish decrypted entries through [emitBuffer]
     * (tail first, older batches after) — the same `historyBuffer` shape the TS worker emits.
     */
    fun load(
        options: JSONObject?,
        emitBuffer: (peer: String, entries: List<Entry>, isTail: Boolean) -> Unit,
        done: () -> Unit,
    ) {
        loadLock.withLock { loadsInFlight++ }
        queue.execute {
            try {
                if (!ready) return@execute
                val tailCount = options?.optInt("tailCount", 60)?.takeIf { it > 0 } ?: 60
                val localOnly = options?.optBoolean("localOnly", false) ?: false
                val emitAll = options?.optString("emit", "fresh") == "all"
                val peerFilter = options?.optString("peer", "")?.lowercase()?.takeIf { it.isNotEmpty() }
                if (!localOnly) syncFromHead()
                var recs = records.toList()
                if (peerFilter != null) recs = recs.filter { it.peer.lowercase() == peerFilter }
                val peerKey = peerFilter ?: "all"
                if (recs.isEmpty()) {
                    emitBuffer(peerKey, emptyList(), true)
                    return@execute
                }
                val ordered = recs.sortedBy { it.seq }
                val tail = ordered.takeLast(tailCount)
                val older = ordered.dropLast(tail.size)
                log("info", "[history] load peer=$peerKey records=${ordered.size} tail=${tail.size} older=${older.size}")

                fun publish(batch: List<IndexRecord>, isTail: Boolean) {
                    val materialized = materializeAll(batch)
                    val entries = ArrayList<Entry>()
                    for ((idx, rec) in batch.withIndex()) {
                        val fresh = emittedCids.add(rec.cid)
                        val entry = materialized[idx] ?: continue
                        if (emitAll || fresh) entries.add(entry)
                    }
                    if (entries.isNotEmpty()) emitBuffer(peerKey, entries, isTail)
                }
                publish(tail, true)
                var i = older.size
                while (i > 0) {
                    publish(older.subList(maxOf(0, i - BACKFILL_BATCH), i), false)
                    i -= BACKFILL_BATCH
                }
            } catch (e: Exception) {
                log("warn", "[history] load failed: ${e.message}")
            } finally {
                loadLock.withLock {
                    loadsInFlight--
                    loadIdle.signalAll()
                }
                done()
            }
        }
    }

    /** A read issued while a restore is running waits (bounded) for that restore's head sync. */
    private fun awaitRestoreIdle(timeoutMs: Long) {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        loadLock.withLock {
            var left = deadline - System.nanoTime()
            while (loadsInFlight > 0 && left > 0) {
                left = loadIdle.awaitNanos(left)
            }
        }
    }

    /**
     * Global read of the decrypted corpus (does not refresh the on-chain pointer).
     * Runs on its own lane from the last published [snapshot], so it answers immediately
     * even while an append / head sync is still talking to IPFS and the relay.
     */
    fun read(options: JSONObject?, completion: (List<Entry>) -> Unit) {
        readQueue.execute {
            try {
                if (!ready) {
                    completion(emptyList())
                    return@execute
                }
                awaitRestoreIdle(READ_RESTORE_WAIT_MS)
                if (!everSynced && snapshot.isEmpty()) {
                    // Nothing restored yet (cold start, read raced ahead of historyLoad): an empty
                    // answer would look like "no history", so pull the chain head first.
                    val synced = CountDownLatch(1)
                    queue.execute {
                        try {
                            syncFromHead()
                        } catch (e: Exception) {
                            log("warn", "[history] read-triggered sync failed: ${e.message}")
                        } finally {
                            synced.countDown()
                        }
                    }
                    synced.await(READ_RESTORE_WAIT_MS, TimeUnit.MILLISECONDS)
                }
                val peer = options?.optString("peer", "")?.lowercase()?.takeIf { it.isNotEmpty() }
                val query = options?.optString("query", "")?.trim().orEmpty()
                val limit = options?.optInt("limit", 0) ?: 0
                val terms = query.lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
                val candidates = snapshot.filter { peer == null || it.peer.lowercase() == peer }
                val materialized = materializeAll(candidates)
                val entries = ArrayList<Entry>()
                for (entry in materialized) {
                    if (entry == null) continue
                    if (terms.isNotEmpty()) {
                        val text = entry.body.lowercase()
                        if (!terms.all { text.contains(it) }) continue
                    }
                    entries.add(entry)
                }
                entries.sortWith(compareBy<Entry>({ it.ts }, { it.seq }))
                completion(if (limit > 0 && entries.size > limit) entries.takeLast(limit) else entries)
            } catch (e: Exception) {
                log("warn", "[history] read failed: ${e.message}")
                completion(emptyList())
            }
        }
    }

    /** Append one mirrored entry. Idempotent per `sendId`. */
    fun append(entry: JSONObject, completion: (Boolean) -> Unit) {
        queue.execute {
            try {
                completion(appendUnlocked(entry))
            } catch (e: Exception) {
                log("warn", "[history] append failed: ${e.message}")
                completion(false)
            }
        }
    }

    // ---- append / sync -----------------------------------------------------------

    private fun appendUnlocked(entry: JSONObject): Boolean {
        val key = indexKey ?: return false
        val masterKey = master ?: return false
        if (!ready) return false
        val sendId = entry.optString("sendId", "").ifEmpty { UUID.randomUUID().toString() }
        // Re-mirroring a conversation re-appends every bubble: skip what the index already has.
        if (records.any { it.sendId == sendId }) return true
        syncFromHead()
        if (records.any { it.sendId == sendId }) return true

        val peer = entry.optString("peer", "").lowercase()
        val dir = entry.optString("dir", "out")
        val body = entry.optString("body", "")
        val ts = if (entry.has("ts")) entry.optLong("ts") else System.currentTimeMillis()
        val seq = if (records.isEmpty()) 0 else records.last().seq + 1
        val prevCid = if (records.isEmpty()) genesisCid else records.last().cid

        val fragKey = ConetChatCryptoUtil.hkdf(masterKey, "frag|$seq|$prevCid", 32)
        val cipher = ConetChatCryptoUtil.aesGcmEncrypt(fragKey, body.toByteArray(Charsets.UTF_8))
        val cid = ConetChatCryptoUtil.keccakUtf8Hex(cipher)
        if (uploadFragment(cipher) == null) return false
        records.add(IndexRecord(seq, cid, prevCid, ts, peer, dir, sendId, body.take(80)))
        plain[cid] = Entry(seq, ts, peer, dir, sendId, body)
        emittedCids.add(cid)
        publishSnapshot()
        return persistManifest(key)
    }

    /** Adopt the remote chain, then re-append any local-only entries (fork repair). */
    private fun syncFromHead() {
        val key = indexKey ?: return
        val pointer = readOnchainPointer() ?: return
        if (pointer.indexHash == syncedIndexHash) return
        val cipher = fetchFragment(pointer.indexHash) ?: return
        val remote: JSONObject = try {
            JSONObject(String(ConetChatCryptoUtil.aesGcmDecrypt(key, cipher), Charsets.UTF_8))
        } catch (e: Exception) {
            log("warn", "[history] sync decrypt failed")
            return
        }
        if (remote.optInt("v", 0) != 1 || remote.optString("eoa", "").lowercase() != eoa) return
        val remoteRecords = parseRecords(remote.optJSONArray("records"))
        val remoteSendIds = remoteRecords.map { it.sendId }.filter { it.isNotEmpty() }.toSet()
        val remoteCids = remoteRecords.map { it.cid }.toSet()
        val localOnly = records.filter {
            it.cid !in remoteCids && (it.sendId.isEmpty() || it.sendId !in remoteSendIds)
        }
        records = remoteRecords.toMutableList()
        publishSnapshot()
        syncedIndexHash = pointer.indexHash
        everSynced = true
        log("info", "[history] synced records=${records.size} localOnly=${localOnly.size}")
        for (rec in localOnly) {
            val entry = plain[rec.cid] ?: continue
            appendUnlocked(
                JSONObject()
                    .put("peer", entry.peer)
                    .put("dir", entry.dir)
                    .put("sendId", entry.sendId)
                    .put("body", entry.body)
                    .put("ts", entry.ts),
            )
        }
    }

    private fun persistManifest(key: ByteArray): Boolean {
        val manifest = JSONObject()
            .put("v", 1)
            .put("eoa", eoa)
            .put("updatedAt", System.currentTimeMillis())
            .put("records", encodeRecords(records))
        val cipher = ConetChatCryptoUtil.aesGcmEncrypt(key, manifest.toString().toByteArray(Charsets.UTF_8))
        val indexHash = uploadFragment(cipher) ?: return false
        val ok = updateOnchainPointer(indexHash, records.size)
        if (ok) {
            syncedIndexHash = indexHash
            log("info", "[history] pointer updated records=${records.size} index=${shortCid(indexHash)}")
        }
        return ok
    }

    /**
     * Decrypts [batch] with bounded parallelism (IPFS fetch dominates); result order matches
     * [batch], `null` for fragments that could not be fetched or decrypted. Safe to call from
     * any lane — only [plain] (concurrent) is shared.
     */
    private fun materializeAll(batch: List<IndexRecord>): List<Entry?> {
        if (batch.isEmpty()) return emptyList()
        val missing = batch.count { !plain.containsKey(it.cid) }
        if (missing <= 1) return batch.map { materialize(it) }
        val futures = batch.map { rec ->
            if (plain.containsKey(rec.cid)) null
            else fetchPool.submit(Callable { materialize(rec) })
        }
        return batch.mapIndexed { idx, rec ->
            plain[rec.cid] ?: futures[idx]?.let {
                try {
                    it.get(MATERIALIZE_TIMEOUT_SEC, TimeUnit.SECONDS)
                } catch (e: Exception) {
                    null
                }
            }
        }
    }

    private fun materialize(rec: IndexRecord): Entry? {
        plain[rec.cid]?.let { return it }
        val masterKey = master ?: return null
        val cipher = fetchFragment(rec.cid) ?: return null
        return try {
            val k = ConetChatCryptoUtil.hkdf(masterKey, "frag|${rec.seq}|${rec.prevCid}", 32)
            val body = String(ConetChatCryptoUtil.aesGcmDecrypt(k, cipher), Charsets.UTF_8)
            Entry(rec.seq, rec.ts, rec.peer, rec.dir, rec.sendId, body).also { plain[rec.cid] = it }
        } catch (e: Exception) {
            log("warn", "[history] record decrypt failed seq=${rec.seq} cid=${shortCid(rec.cid)}")
            null
        }
    }

    // ---- chain / IPFS ------------------------------------------------------------

    private fun readOnchainPointer(): Pointer? {
        val data = SEL_GET_POINTER + padAddress(eoa)
        val result = ethCall(registryAddress, data) ?: return null
        if (!result.startsWith("0x") || result.length < 2 + 64 * 3) return null
        val hex = result.substring(2)
        val indexHash = "0x" + hex.substring(0, 64)
        if (indexHash == "0x" + "0".repeat(64)) return null
        fun u64(offset: Int): Long = hex.substring(offset, offset + 64).trimStart('0').ifEmpty { "0" }.toLongOrNull(16) ?: 0L
        return Pointer(indexHash, u64(64), u64(128))
    }

    private fun updateOnchainPointer(indexHash: String, recordCount: Int): Boolean {
        val nonceHex = ethCall(registryAddress, SEL_NONCE_OF + padAddress(eoa))
        if (nonceHex == null || nonceHex.length < 66) {
            log("warn", "[history] nonceOf failed")
            return false
        }
        val nonce = java.math.BigInteger(nonceHex.substring(nonceHex.length - 64), 16).toString()
        val ts = System.currentTimeMillis()
        val seq = recordCount.toLong()
        val message = JSONObject()
            .put("owner", eoa)
            .put("indexHash", indexHash)
            .put("ts", ts.toString())
            .put("seq", seq.toString())
            .put("nonce", nonce)
        val typedData = JSONObject()
            .put(
                "types",
                JSONObject()
                    .put(
                        "EIP712Domain",
                        JSONArray()
                            .put(field("name", "string"))
                            .put(field("version", "string"))
                            .put(field("chainId", "uint256"))
                            .put(field("verifyingContract", "address")),
                    )
                    .put(
                        "SetPointer",
                        JSONArray()
                            .put(field("owner", "address"))
                            .put(field("indexHash", "bytes32"))
                            .put(field("ts", "uint64"))
                            .put(field("seq", "uint64"))
                            .put(field("nonce", "uint256")),
                    ),
            )
            .put("primaryType", "SetPointer")
            .put(
                "domain",
                JSONObject()
                    .put("name", "ChatIndexRegistry")
                    .put("version", "1")
                    .put("chainId", chainId)
                    .put("verifyingContract", registryAddress),
            )
            // `value` is what the PWA signer reads; `message` is the EIP-712 JSON spelling.
            .put("value", message)
            .put("message", message)
        val signature = try {
            awaitSign { BeamioConetChatSignBroker.requestEip712(typedData, completion = it) }
        } catch (e: Exception) {
            log("warn", "[history] SetPointer sign failed: ${e.message}")
            return false
        }
        val body = JSONObject()
            .put("owner", eoa)
            .put("indexHash", indexHash)
            .put("ts", ts.toString())
            .put("seq", seq.toString())
            .put("nonce", nonce)
            .put("signature", signature)
            .toString()
        val (status, _) = httpPostJson("$apiBase/setChatIndexPointer", body, 30_000)
        if (status !in 200..299) {
            log("warn", "[history] setChatIndexPointer HTTP $status")
            return false
        }
        return true
    }

    private fun uploadFragment(cipherB64: String): String? {
        val contentHash = ConetChatCryptoUtil.keccakUtf8Hex(cipherB64)
        val body = JSONObject()
            .put("wallet", eoa)
            .put("signMessage", selfSign)
            .put("image", cipherB64)
            .toString()
        val (status, _) = httpPostJson("$ipfsWrite/storageFragment", body, 45_000)
        if (status !in 200..299) {
            log("warn", "[history] storageFragment HTTP $status")
            return null
        }
        return contentHash
    }

    private fun fetchFragment(hash: String): String? {
        val url = "$ipfsRead/getFragment?hash=${URLEncoder.encode(hash, "UTF-8")}"
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 15_000
                readTimeout = 30_000
                useCaches = false
            }
            val code = conn.responseCode
            if (code !in 200..299) return null
            val text = BufferedReader(InputStreamReader(conn.inputStream, Charsets.UTF_8)).use { it.readText() }.trim()
            text.ifEmpty { null }
        } catch (_: Exception) {
            null
        } finally {
            conn?.disconnect()
        }
    }

    private fun ethCall(to: String, data: String): String? {
        val payload = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", 1)
            .put("method", "eth_call")
            .put("params", JSONArray().put(JSONObject().put("to", to).put("data", data)).put("latest"))
            .toString()
        val (status, text) = httpPostJson(conetRpcUrl, payload, 20_000)
        if (status !in 200..299) return null
        return try {
            JSONObject(text).optString("result", "").takeIf { it.startsWith("0x") }
        } catch (_: Exception) {
            null
        }
    }

    private fun httpPostJson(url: String, body: String, timeoutMs: Int): Pair<Int, String> {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 15_000
                readTimeout = timeoutMs
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.let {
                BufferedReader(InputStreamReader(it, Charsets.UTF_8)).use { r -> r.readText() }
            }.orEmpty()
            code to text
        } catch (e: Exception) {
            Log.w(TAG, "http ${e.javaClass.simpleName}: ${e.message}")
            0 to ""
        } finally {
            conn?.disconnect()
        }
    }

    // ---- helpers -----------------------------------------------------------------

    private fun awaitSign(request: ((Result<String>) -> Unit) -> Unit): String {
        val latch = CountDownLatch(1)
        var out: Result<String> = Result.failure(IllegalStateException("sign_failed"))
        request { result ->
            out = result
            latch.countDown()
        }
        if (!latch.await(35, TimeUnit.SECONDS)) throw IllegalStateException("sign_timeout")
        return out.getOrThrow()
    }

    private fun field(name: String, type: String) = JSONObject().put("name", name).put("type", type)

    private fun padAddress(addr: String): String {
        val a = addr.lowercase().removePrefix("0x")
        return "0".repeat(maxOf(0, 64 - a.length)) + a
    }

    private fun parseRecords(arr: JSONArray?): List<IndexRecord> {
        if (arr == null) return emptyList()
        val out = ArrayList<IndexRecord>()
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            out.add(
                IndexRecord(
                    seq = o.optInt("seq"),
                    cid = o.optString("cid"),
                    prevCid = o.optString("prevCid"),
                    ts = o.optLong("ts"),
                    peer = o.optString("peer"),
                    dir = o.optString("dir", "out"),
                    sendId = o.optString("sendId", ""),
                    preview = o.optString("preview", "").takeIf { it.isNotEmpty() },
                ),
            )
        }
        return out.sortedWith(compareBy<IndexRecord>({ it.seq }, { it.cid }))
    }

    private fun encodeRecords(list: List<IndexRecord>): JSONArray {
        val arr = JSONArray()
        for (r in list) {
            val o = JSONObject()
                .put("seq", r.seq)
                .put("cid", r.cid)
                .put("prevCid", r.prevCid)
                .put("ts", r.ts)
                .put("peer", r.peer)
                .put("dir", r.dir)
                .put("sendId", r.sendId)
            if (r.preview != null) o.put("preview", r.preview)
            arr.put(o)
        }
        return arr
    }

    private fun shortCid(cid: String): String =
        if (cid.length > 14) cid.take(10) + "…" + cid.takeLast(4) else cid

    companion object {
        private const val TAG = "BeamioConetHistory"
        private const val FRAGMENT_GENESIS_INFO = "frag-genesis"
        private const val BACKFILL_BATCH = 20

        /** Concurrent IPFS fetch+decrypt workers for restore / global read. */
        private const val FETCH_PARALLELISM = 6
        private const val MATERIALIZE_TIMEOUT_SEC = 45L

        /** Longest a read waits for an in-flight restore before answering from the current snapshot. */
        private const val READ_RESTORE_WAIT_MS = 20_000L

        /** `bytes4(keccak256("getPointer(address)"))`. */
        internal const val SEL_GET_POINTER = "0x6bd15a9f"

        /** `bytes4(keccak256("nonceOf(address)"))`. */
        internal const val SEL_NONCE_OF = "0xed2a2d64"
    }
}
