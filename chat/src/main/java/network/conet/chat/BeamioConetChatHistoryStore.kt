package network.conet.chat

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
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
 *
 * Batched writes (2026-11-04, `history-batch-write-design.md`, rules in [HistoryBatch]):
 * - [append] only queues the entry in an encrypted file (key `HKDF(master, "pending-enc")`).
 *   Fragments, index and pointer are written later in one batch: 10 entries, or 2 minutes
 *   after the first waiting entry, whichever comes first, each with random delay.
 * - The pointer write passes the on-chain `ts` / `seq` unchanged (no client clock on chain).
 * - Compare-and-swap: `getPointer` and `nonceOf` are read at one block and the signature uses
 *   that nonce; a concurrent write from another device makes ours fail, then we re-read, chain
 *   our entries after theirs and retry. Committed fragments are never re-encrypted.
 * - Head sync never writes the chain; entries a newer head lacks go back to the queue.
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
    /** Directory for the encrypted pending queue (app-private). null = memory only. */
    private val storageDir: File? = null,
    net: HistoryNet? = null,
    clock: HistoryClock? = null,
    signer: HistorySigner? = null,
    /** False in tests: no timer, no head poll; tests call [flushNowBlocking]. */
    private val autoFlush: Boolean = true,
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
    ) {
        /** Committed key: the sendId (new entries always carry one), else the fragment cid. */
        val key: String get() = sendId.ifEmpty { "cid:$cid" }
    }

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

    enum class FlushResult { OK, EMPTY, CONFLICT, ERROR, NOT_READY }

    private val eoa = eoa.lowercase()
    private val ipfsRead = ipfsBaseUrl.trimEnd('/')
    private val ipfsWrite = (ipfsWriteBaseUrl?.takeIf { it.isNotBlank() } ?: ipfsBaseUrl).trimEnd('/')
    private val apiBase = apiBaseUrl.trimEnd('/')
    private val net: HistoryNet = net ?: DefaultNet()
    private val clock: HistoryClock = clock ?: object : HistoryClock {
        override fun now(): Long = System.currentTimeMillis()
        override fun random(): Double = Math.random()
    }
    private val signer: HistorySigner = signer ?: BrokerSigner()
    private val random: () -> Double = { this.clock.random() }

    @Volatile
    private var master: ByteArray? = null
    @Volatile
    private var indexKey: ByteArray? = null
    private var pendingKey: ByteArray? = null
    private var genesisCid = ""
    private var selfSign = ""
    @Volatile
    private var ready = false
    @Volatile
    private var destroyed = false

    /** Last adopted on-chain index (committed records only). Queue thread only. */
    private var records: MutableList<IndexRecord> = ArrayList()
    private var syncedIndexHash = ""
    private var pending = HistoryBatch.PendingState()

    /** Immutable copies for the read lane, republished after every mutation on [queue]. */
    @Volatile
    private var snapshot: List<IndexRecord> = emptyList()
    @Volatile
    private var pendingSnapshot: List<HistoryBatch.PendingEntry> = emptyList()

    /** True once the chain head has been adopted at least once in this process. */
    @Volatile
    private var everSynced = false

    /** Plaintext of entries decrypted or written in this session (also used to re-queue lost ones). */
    private val plain = ConcurrentHashMap<String, Entry>()
    private val emittedCids = HashSet<String>()

    /** Emitter of the last [load], reused when the head poll finds entries from another device. */
    @Volatile
    private var lastEmit: ((String, List<Entry>, Boolean) -> Unit)? = null

    private val loadLock = ReentrantLock()
    private val loadIdle = loadLock.newCondition()
    private var loadsInFlight = 0

    /** Serial lane for everything that mutates state (prepare / load / append / sync / flush). */
    private val queue = Executors.newSingleThreadExecutor { r ->
        Thread(r, "conet-chat-history").apply { isDaemon = true }
    }

    /** Read lane: global corpus reads, independent of [queue]. */
    private val readQueue = Executors.newSingleThreadExecutor { r ->
        Thread(r, "conet-chat-history-read").apply { isDaemon = true }
    }

    /** Write timer and head poll; both hand their work to [queue]. */
    private val timers: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "conet-chat-history-timer").apply { isDaemon = true }
    }
    private var flushTimer: ScheduledFuture<*>? = null
    private var pollTimer: ScheduledFuture<*>? = null

    /** Bounded parallel IPFS fetch + decrypt for restore / read (TS worker decrypts the tail concurrently). */
    private val fetchPool: ExecutorService = Executors.newFixedThreadPool(FETCH_PARALLELISM) { r ->
        Thread(r, "conet-chat-history-fetch").apply { isDaemon = true }
    }

    fun isReady(): Boolean = ready

    fun destroy() {
        destroyed = true
        synchronized(timers) {
            flushTimer?.cancel(false)
            pollTimer?.cancel(false)
        }
        timers.shutdownNow()
        queue.shutdownNow()
        readQueue.shutdownNow()
        fetchPool.shutdownNow()
        master = null
        indexKey = null
        ready = false
    }

    private fun publishSnapshot() {
        snapshot = records.toList()
        pendingSnapshot = pending.entries.toList()
    }

    // ---- lifecycle ---------------------------------------------------------------

    fun prepare(completion: (Boolean) -> Unit) {
        queue.execute {
            try {
                val domain = "beamio.chat.history.v1|$chainId|$eoa"
                val domainSig = signer.eip191(domain)
                selfSign = signer.eip191(eoa)
                val masterBytes = ConetChatCryptoUtil.keccak256(domainSig.toByteArray(Charsets.UTF_8))
                master = masterBytes
                indexKey = ConetChatCryptoUtil.hkdf(masterBytes, "index-enc", 32)
                pendingKey = ConetChatCryptoUtil.hkdf(masterBytes, PENDING_KEY_INFO, 32)
                val genesis = ConetChatCryptoUtil.hkdf(masterBytes, FRAGMENT_GENESIS_INFO, 32)
                genesisCid = "0x" + ConetChatCryptoUtil.toHex(genesis)
                // Restore the queue left by the last run; a write that fell due while closed runs 10–60 s from now.
                pending = readPendingFile() ?: HistoryBatch.PendingState()
                HistoryBatch.resume(pending, clock.now(), random)
                writePendingFile()
                publishSnapshot()
                ready = true
                log("info", "[history] ready genesis=${shortCid(genesisCid)} pending=${pending.entries.size}")
                armTimer()
                schedulePoll()
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
                if (peerFilter == null) lastEmit = emitBuffer
                if (!localOnly) syncFromHead()
                publishRecords(peerFilter, tailCount, emitAll, emitBuffer)
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

    private fun publishRecords(
        peerFilter: String?,
        tailCount: Int,
        emitAll: Boolean,
        emitBuffer: (peer: String, entries: List<Entry>, isTail: Boolean) -> Unit,
    ) {
        var recs = records.toList()
        if (peerFilter != null) recs = recs.filter { it.peer.lowercase() == peerFilter }
        val peerKey = peerFilter ?: "all"
        if (recs.isEmpty()) {
            emitBuffer(peerKey, emptyList(), true)
            return
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
     * Global read of the decrypted corpus plus entries still waiting to be written (does not
     * refresh the on-chain pointer). Runs on its own lane from the last published snapshots.
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
                val committed = snapshot
                val candidates = committed.filter { peer == null || it.peer.lowercase() == peer }
                val materialized = materializeAll(candidates)
                val entries = ArrayList<Entry>()
                fun matches(body: String): Boolean {
                    if (terms.isEmpty()) return true
                    val text = body.lowercase()
                    return terms.all { text.contains(it) }
                }
                for (entry in materialized) {
                    if (entry == null || !matches(entry.body)) continue
                    entries.add(entry)
                }
                var provisionalSeq = (committed.maxOfOrNull { it.seq } ?: -1) + 1
                for (w in HistoryBatch.order(pendingSnapshot)) {
                    if (peer != null && w.peer != peer) continue
                    if (!matches(w.body)) continue
                    entries.add(Entry(provisionalSeq++, w.ts, w.peer, w.dir, w.key, w.body))
                }
                entries.sortWith(compareBy<Entry>({ it.ts }, { it.seq }))
                completion(if (limit > 0 && entries.size > limit) entries.takeLast(limit) else entries)
            } catch (e: Exception) {
                log("warn", "[history] read failed: ${e.message}")
                completion(emptyList())
            }
        }
    }

    /** Queue one mirrored entry for the next batch write. Idempotent per key. */
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

    /** Write every waiting entry now (tests; production uses the timer). Blocks the caller. */
    fun flushNowBlocking(timeoutMs: Long = 120_000): FlushResult {
        val latch = CountDownLatch(1)
        var result = FlushResult.NOT_READY
        try {
            queue.execute {
                try {
                    result = flushUnlocked()
                } finally {
                    latch.countDown()
                }
            }
        } catch (_: Exception) {
            return FlushResult.NOT_READY
        }
        latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        return result
    }

    /** Pull the head now (tests). Blocks the caller. */
    fun syncNowBlocking(timeoutMs: Long = 60_000): Boolean {
        val latch = CountDownLatch(1)
        var changed = false
        queue.execute {
            try {
                changed = syncFromHead()
            } finally {
                latch.countDown()
            }
        }
        latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        return changed
    }

    /** Entries waiting for the next batch write (diagnostics / tests). */
    fun pendingCount(): Int = pendingSnapshot.size

    /** Planned write time (diagnostics / tests), read on the queue thread. */
    fun pendingDueAtBlocking(): Long? {
        val latch = CountDownLatch(1)
        var due: Long? = null
        queue.execute {
            due = pending.dueAt
            latch.countDown()
        }
        latch.await(10, TimeUnit.SECONDS)
        return due
    }

    // ---- append / sync / flush (queue thread) ---------------------------------------

    private fun committedKeys(): Set<String> = records.mapTo(HashSet()) { it.key }

    private fun appendUnlocked(entry: JSONObject): Boolean {
        if (!ready || destroyed) return false
        val peer = entry.optString("peer", "").lowercase()
        val dir = entry.optString("dir", "out")
        val body = entry.optString("body", "")
        val ts = if (entry.has("ts")) entry.optLong("ts") else clock.now()
        val key = HistoryBatch.recordKey(entry.optString("sendId", ""), peer, dir, ts, body)
        val committed = committedKeys()
        val added = HistoryBatch.enqueue(
            pending,
            HistoryBatch.PendingEntry(key, peer, dir, ts, body),
            clock.now(),
            random,
        ) { it in committed }
        if (!added) return true
        writePendingFile()
        publishSnapshot()
        armTimer()
        return true
    }

    /**
     * Adopt [snap]'s head as the committed index. Never writes the chain. Records the previous
     * head had but this one lacks (an older client overwrote them) go back to the queue.
     * Returns null when the head could not be fetched or decrypted (state untouched).
     */
    private fun adoptHead(snap: HistorySnapshot): Boolean? {
        val key = indexKey ?: return null
        val previous = records.toList()
        if (snap.indexHash != null && snap.indexHash == syncedIndexHash && everSynced) return false
        val remote: List<IndexRecord> = if (snap.indexHash == null) {
            emptyList()
        } else {
            val cipher = net.fetchFragment(snap.indexHash) ?: run {
                log("warn", "[history] index fetch failed index=${shortCid(snap.indexHash)}")
                return null
            }
            val obj = try {
                JSONObject(String(ConetChatCryptoUtil.aesGcmDecrypt(key, cipher), Charsets.UTF_8))
            } catch (e: Exception) {
                log("warn", "[history] sync decrypt failed")
                return null
            }
            if (obj.optInt("v", 0) != 1 || obj.optString("eoa", "").lowercase() != eoa) {
                log("warn", "[history] index version/owner mismatch")
                return null
            }
            parseRecords(obj.optJSONArray("records"))
        }
        val remoteKeys = remote.mapTo(HashSet()) { it.key }
        var requeued = 0
        for (rec in previous) {
            if (rec.key in remoteKeys) continue
            val entry = plain[rec.cid] ?: materialize(rec) ?: continue
            val k = rec.sendId.ifEmpty { HistoryBatch.recordKey(null, entry.peer, entry.dir, entry.ts, entry.body) }
            val added = HistoryBatch.enqueue(
                pending,
                HistoryBatch.PendingEntry(k, entry.peer, entry.dir, entry.ts, entry.body),
                clock.now(),
                random,
            ) { it in remoteKeys }
            if (added) requeued++
        }
        HistoryBatch.dropCommitted(pending) { it in remoteKeys }
        val changed = remote.size != previous.size || remote.indices.any { remote[it].cid != previous.getOrNull(it)?.cid }
        records = remote.toMutableList()
        syncedIndexHash = snap.indexHash ?: ""
        everSynced = true
        writePendingFile()
        publishSnapshot()
        log("info", "[history] head adopted records=${remote.size} previous=${previous.size} requeued=$requeued pending=${pending.entries.size}")
        if (requeued > 0) armTimer()
        return changed
    }

    /** Pull the current head into memory (read-only). True when the committed set changed. */
    private fun syncFromHead(): Boolean {
        if (indexKey == null) return false
        val snap = net.readSnapshot(eoa) ?: return false
        return adoptHead(snap) ?: false
    }

    private fun flushUnlocked(): FlushResult {
        if (!ready || destroyed) return FlushResult.NOT_READY
        if (pending.entries.isEmpty()) return FlushResult.EMPTY
        for (attempt in 0 until HistoryBatch.CAS_ATTEMPTS) {
            when (flushAttempt()) {
                FlushResult.OK -> return FlushResult.OK
                FlushResult.EMPTY -> return FlushResult.EMPTY
                FlushResult.CONFLICT -> {
                    log("info", "[history] head moved by another device; retry ${attempt + 1}/${HistoryBatch.CAS_ATTEMPTS}")
                    if (attempt + 1 < HistoryBatch.CAS_ATTEMPTS) clock.sleep(HistoryBatch.casRetryDelay(random))
                }
                else -> break
            }
        }
        HistoryBatch.flushFailed(pending, clock.now(), random)
        writePendingFile()
        log("warn", "[history] batch write failed pending=${pending.entries.size} failures=${pending.failures}")
        return FlushResult.ERROR
    }

    private fun flushAttempt(): FlushResult {
        val key = indexKey ?: return FlushResult.ERROR
        val masterKey = master ?: return FlushResult.ERROR
        // 1. Snapshot: head + nonce at one block. No snapshot → no write.
        val snap = net.readSnapshot(eoa) ?: return FlushResult.ERROR
        // 2. Adopt that head. Unreadable head → no write.
        adoptHead(snap) ?: return FlushResult.ERROR
        if (pending.entries.isEmpty()) return FlushResult.EMPTY
        // 3. Chain the waiting entries after the committed tail; committed fragments stay as they are.
        val committed = records.sortedBy { it.seq }
        var seq = (committed.lastOrNull()?.seq ?: -1) + 1
        var prevCid = committed.lastOrNull()?.cid ?: genesisCid
        val batch = HistoryBatch.order(pending.entries)
        val fresh = ArrayList<Pair<IndexRecord, String>>()
        for (e in batch) {
            val fragKey = ConetChatCryptoUtil.hkdf(masterKey, "frag|$seq|$prevCid", 32)
            val cipher = ConetChatCryptoUtil.aesGcmEncrypt(fragKey, e.body.toByteArray(Charsets.UTF_8))
            val cid = ConetChatCryptoUtil.keccakUtf8Hex(cipher)
            fresh.add(IndexRecord(seq, cid, prevCid, e.ts, e.peer, e.dir, e.key, e.body.take(80)) to cipher)
            seq += 1
            prevCid = cid
        }
        // 4. Upload fragments, then the index.
        for ((_, cipher) in fresh) {
            if (!net.uploadFragment(eoa, selfSign, cipher)) return FlushResult.ERROR
        }
        val next = committed + fresh.map { it.first }
        val manifest = JSONObject()
            .put("v", 1)
            .put("eoa", eoa)
            .put("updatedAt", clock.now())
            .put("records", encodeRecords(next))
        val indexCipher = ConetChatCryptoUtil.aesGcmEncrypt(key, manifest.toString().toByteArray(Charsets.UTF_8))
        val indexHash = ConetChatCryptoUtil.keccakUtf8Hex(indexCipher)
        if (!net.uploadFragment(eoa, selfSign, indexCipher)) return FlushResult.ERROR
        // 5. Sign with the snapshot nonce; ts / seq stay at their on-chain values (no client clock).
        val signature = try {
            signer.eip712(setPointerTypedData(indexHash, snap.ts, snap.seq, snap.nonce))
        } catch (e: Exception) {
            log("warn", "[history] SetPointer sign failed: ${e.message}")
            return FlushResult.ERROR
        }
        when (net.submitPointer(eoa, indexHash, snap.ts, snap.seq, snap.nonce, signature)) {
            HistoryBatch.SubmitResult.OK -> Unit
            HistoryBatch.SubmitResult.CONFLICT -> return FlushResult.CONFLICT
            HistoryBatch.SubmitResult.ERROR -> return FlushResult.ERROR
        }
        // 6. Landed: the new index is the committed head.
        val bodies = batch.associate { it.key to it.body }
        for ((rec, _) in fresh) {
            plain[rec.cid] = Entry(rec.seq, rec.ts, rec.peer, rec.dir, rec.sendId, bodies[rec.sendId].orEmpty())
            emittedCids.add(rec.cid)
        }
        records = next.toMutableList()
        syncedIndexHash = indexHash
        HistoryBatch.flushSucceeded(pending, batch.mapTo(HashSet()) { it.key }, clock.now(), random)
        writePendingFile()
        publishSnapshot()
        log("info", "[history] batch written entries=${batch.size} records=${next.size} index=${shortCid(indexHash)}")
        return FlushResult.OK
    }

    private fun setPointerTypedData(indexHash: String, ts: String, seq: String, nonce: String): JSONObject {
        val message = JSONObject()
            .put("owner", eoa)
            .put("indexHash", indexHash)
            .put("ts", ts)
            .put("seq", seq)
            .put("nonce", nonce)
        return JSONObject()
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
    }

    // ---- timers -----------------------------------------------------------------------

    /** (Re)arm the write timer for the planned time. Queue thread. */
    private fun armTimer() {
        if (!autoFlush || destroyed) return
        val due = pending.dueAt
        synchronized(timers) {
            flushTimer?.cancel(false)
            flushTimer = null
            if (due == null) return
            val delay = maxOf(0L, due - clock.now())
            flushTimer = try {
                timers.schedule({
                    try {
                        queue.execute {
                            flushUnlocked()
                            armTimer()
                        }
                    } catch (_: Exception) {
                        // destroyed
                    }
                }, delay, TimeUnit.MILLISECONDS)
            } catch (_: Exception) {
                null
            }
        }
    }

    /** While the module runs, look at the head every 60–120 s so other devices' entries show up. */
    private fun schedulePoll() {
        if (!autoFlush || destroyed) return
        val delay = POLL_MIN_MS + (clock.random() * (POLL_MAX_MS - POLL_MIN_MS)).toLong()
        synchronized(timers) {
            pollTimer = try {
                timers.schedule({
                    try {
                        queue.execute {
                            try {
                                val changed = syncFromHead()
                                val emit = lastEmit
                                if (changed && emit != null) publishRecords(null, Int.MAX_VALUE, false, emit)
                            } catch (e: Exception) {
                                log("warn", "[history] head poll failed: ${e.message}")
                            }
                            schedulePoll()
                        }
                    } catch (_: Exception) {
                        // destroyed
                    }
                }, delay, TimeUnit.MILLISECONDS)
            } catch (_: Exception) {
                null
            }
        }
    }

    // ---- pending file -----------------------------------------------------------------

    private fun pendingFile(): File? {
        val dir = storageDir ?: return null
        val tag = ConetChatCryptoUtil.keccakUtf8Hex(eoa).substring(2, 18)
        return File(dir, "history-pending-$tag.bin")
    }

    private fun readPendingFile(): HistoryBatch.PendingState? {
        val file = pendingFile() ?: return null
        val key = pendingKey ?: return null
        if (!file.exists()) return null
        return try {
            val json = String(ConetChatCryptoUtil.aesGcmDecrypt(key, file.readText(Charsets.UTF_8)), Charsets.UTF_8)
            HistoryBatch.PendingState.fromJson(JSONObject(json))
        } catch (e: Exception) {
            log("warn", "[history] pending file unreadable; starting empty")
            null
        }
    }

    /** Atomic replace (temp file + rename) so a kill mid-write keeps the previous queue. */
    private fun writePendingFile() {
        val file = pendingFile() ?: return
        val key = pendingKey ?: return
        try {
            file.parentFile?.mkdirs()
            val cipher = ConetChatCryptoUtil.aesGcmEncrypt(key, pending.toJson().toString().toByteArray(Charsets.UTF_8))
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText(cipher, Charsets.UTF_8)
            if (!tmp.renameTo(file)) {
                file.delete()
                tmp.renameTo(file)
            }
        } catch (e: Exception) {
            log("warn", "[history] pending file write failed: ${e.javaClass.simpleName}")
        }
    }

    // ---- materialize --------------------------------------------------------------------

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
        val cipher = net.fetchFragment(rec.cid) ?: return null
        return try {
            val k = ConetChatCryptoUtil.hkdf(masterKey, "frag|${rec.seq}|${rec.prevCid}", 32)
            val body = String(ConetChatCryptoUtil.aesGcmDecrypt(k, cipher), Charsets.UTF_8)
            Entry(rec.seq, rec.ts, rec.peer, rec.dir, rec.sendId, body).also { plain[rec.cid] = it }
        } catch (e: Exception) {
            log("warn", "[history] record decrypt failed seq=${rec.seq} cid=${shortCid(rec.cid)}")
            null
        }
    }

    // ---- production network + signer -------------------------------------------------------

    private inner class BrokerSigner : HistorySigner {
        override fun eip191(message: String): String =
            awaitSign { BeamioConetChatSignBroker.requestEip191(message, completion = it) }

        override fun eip712(typedData: JSONObject): String =
            awaitSign { BeamioConetChatSignBroker.requestEip712(typedData, completion = it) }
    }

    private inner class DefaultNet : HistoryNet {
        override fun readSnapshot(owner: String): HistorySnapshot? {
            val block = rpc("eth_blockNumber", JSONArray()) ?: run {
                log("warn", "[history] blockNumber failed")
                return null
            }
            val ptr = ethCall(registryAddress, SEL_GET_POINTER + padAddress(owner), block) ?: return null
            val nonceHex = ethCall(registryAddress, SEL_NONCE_OF + padAddress(owner), block) ?: return null
            if (!ptr.startsWith("0x") || ptr.length < 2 + 64 * 3 || nonceHex.length < 66) return null
            val hex = ptr.substring(2)
            val indexHash = "0x" + hex.substring(0, 64)
            fun word(offset: Int): String = java.math.BigInteger(hex.substring(offset, offset + 64), 16).toString()
            return HistorySnapshot(
                indexHash = if (indexHash == "0x" + "0".repeat(64)) null else indexHash,
                ts = word(64),
                seq = word(128),
                nonce = java.math.BigInteger(nonceHex.substring(nonceHex.length - 64), 16).toString(),
            )
        }

        override fun fetchFragment(hash: String): String? {
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

        override fun uploadFragment(owner: String, selfSign: String, cipherB64: String): Boolean {
            val body = JSONObject()
                .put("wallet", owner)
                .put("signMessage", selfSign)
                .put("image", cipherB64)
                .toString()
            val (status, _) = httpPostJson("$ipfsWrite/storageFragment", body, 45_000)
            if (status !in 200..299) log("warn", "[history] storageFragment HTTP $status")
            return status in 200..299
        }

        override fun submitPointer(
            owner: String,
            indexHash: String,
            ts: String,
            seq: String,
            nonce: String,
            signature: String,
        ): HistoryBatch.SubmitResult {
            val body = JSONObject()
                .put("owner", owner)
                .put("indexHash", indexHash)
                .put("ts", ts)
                .put("seq", seq)
                .put("nonce", nonce)
                .put("signature", signature)
                .toString()
            val (status, text) = httpPostJson("$apiBase/setChatIndexPointer", body, 30_000)
            val result = HistoryBatch.classify(status, text)
            if (result != HistoryBatch.SubmitResult.OK) log("warn", "[history] setChatIndexPointer HTTP $status → $result")
            return result
        }

        private fun rpc(method: String, params: JSONArray): String? {
            val payload = JSONObject()
                .put("jsonrpc", "2.0")
                .put("id", 1)
                .put("method", method)
                .put("params", params)
                .toString()
            val (status, text) = httpPostJson(conetRpcUrl, payload, 20_000)
            if (status !in 200..299) return null
            return try {
                JSONObject(text).optString("result", "").takeIf { it.startsWith("0x") }
            } catch (_: Exception) {
                null
            }
        }

        private fun ethCall(to: String, data: String, block: String): String? =
            rpc("eth_call", JSONArray().put(JSONObject().put("to", to).put("data", data)).put(block))
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
        private const val PENDING_KEY_INFO = "pending-enc"
        private const val BACKFILL_BATCH = 20

        /** Concurrent IPFS fetch+decrypt workers for restore / global read. */
        private const val FETCH_PARALLELISM = 6
        private const val MATERIALIZE_TIMEOUT_SEC = 45L

        /** Longest a read waits for an in-flight restore before answering from the current snapshot. */
        private const val READ_RESTORE_WAIT_MS = 20_000L

        /** Head poll while the module runs (other devices' entries). */
        private const val POLL_MIN_MS = 60_000L
        private const val POLL_MAX_MS = 120_000L

        /** `bytes4(keccak256("getPointer(address)"))`. */
        internal const val SEL_GET_POINTER = "0x6bd15a9f"

        /** `bytes4(keccak256("nonceOf(address)"))`. */
        internal const val SEL_NONCE_OF = "0xed2a2d64"
    }
}
