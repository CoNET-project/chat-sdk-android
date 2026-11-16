package network.conet.chat

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
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
import network.conet.chat.localread.ApplyResult
import network.conet.chat.localread.IncomingRecord
import network.conet.chat.localread.LocalChatIds
import network.conet.chat.localread.LocalChatEvent
import network.conet.chat.localread.LocalChatStore
import network.conet.chat.localread.AndroidSqlDb
import network.conet.chat.localread.SqlDb
import network.conet.chat.localread.LocalMediaKind
import network.conet.chat.localread.UnlockResult

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
/**
 * The names of this store's files in its storage directory (25.52Y.85 第 3 项 (c), chat history). They are derived from the EOA alone, so the
 * owner of a file is decided by the name: the new account's names are kept, and any other name of these families belongs to another account.
 * Shared by [BeamioConetChatHistoryStore] and the account cleanup, so both use one derivation.
 */
internal object ChatHistoryFileNames {
    const val LOCAL_PREFIX = "chat-local-v1-"
    const val PENDING_PREFIX = "history-pending-"
    val LOCAL_SUFFIXES = listOf(".sqlite", ".sqlite-wal", ".sqlite-shm", ".sqlite-journal")

    /** `accountKey` is `eoa:default` with the EOA lower-case (D5). */
    fun localName(eoa: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest("${eoa.lowercase()}:default".toByteArray(Charsets.UTF_8))
        return LOCAL_PREFIX + LocalChatIds.base64Url(digest).take(22) + ".sqlite"
    }

    fun pendingName(eoa: String): String = PENDING_PREFIX + ConetChatCryptoUtil.keccakUtf8Hex(eoa.lowercase()).substring(2, 18) + ".bin"

    /** The digest part of a local file name (base64url has no dot), for an owner that is not the new account. */
    fun localDigestOf(name: String): String = name.removePrefix(LOCAL_PREFIX).substringBefore('.')

    /** The tag part of a pending file name. */
    fun pendingTagOf(name: String): String = name.removePrefix(PENDING_PREFIX).removeSuffix(".bin")
}

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
    /**
     * Local-DB root R_db (spec v1.1-r1 22.2): derived inside the wallet boundary from the private key.
     * Null when the boundary holds no key: the local store then refuses to open (`db_root_missing`).
     */
    private val dbRootProvider: (() -> ByteArray?)? = null,
    /** Opens the local SQLite handle (null file = in-memory). Android by default; tests inject JDBC. */
    private val sqlDbFactory: (File?) -> SqlDb = { AndroidSqlDb.open(it) },
    /**
     * R559 switch: false means nothing is written. The queue still takes entries locally; no fragment, index or pointer is uploaded or
     * submitted. Production builds take the build value (true), so their behaviour is unchanged.
     */
    private val writesEnabled: Boolean = BuildConfig.HISTORY_WRITES,
    /** Replaces the queue file with its temporary copy. Tests inject a failing replace; production keeps rename. */
    private val replaceFile: (File, File) -> Boolean = { from, to -> from.renameTo(to) },
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

    /**
     * DISABLED: the build switched history writes off (QA switch, R559). Nothing was written; the entries stay in the local queue. It is not
     * EMPTY, which means there was nothing to write.
     */
    enum class FlushResult { OK, EMPTY, CONFLICT, ERROR, NOT_READY, DISABLED }

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
    /** Pre-v2 storageFragment credential, requested only after an old server answered 403. */
    private var selfSign = ""
    /** This run talks to a pre-v2 fragment server. */
    private var legacyUpload = false
    /** A 429 asked us not to upload before this local time. */
    private var uploadNotBefore = 0L
    @Volatile
    private var ready = false
    @Volatile
    private var destroyed = false

    /** Last adopted on-chain index (committed records only). Queue thread only. */
    private var records: MutableList<IndexRecord> = ArrayList()
    private var syncedIndexHash = ""
    private var pending = HistoryBatch.PendingState()
    /** True while the queue file on disk has not been read: nothing is written over it (queue thread only). */
    private var pendingUnreadable = false

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

    /** Nonce signed by the last write the relay called done, until a head read confirms it. Queue thread. */
    private var awaitingLandingNonce: java.math.BigInteger? = null
    /** Writes in a row the relay called done but the head never showed. Queue thread. */
    private var unlandedWrites = 0
    /** Consecutive pointer submits the relay answered without confirming (REJECTED). */
    private var relayRejects = 0
    /** After [HistoryBatch.UNLANDED_PAUSE_AFTER] such writes: no timed writes for the rest of this run. */
    @Volatile
    private var writesPaused = false
    /** The last [adoptHead] found our previous write missing (already backed off). Queue thread. */
    private var unlandedJustNow = false
    private var pollTimer: ScheduledFuture<*>? = null

    /** Bounded parallel IPFS fetch + decrypt for restore / read (TS worker decrypts the tail concurrently). */
    private val fetchPool: ExecutorService = Executors.newFixedThreadPool(FETCH_PARALLELISM) { r ->
        Thread(r, "conet-chat-history-fetch").apply { isDaemon = true }
    }

    /**
     * Encrypted local read store (spec v1.0/v0.2 sections 6–9). Fed by the head sync; reads never
     * touch the network. Null until [prepare] has derived the master key.
     */
    @Volatile
    private var local: LocalChatStore? = null
    private val localIo = Any()
    private val persistPending = java.util.concurrent.atomic.AtomicBoolean(false)

    /** Receives [LocalChatEvent]s of the local store (set by the host before [prepare]). */
    @Volatile
    var onLocalEvent: ((LocalChatEvent) -> Unit)? = null

    /** The local read store, or null when not ready or destroyed. */
    fun localStore(): LocalChatStore? = if (ready && !destroyed) local else null

    fun isReady(): Boolean = ready

    fun destroy() {
        // Spec 6.5 order: generation, UI clear, persist, zeroize, close.
        local?.let {
            it.bumpGeneration()
            onLocalEvent?.invoke(LocalChatEvent.Locked)
            it.lock()
        }
        local = null
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
                val masterBytes = ConetChatCryptoUtil.keccak256(domainSig.toByteArray(Charsets.UTF_8))
                master = masterBytes
                indexKey = ConetChatCryptoUtil.hkdf(masterBytes, "index-enc", 32)
                pendingKey = ConetChatCryptoUtil.hkdf(masterBytes, PENDING_KEY_INFO, 32)
                val genesis = ConetChatCryptoUtil.hkdf(masterBytes, FRAGMENT_GENESIS_INFO, 32)
                genesisCid = "0x" + ConetChatCryptoUtil.toHex(genesis)
                // Restore the queue left by the last run; a write that fell due while closed runs 10–60 s from now.
                // An unreadable queue file fails prepare: the file is kept untouched and nothing is written over it until a later prepare reads it.
                pending = try {
                    readPendingFile() ?: HistoryBatch.PendingState()
                } catch (e: IOException) {
                    pendingUnreadable = true
                    throw e
                }
                pendingUnreadable = false
                HistoryBatch.resume(pending, clock.now(), random)
                writePendingFile()
                publishSnapshot()
                openLocal(masterBytes)
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
        val key = writerSendKey(entry.optString("sendId", ""), peer, dir, ts, body) ?: return false
        val committed = committedKeys()
        // Snapshot first: if the queue file cannot be written the enqueue is taken back, so "not queued" (false) is the truth.
        val before = HistoryBatch.PendingState.fromJson(pending.toJson()) ?: return false
        val added = HistoryBatch.enqueue(
            pending,
            HistoryBatch.PendingEntry(key, peer, dir, ts, body),
            clock.now(),
            random,
        ) { it in committed }
        if (!added) return true
        if (!writePendingFile()) {
            pending = before
            return false
        }
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
        unlandedJustNow = false
        val key = indexKey ?: return null
        val previous = records.toList()
        if (snap.indexHash != null && snap.indexHash == syncedIndexHash && everSynced) {
            // The head is the index we wrote: it landed.
            if (awaitingLandingNonce != null) {
                awaitingLandingNonce = null
                unlandedWrites = 0
            }
            return false
        }
        val remote: List<IndexRecord> = if (snap.indexHash == null) {
            emptyList()
        } else {
            val cipher = fetchVerified(snap.indexHash) ?: run {
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
            val k = rec.sendId.ifEmpty { null } ?: writerSendKey("", entry.peer, entry.dir, entry.ts, entry.body) ?: continue
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
        // Did our last "done" write land? The registry consumes the nonce we signed; if the head
        // still shows that nonce, the relay answered success without writing (2026-11-05).
        val landing = awaitingLandingNonce
        if (landing != null) {
            awaitingLandingNonce = null
            val headNonce = snap.nonce.toBigIntegerOrNull()
            if (headNonce != null && headNonce <= landing) {
                unlandedWrites += 1
                unlandedJustNow = true
                // The relay's "done" reset the failure count: count unlanded writes (30 s, 60 s, ...).
                pending.failures = unlandedWrites - 1
                HistoryBatch.flushFailed(pending, clock.now(), random)
                if (unlandedWrites >= HistoryBatch.UNLANDED_PAUSE_AFTER) writesPaused = true
            } else {
                unlandedWrites = 0
            }
        }
        writePendingFile()
        publishSnapshot()
        log("info", "[history] head adopted records=${remote.size} previous=${previous.size} requeued=$requeued pending=${pending.entries.size}")
        if (unlandedJustNow) {
            log(
                "warn",
                if (writesPaused) {
                    "[history] write did not land ${unlandedWrites}x; timed writes paused until restart pending=${pending.entries.size}"
                } else {
                    "[history] write did not land; backing off failures=${pending.failures} pending=${pending.entries.size}"
                },
            )
        }
        if (requeued > 0 || unlandedJustNow) armTimer()
        return changed
    }

    /** Pull the current head into memory and ingest it into the local store. True when the set changed. */
    private fun syncFromHead(): Boolean {
        if (indexKey == null) return false
        local?.setSyncState("running")
        val snap = net.readSnapshot(eoa)
        if (snap == null) {
            local?.setSyncState("error")
            return false
        }
        val changed = adoptHead(snap)
        if (changed == null) {
            local?.setSyncState("error")
            return false
        }
        // Sync is complete only when every index record is held (spec 9.4): a failed fetch keeps `pending`.
        if (ingestLocal(records.toList())) local?.markSyncComplete()
        local?.setSyncState("idle")
        return changed
    }

    /**
     * Identity written into the index as sendId (spec v1.1 4.2, D10): a non-empty sendId is kept;
     * an empty one gets the deterministic sendKey, not a random id. Needs the master key (after prepare).
     */
    private fun writerSendKey(sendId: String, peer: String, dir: String, ts: Long, body: String): String? {
        if (sendId.isNotEmpty()) return sendId
        // K_id comes from the local-DB root (spec v1.1-r1); without a wallet root no sendKey can be derived.
        val kId = kIdDb ?: return null
        return LocalChatIds.sendKeyDerived(kId, peer.lowercase(), dir, ts, body)
    }

    /** K_id from the local-DB root, set when the local store opens (null while no root is held). */
    @Volatile
    private var kIdDb: ByteArray? = null

    /** Spec 9.2: held records are skipped (no download, no decrypt); the rest are fetched once and stored sealed. */
    private fun ingestLocal(remote: List<IndexRecord>): Boolean {
        val s = local ?: return false
        if (!s.isUnlocked) return false
        var stored = 0
        var known = 0
        var failed = 0
        for (rec in remote) {
            val sid = rec.sendId.ifEmpty { null }
            if (s.knowsRemote(rec.peer, sid, rec.cid)) {
                known++
                continue
            }
            val entry = materialize(rec)
            if (entry == null) {
                failed++
                continue
            }
            // Kind, media fields and failure come from the body parser inside the store (spec r2 21.2).
            val r = s.applyRecord(
                rec.peer,
                IncomingRecord(
                    dir = entry.dir,
                    sortTs = entry.ts,
                    kind = LocalMediaKind.TEXT,
                    sendId = sid,
                    body = entry.body,
                    cid = rec.cid,
                ),
            )
            if (r == ApplyResult.INSERTED || r == ApplyResult.UPDATED) stored++
        }
        if (s.migration != "complete") s.markMigrationComplete()
        log("info", "[history] local ingest records=${remote.size} stored=$stored known=$known failed=$failed")
        return failed == 0
    }

    // ---- local store: open, persist ----------------------------------------------------

    /** SQLite file of this account (spec r3a 7.1). The device-key name (D18) is pending; SHA-256 stands in for now. */
    private fun localFile(): File? {
        val dir = storageDir ?: return null
        return File(dir, ChatHistoryFileNames.localName(eoa))
    }

    /** accountKey = eoa + ":" + workspace; iOS and Android use the workspace `default` (spec D5). */
    private fun localAccountKey(): String = "$eoa:default"

    /** Opens the local database and unlocks the store. No root = locked (db_root_missing). */
    private fun openLocal(master: ByteArray) {
        val dbRoot = dbRootProvider?.invoke()
        kIdDb = dbRoot?.let { LocalChatIds.idKeyFromRootDb(it) }
        if (dbRoot == null) {
            // No key, no file: the store is locked on an in-memory handle, so nothing is written to disk.
            val locked = LocalChatStore(localAccountKey(), sqlDbFactory(null))
            local = locked
            locked.markLocked("db_root_missing")
            log("warn", "[history] local store locked: db_root_missing")
            return
        }
        val s = LocalChatStore(localAccountKey(), sqlDbFactory(localFile()))
        local = s
        val r = s.unlock(master, dbRoot)
        if (r == UnlockResult.OK || r == UnlockResult.REBUILT_KCV_MISMATCH) {
            s.subscribe { ev -> onLocalEvent?.invoke(ev) }
        }
        // Codes only: no record counts, keys or content in the log.
        log(if (r.opened) "info" else "warn", "[history] local store unlock=$r")
    }

    /** Runs a full head sync on the write queue (spec 9.1: the only writer). [done] gets true once it ran. */
    fun startFullSync(done: (Boolean) -> Unit) {
        queue.execute {
            val ok = try {
                syncFromHead()
                true
            } catch (e: Exception) {
                log("warn", "[history] full sync failed: ${e.javaClass.simpleName}")
                false
            }
            done(ok)
        }
    }

    /**
     * Global read of the held corpus plus entries still waiting to be written. Answers from the
     * local store only: it never waits for a sync or the network (spec 9.1, T-15, T-16).
     */
    fun read(options: JSONObject?, completion: (List<Entry>) -> Unit) {
        readQueue.execute {
            try {
                if (!ready) {
                    completion(emptyList())
                    return@execute
                }
                val peer = options?.optString("peer", "")?.lowercase()?.takeIf { it.isNotEmpty() }
                val query = options?.optString("query", "")?.trim().orEmpty()
                val limit = options?.optInt("limit", 0) ?: 0
                val terms = query.lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
                fun matches(body: String): Boolean {
                    if (terms.isEmpty()) return true
                    val text = body.lowercase()
                    return terms.all { text.contains(it) }
                }
                val s = local
                val held = if (s != null && s.isUnlocked) s.snapshotEntries(peer) else emptyList()
                val entries = ArrayList<Entry>()
                var seq = 0
                for (h in held) {
                    if (!matches(h.body)) continue
                    entries.add(Entry(seq++, h.sortTs, h.convKey, h.dir, h.sendId ?: "", h.body))
                }
                var provisionalSeq = seq
                for (w in HistoryBatch.order(pendingSnapshot)) {
                    if (peer != null && w.peer != peer) continue
                    if (!matches(w.body)) continue
                    entries.add(Entry(provisionalSeq++, w.ts, w.peer, w.dir, w.key, w.body))
                }
                entries.sortWith(compareBy<Entry>({ it.ts }, { it.seq }))
                completion(if (limit > 0 && entries.size > limit) entries.takeLast(limit) else entries)
            } catch (e: Exception) {
                log("warn", "[history] read failed: ${e.javaClass.simpleName}")
                completion(emptyList())
            }
        }
    }

    private fun flushUnlocked(): FlushResult {
        if (!writesEnabled) return FlushResult.DISABLED
        if (!ready || destroyed) return FlushResult.NOT_READY
        if (pending.entries.isEmpty()) return FlushResult.EMPTY
        for (attempt in 0 until HistoryBatch.CAS_ATTEMPTS) {
            val outcome = flushAttempt()
            // The previous write never landed: adoptHead already backed off; do not write now.
            if (unlandedJustNow) return FlushResult.ERROR
            when (outcome) {
                FlushResult.OK -> return FlushResult.OK
                FlushResult.EMPTY -> return FlushResult.EMPTY
                FlushResult.DISABLED -> return FlushResult.DISABLED
                FlushResult.CONFLICT -> {
                    log("info", "[history] head moved by another device; retry ${attempt + 1}/${HistoryBatch.CAS_ATTEMPTS}")
                    if (attempt + 1 < HistoryBatch.CAS_ATTEMPTS) clock.sleep(HistoryBatch.casRetryDelay(random))
                }
                else -> break
            }
        }
        HistoryBatch.flushFailed(pending, clock.now(), random)
        pending.dueAt?.let { if (uploadNotBefore > it) pending.dueAt = uploadNotBefore }
        writePendingFile()
        log("warn", "[history] batch write failed pending=${pending.entries.size} failures=${pending.failures}")
        return FlushResult.ERROR
    }

    private fun flushAttempt(): FlushResult {
        if (!writesEnabled) return FlushResult.DISABLED
        unlandedJustNow = false
        val key = indexKey ?: return FlushResult.ERROR
        val masterKey = master ?: return FlushResult.ERROR
        // 1. Snapshot: head + nonce at one block. No snapshot → no write.
        val snap = net.readSnapshot(eoa) ?: return FlushResult.ERROR
        // 2. Adopt that head. Unreadable head → no write. Our last write missing → no write (backed off).
        adoptHead(snap) ?: return FlushResult.ERROR
        if (unlandedJustNow) return FlushResult.ERROR
        if (pending.entries.isEmpty()) return FlushResult.EMPTY
        // 3. Chain the waiting entries after the committed tail; committed fragments stay as they are.
        val committed = records.sortedBy { it.seq }
        var seq = (committed.lastOrNull()?.seq ?: -1) + 1
        var prevCid = committed.lastOrNull()?.cid ?: genesisCid
        val batch = HistoryBatch.order(pending.entries)
        val fresh = ArrayList<Pair<IndexRecord, String>>()
        for (e in batch) {
            val cipher = encryptFragment(masterKey, seq, prevCid, e.body)
            val cid = ConetChatCryptoUtil.keccakUtf8Hex(cipher)
            fresh.add(IndexRecord(seq, cid, prevCid, e.ts, e.peer, e.dir, e.key, e.body.take(80)) to cipher)
            seq += 1
            prevCid = cid
        }
        // 4. Upload fragments, then the index.
        for ((_, cipher) in fresh) {
            if (!uploadOne(cipher)) return FlushResult.ERROR
        }
        val next = committed + fresh.map { it.first }
        val manifest = JSONObject()
            .put("v", 1)
            .put("eoa", eoa)
            .put("updatedAt", clock.now())
            .put("records", encodeRecords(next))
        val indexCipher = ConetChatCryptoUtil.aesGcmEncrypt(key, manifest.toString().toByteArray(Charsets.UTF_8))
        val indexHash = ConetChatCryptoUtil.keccakUtf8Hex(indexCipher)
        if (!uploadOne(indexCipher)) return FlushResult.ERROR
        // 5. Sign with the snapshot nonce; ts / seq stay at their on-chain values (no client clock).
        val signature = try {
            signer.eip712(setPointerTypedData(indexHash, snap.ts, snap.seq, snap.nonce))
        } catch (e: Exception) {
            log("warn", "[history] SetPointer sign failed: ${e.message}")
            return FlushResult.ERROR
        }
        when (net.submitPointer(eoa, indexHash, snap.ts, snap.seq, snap.nonce, signature)) {
            HistoryBatch.SubmitResult.OK -> relayRejects = 0
            HistoryBatch.SubmitResult.CONFLICT -> return FlushResult.CONFLICT
            HistoryBatch.SubmitResult.REJECTED -> {
                // The relay said no (e.g. 200 with success:false while it has no gas). Retrying
                // only re-signs the same refusal: after 3 in a row stop timed writes for this run.
                relayRejects += 1
                if (relayRejects >= HistoryBatch.UNLANDED_PAUSE_AFTER) {
                    writesPaused = true
                    log("warn", "[history] relay rejected the pointer ${relayRejects}x; timed writes paused until restart pending=${pending.entries.size}")
                }
                return FlushResult.ERROR
            }
            HistoryBatch.SubmitResult.ERROR -> return FlushResult.ERROR
        }
        // 6. Landed: the new index is the committed head.
        val bodies = batch.associate { it.key to it.body }
        for ((rec, _) in fresh) {
            plain[rec.cid] = Entry(rec.seq, rec.ts, rec.peer, rec.dir, rec.sendId, bodies[rec.sendId].orEmpty())
            emittedCids.add(rec.cid)
        }
        records = next.toMutableList()
        // Our own committed entries are already in the plaintext cache: ingest them without a download.
        ingestLocal(records.toList())
        syncedIndexHash = indexHash
        awaitingLandingNonce = snap.nonce.toBigIntegerOrNull()
        HistoryBatch.flushSucceeded(pending, batch.mapTo(HashSet()) { it.key }, clock.now(), random)
        writePendingFile()
        publishSnapshot()
        log("info", "[history] batch written entries=${batch.size} records=${next.size} index=${shortCid(indexHash)}")
        return FlushResult.OK
    }

    /**
     * Upload one fragment with the v2 body (no wallet, no signature). A pre-v2 server answers 403:
     * retry once with the legacy body and stay on it for this run; only then is the PWA asked for
     * the self-address signature (spec §4; remove after v2 ships).
     */
    private fun uploadOne(cipher: String): Boolean {
        if (!legacyUpload) {
            when (val r = net.uploadFragment(cipher, null)) {
                HistoryBatch.UploadResult.Ok -> return true
                is HistoryBatch.UploadResult.RateLimited -> {
                    uploadNotBefore = clock.now() + r.retryAfterMs
                    return false
                }
                HistoryBatch.UploadResult.Error -> return false
                HistoryBatch.UploadResult.LegacyRequired -> {
                    legacyUpload = true
                    log("info", "[history] fragment server is pre-v2; using the signed upload for this run")
                }
            }
        }
        if (selfSign.isEmpty()) {
            selfSign = try {
                signer.eip191(eoa)
            } catch (e: Exception) {
                log("warn", "[history] storageFragment sign failed: ${e.message}")
                return false
            }
        }
        val r = net.uploadFragment(cipher, LegacyUploadCredential(eoa, selfSign))
        if (r is HistoryBatch.UploadResult.RateLimited) uploadNotBefore = clock.now() + r.retryAfterMs
        return r == HistoryBatch.UploadResult.Ok
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

    /**
     * What the write timer runs (queue thread). A timer armed with delay 0 behind a stuck queue
     * can fire after an earlier task already wrote or failed and planned a later time (Samsung
     * qa4, 2026-11-05: 4 failed writes in 13 ms). Write only when the planned time has come.
     * While writes are paused no timer is armed, so this writes nothing.
     */
    private fun onWriteTimer() {
        if (writesPaused || destroyed) return
        val planned = pending.dueAt
        if (planned != null && planned <= clock.now()) flushUnlocked()
    }

    /** Tests: run one write-timer tick exactly as the armed timer would (respects the pause). */
    internal fun runTimerTickBlocking(timeoutMs: Long = 120_000) {
        val latch = CountDownLatch(1)
        queue.execute {
            try {
                onWriteTimer()
            } finally {
                latch.countDown()
            }
        }
        latch.await(timeoutMs, TimeUnit.MILLISECONDS)
    }

    /** (Re)arm the write timer for the planned time. Queue thread. */
    private fun armTimer() {
        if (!autoFlush || destroyed || writesPaused) return
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
                            onWriteTimer()
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
        return File(dir, ChatHistoryFileNames.pendingName(eoa))
    }

    /**
     * Null only when there is no pending file. A file that exists but cannot be
     * decrypted, parsed or recognised throws [IOException]: the queue is unknown,
     * not empty, and the caller must not write over it.
     */
    private fun readPendingFile(): HistoryBatch.PendingState? {
        val file = pendingFile() ?: return null
        val key = pendingKey ?: return null
        if (!file.exists()) return null
        val state = try {
            val json = String(ConetChatCryptoUtil.aesGcmDecrypt(key, file.readText(Charsets.UTF_8)), Charsets.UTF_8)
            HistoryBatch.PendingState.fromJson(JSONObject(json))
        } catch (e: Exception) {
            throw IOException("pending queue unreadable", e)
        }
        return state ?: throw IOException("pending queue has an unknown format")
    }

    /**
     * Atomic replace (temp file + rename). The previous queue file is never deleted
     * first: when the rename fails it is kept, and the next write retries with the
     * whole in-memory queue. Refused while the file on disk has not been read.
     * Returns false when the queue is not durable. A memory-only store (no storage directory) returns true by design.
     */
    private fun writePendingFile(): Boolean {
        if (pendingUnreadable) {
            log("warn", "[history] pending file not read; not overwriting it")
            return false
        }
        val file = pendingFile() ?: return true
        val key = pendingKey ?: return false
        return try {
            file.parentFile?.mkdirs()
            val cipher = ConetChatCryptoUtil.aesGcmEncrypt(key, pending.toJson().toString().toByteArray(Charsets.UTF_8))
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText(cipher, Charsets.UTF_8)
            if (!replaceFile(tmp, file)) throw IOException("pending queue replace failed; previous file kept")
            true
        } catch (e: Exception) {
            log("warn", "[history] pending file write failed: ${e.javaClass.simpleName}")
            false
        }
    }

    // ---- materialize --------------------------------------------------------------------

    /**
     * Fetch a fragment and check `keccak256(utf8(content)) == hash`. AES-GCM only proves the owner
     * encrypted it, not that it is this version: an older index served under the head's hash
     * would otherwise make the next write drop the entries after it.
     */
    private fun fetchVerified(hash: String): String? {
        val text = net.fetchFragment(hash) ?: return null
        if (!ConetChatCryptoUtil.keccakUtf8Hex(text).equals(hash, ignoreCase = true)) {
            log("warn", "[history] fragment content does not match its hash cid=${shortCid(hash)}")
            return null
        }
        return text
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
        local?.takeIf { it.isUnlocked }?.bodyForRemote(rec.peer, rec.sendId.ifEmpty { null }, rec.cid)?.let { body ->
            return Entry(rec.seq, rec.ts, rec.peer, rec.dir, rec.sendId, body).also { plain[rec.cid] = it }
        }
        val masterKey = master ?: return null
        val cipher = fetchVerified(rec.cid) ?: return null
        return try {
            val body = decryptFragment(masterKey, rec.seq, rec.prevCid, cipher)
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

        override fun uploadFragment(cipherB64: String, legacy: LegacyUploadCredential?): HistoryBatch.UploadResult {
            // v2: { image } only; the server recomputes keccak256(utf8(image)) as the name.
            val body = JSONObject().put("image", cipherB64)
            if (legacy != null) body.put("wallet", legacy.owner).put("signMessage", legacy.selfSign)
            var retryAfter: String? = null
            val (status, text) = httpPostJson("$ipfsWrite/storageFragment", body.toString(), 45_000) { conn ->
                retryAfter = conn.getHeaderField("Retry-After")
            }
            val result = HistoryBatch.classifyUpload(
                status, text, retryAfter, ConetChatCryptoUtil.keccakUtf8Hex(cipherB64), legacy != null,
            )
            if (result != HistoryBatch.UploadResult.Ok) log("warn", "[history] storageFragment HTTP $status → ${result.javaClass.simpleName}")
            return result
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

    private fun httpPostJson(
        url: String,
        body: String,
        timeoutMs: Int,
        onResponse: ((HttpURLConnection) -> Unit)? = null,
    ): Pair<Int, String> {
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
            onResponse?.invoke(conn)
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

        /** Encrypts one fragment body with its key (§25.43.5); returns the base64 cipher that is uploaded. The write path uses only this. */
        internal fun encryptFragment(master: ByteArray, seq: Int, prevCid: String, body: String): String =
            ConetChatCryptoUtil.aesGcmEncrypt(ConetChatCryptoUtil.fragmentKey(master, seq, prevCid), body.toByteArray(Charsets.UTF_8))

        /** Decrypts one fragment cipher (base64) with its key. The read path uses only this. */
        internal fun decryptFragment(master: ByteArray, seq: Int, prevCid: String, cipherB64: String): String =
            String(ConetChatCryptoUtil.aesGcmDecrypt(ConetChatCryptoUtil.fragmentKey(master, seq, prevCid), cipherB64), Charsets.UTF_8)
        private const val BACKFILL_BATCH = 20

        /** Concurrent IPFS fetch+decrypt workers for restore / global read. */
        private const val FETCH_PARALLELISM = 6
        private const val MATERIALIZE_TIMEOUT_SEC = 45L

        /** Longest a read waits for an in-flight restore before answering from the current snapshot. */

        /** Head poll while the module runs (other devices' entries). */
        private const val POLL_MIN_MS = 60_000L
        private const val POLL_MAX_MS = 120_000L

        /** `bytes4(keccak256("getPointer(address)"))`. */
        internal const val SEL_GET_POINTER = "0x6bd15a9f"

        /** `bytes4(keccak256("nonceOf(address)"))`. */
        internal const val SEL_NONCE_OF = "0xed2a2d64"
    }
}
