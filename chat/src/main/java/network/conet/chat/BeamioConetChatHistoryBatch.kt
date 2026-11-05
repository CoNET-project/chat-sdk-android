package network.conet.chat

import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.floor
import kotlin.math.max
import kotlin.math.min

/**
 * Batched history writes — the same rules as the TS worker's `history-batch.ts`
 * (design note `history-batch-write-design.md`, 2026-11-04).
 *
 * Entries wait in an encrypted local queue. The on-chain head pointer moves only after
 * 10 entries, or 2 minutes after the first waiting entry (and after the last write),
 * whichever comes first; both triggers carry random delay. No waiting entry → no write.
 */
object HistoryBatch {
    const val MAX_ENTRIES = 10
    const val MIN_INTERVAL_MS = 120_000L
    const val TIME_JITTER_MS = 120_000L
    const val COUNT_DELAY_MIN_MS = 5_000L
    const val COUNT_DELAY_MAX_MS = 45_000L
    const val LAUNCH_DELAY_MIN_MS = 10_000L
    const val LAUNCH_DELAY_MAX_MS = 60_000L
    const val RETRY_BASE_MS = 30_000L
    const val RETRY_MAX_MS = 600_000L
    const val CAS_ATTEMPTS = 3
    const val CAS_DELAY_MIN_MS = 1_000L
    const val CAS_DELAY_MAX_MS = 5_000L
    /** Writes the relay called done but the head never showed: after this many in a row, stop writing this run. */
    const val UNLANDED_PAUSE_AFTER = 3

    data class PendingEntry(
        val key: String,
        val peer: String,
        val dir: String,
        val ts: Long,
        val body: String,
    )

    class PendingState(
        var entries: MutableList<PendingEntry> = ArrayList(),
        /** Local time the queue went from empty to non-empty. */
        var firstPendingAt: Long? = null,
        /** Local time of the last successful chain write (0 = never). */
        var lastFlushAt: Long = 0,
        /** Time-trigger jitter, drawn once per non-empty period. */
        var timeJitterMs: Long? = null,
        /** Planned write time; null when the queue is empty. */
        var dueAt: Long? = null,
        /** Consecutive failed writes (CAS conflicts do not count). */
        var failures: Int = 0,
    ) {
        fun toJson(): JSONObject {
            val arr = JSONArray()
            for (e in entries) {
                arr.put(
                    JSONObject().put("key", e.key).put("peer", e.peer).put("dir", e.dir)
                        .put("ts", e.ts).put("body", e.body),
                )
            }
            return JSONObject()
                .put("v", 1)
                .put("entries", arr)
                .put("firstPendingAt", firstPendingAt ?: JSONObject.NULL)
                .put("lastFlushAt", lastFlushAt)
                .put("timeJitterMs", timeJitterMs ?: JSONObject.NULL)
                .put("dueAt", dueAt ?: JSONObject.NULL)
                .put("failures", failures)
        }

        companion object {
            fun fromJson(o: JSONObject): PendingState? {
                if (o.optInt("v", 0) != 1) return null
                val arr = o.optJSONArray("entries") ?: return null
                val entries = ArrayList<PendingEntry>()
                for (i in 0 until arr.length()) {
                    val e = arr.optJSONObject(i) ?: continue
                    val key = e.optString("key", "")
                    if (key.isEmpty()) continue
                    entries.add(
                        PendingEntry(key, e.optString("peer"), e.optString("dir", "out"), e.optLong("ts"), e.optString("body")),
                    )
                }
                fun optLongOrNull(name: String): Long? = if (o.isNull(name) || !o.has(name)) null else o.optLong(name)
                return PendingState(
                    entries = entries,
                    firstPendingAt = optLongOrNull("firstPendingAt"),
                    lastFlushAt = o.optLong("lastFlushAt", 0),
                    timeJitterMs = optLongOrNull("timeJitterMs"),
                    dueAt = optLongOrNull("dueAt"),
                    failures = o.optInt("failures", 0),
                )
            }
        }
    }

    private fun uniform(random: () -> Double, minMs: Long, maxMs: Long): Long =
        floor(minMs + random() * (maxMs - minMs)).toLong()

    /**
     * Stable record key: the sendId when present, else
     * `"h:" + keccak256(utf8(peer|dir|ts|body)).hex[0..32)` (same formula as TS / iOS).
     */
    fun recordKey(sendId: String?, peer: String, dir: String, ts: Long, body: String): String {
        if (!sendId.isNullOrEmpty()) return sendId
        val digest = ConetChatCryptoUtil.keccakUtf8Hex("${peer.lowercase()}|$dir|$ts|$body")
        return "h:" + digest.substring(2, 34)
    }

    private fun planDueAt(state: PendingState, now: Long, random: () -> Double): Long? {
        if (state.entries.isEmpty()) return null
        val first = state.firstPendingAt ?: now
        var due = max(first, state.lastFlushAt) + MIN_INTERVAL_MS + (state.timeJitterMs ?: 0)
        state.dueAt?.let { due = min(due, it) }
        if (state.entries.size >= MAX_ENTRIES) {
            due = min(due, now + uniform(random, COUNT_DELAY_MIN_MS, COUNT_DELAY_MAX_MS))
        }
        return due
    }

    /** Add one entry. False when the key is already waiting or already committed. */
    fun enqueue(
        state: PendingState,
        entry: PendingEntry,
        now: Long,
        random: () -> Double,
        committed: (String) -> Boolean,
    ): Boolean {
        if (committed(entry.key) || state.entries.any { it.key == entry.key }) return false
        val wasEmpty = state.entries.isEmpty()
        state.entries.add(entry)
        if (wasEmpty) {
            state.firstPendingAt = now
            state.timeJitterMs = uniform(random, 0, TIME_JITTER_MS)
            state.dueAt = null
        }
        if (wasEmpty || state.entries.size == MAX_ENTRIES) state.dueAt = planDueAt(state, now, random)
        return true
    }

    /** After restart: a write that fell due while the app was closed runs 10–60 s after launch. */
    fun resume(state: PendingState, now: Long, random: () -> Double) {
        if (state.entries.isEmpty()) {
            clearSchedule(state)
            return
        }
        if (state.firstPendingAt == null) state.firstPendingAt = now
        if (state.timeJitterMs == null) state.timeJitterMs = uniform(random, 0, TIME_JITTER_MS)
        if (state.dueAt == null) state.dueAt = planDueAt(state, now, random)
        val due = state.dueAt
        if (due != null && due <= now) state.dueAt = now + uniform(random, LAUNCH_DELAY_MIN_MS, LAUNCH_DELAY_MAX_MS)
    }

    private fun clearSchedule(state: PendingState) {
        state.firstPendingAt = null
        state.timeJitterMs = null
        state.dueAt = null
    }

    /** Network / relay failure: exponential backoff with ±50 % spread, capped at 10 minutes. */
    fun flushFailed(state: PendingState, now: Long, random: () -> Double) {
        val shift = min(state.failures, 20)
        val base = min(RETRY_BASE_MS shl shift, RETRY_MAX_MS)
        state.failures += 1
        state.dueAt = if (state.entries.isEmpty()) null else now + floor(base * (0.5 + random())).toLong()
    }

    /** Drop entries whose key is committed. Returns how many were dropped. */
    fun dropCommitted(state: PendingState, committed: (String) -> Boolean): Int {
        val before = state.entries.size
        state.entries = state.entries.filterNot { committed(it.key) }.toMutableList()
        if (state.entries.isEmpty()) clearSchedule(state)
        return before - state.entries.size
    }

    /** A chain write landed: remove the written keys and plan the next window for what is left. */
    fun flushSucceeded(state: PendingState, written: Set<String>, now: Long, random: () -> Double) {
        state.entries = state.entries.filterNot { it.key in written }.toMutableList()
        state.lastFlushAt = now
        state.failures = 0
        clearSchedule(state)
        if (state.entries.isNotEmpty()) {
            state.firstPendingAt = now
            state.timeJitterMs = uniform(random, 0, TIME_JITTER_MS)
            state.dueAt = planDueAt(state, now, random)
        }
    }

    /** Order in which waiting entries are chained after the committed tail. */
    fun order(entries: List<PendingEntry>): List<PendingEntry> =
        entries.sortedWith(compareBy<PendingEntry>({ it.ts }, { it.key }))

    enum class SubmitResult { OK, CONFLICT, ERROR }

    /**
     * Relay / chain answers that mean "someone moved the head first" (CAS lost): beamio.app
     * precheck 400 `Stale pointer nonce` / `Stale ts` / `Stale seq`, Master 409, contract revert
     * `bad nonce` / `stale ts` / `stale seq`.
     */
    fun classify(status: Int, body: String): SubmitResult = when {
        // A Cluster that forwarded a Master failure without its status (2026-11-05) answers 200
        // with `success: false`: that is not a landed write.
        status in 200..299 -> {
            val parsed = try {
                JSONObject(body)
            } catch (_: Exception) {
                null
            }
            if (parsed != null && parsed.has("success") && !parsed.optBoolean("success", true)) {
                if (Regex("nonce|stale|conflict", RegexOption.IGNORE_CASE).containsMatchIn(parsed.optString("error", ""))) {
                    SubmitResult.CONFLICT
                } else {
                    SubmitResult.ERROR
                }
            } else {
                SubmitResult.OK
            }
        }
        status == 409 -> SubmitResult.CONFLICT
        status == 400 && Regex("nonce|stale", RegexOption.IGNORE_CASE).containsMatchIn(body) -> SubmitResult.CONFLICT
        else -> SubmitResult.ERROR
    }

    fun casRetryDelay(random: () -> Double): Long = uniform(random, CAS_DELAY_MIN_MS, CAS_DELAY_MAX_MS)

    /**
     * storageFragment v2 (`storage-fragment-v2-spec.md`): the direct upload sends only `{ image }`.
     * A server that predates v2 answers 403 to an unsigned upload; the caller then retries once with
     * the legacy `{ wallet, signMessage, image }` body and keeps it for the rest of the run.
     * Remove the legacy path once v2 is deployed everywhere.
     */
    sealed class UploadResult {
        object Ok : UploadResult()
        object LegacyRequired : UploadResult()
        data class RateLimited(val retryAfterMs: Long) : UploadResult()
        object Error : UploadResult()
    }

    /** Default wait for a 429 that carries neither `Retry-After` nor `retryAfterSec`. */
    const val UPLOAD_RATE_LIMIT_DEFAULT_MS = 60_000L

    fun classifyUpload(status: Int, body: String, retryAfterHeader: String?, expectedHash: String, legacy: Boolean): UploadResult {
        if (status == 403 && !legacy) return UploadResult.LegacyRequired
        if (status == 429) {
            var seconds = retryAfterHeader?.trim()?.toDoubleOrNull()
            if (seconds == null || seconds <= 0) {
                seconds = try {
                    JSONObject(body).optDouble("retryAfterSec", Double.NaN).takeIf { !it.isNaN() }
                } catch (_: Exception) {
                    null
                }
            }
            val ms = if (seconds != null && seconds > 0) kotlin.math.ceil(seconds * 1000).toLong() else UPLOAD_RATE_LIMIT_DEFAULT_MS
            return UploadResult.RateLimited(ms)
        }
        if (status !in 200..299) return UploadResult.Error
        // v2 answers `{ ok: true, hash }`; an old server's 200 body differs and is accepted as is.
        try {
            val o = JSONObject(body)
            if (o.has("ok") && !o.optBoolean("ok", true)) return UploadResult.Error
            val hash = o.optString("hash", "")
            if (hash.isNotEmpty() && !hash.equals(expectedHash, ignoreCase = true)) return UploadResult.Error
        } catch (_: Exception) {
            // non-JSON 200 from an old server
        }
        return UploadResult.Ok
    }
}

/** Pre-v2 storageFragment credential (wallet + its signature over its own address). */
data class LegacyUploadCredential(val owner: String, val selfSign: String)

/** Head pointer and nonce read at one block. `indexHash` null = the owner never wrote. */
data class HistorySnapshot(val indexHash: String?, val ts: String, val seq: String, val nonce: String)

/** Network side of the history store (RPC, IPFS, relay, signer). Replaced in tests. */
interface HistoryNet {
    /** null = could not read (never treat as "no pointer"). */
    fun readSnapshot(owner: String): HistorySnapshot?
    fun fetchFragment(hash: String): String?
    /** `legacy` null sends the v2 `{ image }` body; set, sends the pre-v2 signed body. */
    fun uploadFragment(cipherB64: String, legacy: LegacyUploadCredential?): HistoryBatch.UploadResult
    fun submitPointer(owner: String, indexHash: String, ts: String, seq: String, nonce: String, signature: String): HistoryBatch.SubmitResult
}

/** Clock and randomness. Replaced in tests. */
interface HistoryClock {
    fun now(): Long
    fun random(): Double
    fun sleep(ms: Long) {
        Thread.sleep(ms)
    }
}

/** EIP-191 / EIP-712 signatures (the PWA signs; tests use a fake). */
interface HistorySigner {
    fun eip191(message: String): String
    fun eip712(typedData: JSONObject): String
}
