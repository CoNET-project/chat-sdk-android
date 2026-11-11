package network.conet.chat.localread

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.TreeMap
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Local chat read store, interface spec v1.0 sections 5–10 (Android logical model).
 *
 * - One store per account. Only ciphertext for bodies and media metadata; the DEK is
 *   `HKDF(master, "chat-local-db-v1|"+accountKey)` and never leaves memory (spec D1).
 * - Ordering and cursors use `(sortTs, stableId)` only (spec 3, 5).
 * - Read paths (`openConversation`, `loadOlder`) never touch the network and never wait
 *   for a sync (spec 9.1). This class has no network dependency at all.
 * - Persistence is a single encrypted snapshot ([snapshot] / [unlock]); the caller writes
 *   the bytes atomically. A SQLite-backed variant would implement the same rules.
 *
 * Not thread-safe beyond `synchronized(lock)`; all public methods take the lock.
 */
class LocalChatStore(
    val accountKey: String,
    /** Body parser (spec r2 21.2). Null = the host did not set one: media-like bodies become failed `media_parser_missing`. */
    private val mediaParser: ((ByteArray) -> ParsedBody)? = MediaManifestParser::parse,
) {
    private val lock = Any()
    private val rng = SecureRandom()

    private var dek: ByteArray? = null
    private var idKey: ByteArray? = null
    private var idxKey: ByteArray? = null
    /** Bumped on every lock(); results of an older generation must be dropped by the host (spec 6.5). */
    @Volatile
    var generation: Long = 0L
        private set
    /** Why the store is locked, when unlock refused (spec 6.6 codes). Null when unlocked or never tried. */
    @Volatile
    var lastError: String? = null
        private set
    private var syncComplete = false
    /** Conversations whose last page ended at a pending cursor (spec 6.4). */
    private val pendingOlder = HashSet<String>()
    /** conv|digest -> survivor stable id; conv|stable id -> digest (spec 4.5). */
    private val digestIndex = HashMap<String, String>()
    private val digestOf = HashMap<String, String>()
    /** conv|alias stable id (folded sendKey) -> survivor stable id (spec 4.5 alias table). */
    private val aliases = HashMap<String, String>()
    private var kcv: ByteArray? = null
    private var epoch: String = newEpoch()
    private var headIndexHash: String? = null

    private val rows = TreeMap<RowKey, StoredRow>(rowComparator)
    private val byStable = HashMap<String, RowKey>()
    private val layouts = HashMap<LayoutKey, LayoutValue>()
    private val failedMedia = HashSet<String>()
    /** cid -> row, for records whose stable id is content-derived (spec 9.2 step 2). */
    private val byCid = HashMap<String, RowKey>()
    private var migrationState = "none"
    /** Set by the sync layer: "idle" | "running" | "paused" | "error" (spec 6.1). */
    @Volatile
    var syncState: String = "idle"
        private set
    private val windows = HashMap<String, Window>()
    private val listeners = ArrayList<(LocalChatEvent) -> Unit>()

    /** Count of sync records whose sortTs differed from the stored one (spec 5, counted only). */
    var tsMismatchCount: Int = 0
        private set

    val isUnlocked: Boolean get() = synchronized(lock) { dek != null }

    // ---- lock / unlock / persistence --------------------------------------------------

    /**
     * Derive the DEK and open the store. [snapshot] is the bytes of the last [snapshot] call,
     * or null for a new account. Follows spec 7.3 (kcv mismatch) and 7.5 (schema).
     */
    /**
     * Test convenience only: derives the local root from [master] as if it were the private key.
     * Production code must call [unlock] with the wallet-boundary root (spec v1.1-r1 22.6).
     */
    fun unlock(master: ByteArray, snapshot: ByteArray?): UnlockResult {
        val eoa = accountKey.substringBeforeLast(':')
        val ws = accountKey.substringAfterLast(':')
        return unlock(master, LocalChatIds.rootDbFromPrivateKey(master, eoa, ws), snapshot)
    }

    /**
     * Unlock with the protocol root [master] (K_id, sendKeys) and the local-DB root [dbRoot] (R_db:
     * DEK, kcv, K_idx). spec v1.1-r1 section 22.2.
     */
    fun unlock(master: ByteArray, dbRoot: ByteArray, snapshot: ByteArray?): UnlockResult {
        val r = unlockInner(master, dbRoot, snapshot)
        lastError = when (r) {
            UnlockResult.OK, UnlockResult.REBUILT_KCV_MISMATCH -> null
            UnlockResult.LOCKED_KCV_MISMATCH_PENDING -> "kcv_mismatch"
            UnlockResult.LOCKED_SCHEMA_NEWER -> "schema_newer"
            UnlockResult.SNAPSHOT_CORRUPT -> "snapshot_corrupt"
        }
        return r
    }

    /** Refuse to open with an error code, e.g. `db_root_missing` when the wallet boundary holds no key. */
    fun markLocked(error: String) {
        synchronized(lock) {
            lockMemory()
            lastError = error
        }
    }

    private fun unlockInner(master: ByteArray, dbRoot: ByteArray, snapshot: ByteArray?): UnlockResult {
        return synchronized(lock) {
        val key = LocalChatIds.dekFromRootDb(dbRoot, accountKey.substringBeforeLast(':'), accountKey.substringAfterLast(':'))
        val mac = hmac(key, "kcv".toByteArray(Charsets.UTF_8))
        if (snapshot == null) {
            resetMemory()
            dek = key
            idKey = LocalChatIds.idKeyFromRootDb(dbRoot)
            idxKey = LocalChatIds.idxKeyFromRootDb(dbRoot)
            kcv = mac
            return UnlockResult.OK
        }
        val split = snapshot.indexOf('\n'.code.toByte())
        if (split <= 0) return UnlockResult.SNAPSHOT_CORRUPT
        val header = try {
            JSONObject(String(snapshot, 0, split, Charsets.UTF_8))
        } catch (e: Exception) {
            return UnlockResult.SNAPSHOT_CORRUPT
        }
        if (header.optString("fmt") != FORMAT_TAG) return UnlockResult.SNAPSHOT_CORRUPT
        if (header.optInt("schema", -1) > SCHEMA_VERSION) return UnlockResult.LOCKED_SCHEMA_NEWER
        val storedKcv = ConetChatCryptoUtil.hexToBytes(header.optString("kcv")) ?: return UnlockResult.SNAPSHOT_CORRUPT
        if (!MessageDigest.isEqual(storedKcv, mac)) {
            if (header.optInt("pending", 0) > 0) return UnlockResult.LOCKED_KCV_MISMATCH_PENDING
            // Spec 7.3: nothing waiting to publish, so rebuild under a new epoch.
            resetMemory()
            dek = key
            idKey = LocalChatIds.idKeyFromRootDb(dbRoot)
            idxKey = LocalChatIds.idxKeyFromRootDb(dbRoot)
            kcv = mac
            return UnlockResult.REBUILT_KCV_MISMATCH
        }
        val plain = try {
            open(key, snapshotAad(mac), snapshot.copyOfRange(split + 1, snapshot.size))
        } catch (e: Exception) {
            return UnlockResult.SNAPSHOT_CORRUPT
        }
        resetMemory()
        dek = key
        idKey = LocalChatIds.idKeyFromRootDb(dbRoot)
        idxKey = LocalChatIds.idxKeyFromRootDb(dbRoot)
        kcv = mac
        if (!loadPayload(JSONObject(String(plain, Charsets.UTF_8)))) {
            lockMemory()
            return UnlockResult.SNAPSHOT_CORRUPT
        }
        UnlockResult.OK
        }
    }

    /** Encrypted snapshot of the whole store; the caller persists it atomically. Requires unlock. */
    fun snapshot(): ByteArray = synchronized(lock) {
        val k = requireKey()
        val m = kcv ?: throw IllegalStateException("locked")
        val payload = JSONObject().put("epoch", epoch).put("headIndexHash", headIndexHash ?: JSONObject.NULL)
        val rowArr = JSONArray()
        for (r in rows.values) rowArr.put(r.toJson())
        payload.put("rows", rowArr)
        val layArr = JSONArray()
        for ((k2, v) in layouts) layArr.put(JSONObject()
            .put("c", k2.convKey).put("s", k2.stableId).put("w", k2.widthBucket)
            .put("o", k2.orientation).put("f", k2.fontBucket).put("v", k2.layoutVersion)
            .put("wp", v.wPt).put("hp", v.hPt).put("u", v.updatedMs))
        payload.put("layouts", layArr)
        payload.put("migration", migrationState)
        payload.put("syncComplete", syncComplete)
        val dg = JSONArray()
        for ((k3, v3) in digestOf) dg.put(JSONObject().put("k", k3).put("v", v3))
        payload.put("digests", dg)
        val al = JSONArray()
        for ((k4, v4) in aliases) al.put(JSONObject().put("k", k4).put("v", v4))
        payload.put("aliases", al)
        val blob = seal(k, snapshotAad(m), payload.toString().toByteArray(Charsets.UTF_8))
        val header = JSONObject()
            .put("fmt", FORMAT_TAG)
            .put("schema", SCHEMA_VERSION)
            .put("kcv", ConetChatCryptoUtil.toHex(m))
            .put("pending", rows.values.count { it.pendingPublish && !it.deleted })
        header.toString().toByteArray(Charsets.UTF_8) + byteArrayOf('\n'.code.toByte()) + blob
    }

    /** Logout (spec D2): drop DEK, identity key and every decrypted or in-memory structure. */
    fun lock() = synchronized(lock) {
        generation++
        lockMemory()
    }

    /** Step 1 of spec 6.5 only: results from before this point are stale from now on. */
    fun bumpGeneration(): Long = synchronized(lock) {
        generation++
        generation
    }

    // ---- sync write path (called by the single sync writer) ---------------------------

    /**
     * Apply one source record (spec 5 and 9.2 rules). The caller has already downloaded and
     * decrypted the body when [IncomingRecord.body] is needed.
     */
    fun applyRecord(convKey: String, rec: IncomingRecord, pendingPublish: Boolean = false): ApplyResult {
        return synchronized(lock) {
        val k = requireKey()
        // The stable id is known from the source's hint, else from the sendKey (which needs a body if derived).
        val sk = rec.sendKeyHint
            ?: if (rec.stableIdHint == null) {
                LocalChatIds.sendKey(requireIdKey(), convKey, rec.sendId, rec.dir, rec.sortTs, rec.body)
                    ?: return ApplyResult.REJECTED
            } else {
                null
            }
        val derivedSid = rec.stableIdHint ?: LocalChatIds.stableIdOf(requireIdxKey(), sk!!)
        // A folded sendKey resolves to its survivor (spec 4.5): updates and tombstones follow the alias.
        val sid = aliases[indexKey(convKey, derivedSid)] ?: derivedSid
        val existingKey = byStable[indexKey(convKey, sid)]
        val existing = existingKey?.let { rows[it] }
        if (existing == null) {
            if (rec.deleted) {
                insertRow(convKey, sid, rec, null, pendingPublish, deleted = true).sendKey = sk
                return ApplyResult.TOMBSTONED
            }
            val body = rec.body ?: return ApplyResult.REJECTED
            val digest = LocalChatIds.contentDigest(convKey, rec.dir, rec.sortTs, body)
            val survivor = digestIndex[indexKey(convKey, digest)]
            if (survivor != null && survivor != sid) {
                // Same (peer, dir, ts, body digest) under another sendKey: fold it to the earliest (spec 4.5).
                aliases[indexKey(convKey, derivedSid)] = survivor
                return ApplyResult.COLLAPSED
            }
            val row = insertRow(convKey, sid, rec, body, pendingPublish, deleted = false)
            row.sendKey = sk
            digestIndex[indexKey(convKey, digest)] = sid
            digestOf[indexKey(convKey, sid)] = digest
            emitInserted(row, k)
            if (pendingOlder.remove(convKey)) emit(LocalChatEvent.OlderAvailable(convKey))
            return ApplyResult.INSERTED
        }
        if (rec.deleted) {
            if (existing.deleted) return ApplyResult.SKIPPED
            tombstone(existing)
            emit(LocalChatEvent.Deleted(convKey, sid))
            return ApplyResult.TOMBSTONED
        }
        if (existing.deleted) return ApplyResult.SKIPPED
        if (rec.sortTs != existing.sortTs) tsMismatchCount++
        if (rec.revision > existing.revision) {
            val body = rec.body ?: return ApplyResult.REJECTED
            existing.bodyEnc = seal(k, bodyAad(convKey, sid, rec.revision), body.toByteArray(Charsets.UTF_8))
            existing.revision = rec.revision
            moveCid(existing, rec.cid ?: existing.cid)
            val parsedU = parseBody(body)
            existing.kind = parsedU.kind
            setMedia(existing, parsedU)
            removeLayouts(convKey, sid)
            emit(LocalChatEvent.Updated(convKey, sid, rec.revision))
            return ApplyResult.UPDATED
        }
        if (rec.revision == existing.revision && rec.cid != null && rec.cid != existing.cid) {
            moveCid(existing, rec.cid)
            return ApplyResult.CID_ONLY
        }
        ApplyResult.SKIPPED
        }
    }

    // ---- read path (never touches the network, never waits for sync) -----------------

    /** First screen: newest rows up to one viewport (spec v1.1 6.2). Nothing is read ahead. */
    fun openConversation(convKey: String, vp: LocalViewport): LocalPage {
        return synchronized(lock) {
            if (dek == null) return LocalPage(emptyList(), null, false, LocalSource.LOCKED, lastError ?: "locked", generation = generation)
            sweepLayouts(vp.layoutVersion)
            val page = readPage(convKey, null, vp, first = true)
            windowViewports[convKey] = vp
            windows[convKey] = Window(oldest = lastScanLo, newest = lastScanHi, opened = true)
            page
        }
    }

    /** Older page strictly before [cursor]; scans up to the budget of raw rows (spec v1.1 6.3). */
    fun loadOlder(convKey: String, cursor: String, vp: LocalViewport): LocalPage {
        return synchronized(lock) {
            if (dek == null) return LocalPage(emptyList(), null, false, LocalSource.LOCKED, lastError ?: "locked", generation = generation)
            val before = decodeCursor(cursor, convKey)
                ?: return LocalPage(emptyList(), null, false, LocalSource.LOCKED, "cursor_invalid", generation = generation)
            val page = readPage(convKey, before, vp, first = false)
            windowViewports[convKey] = vp
            val w = windows[convKey]
            if (w != null && lastScanLo != null) windows[convKey] = w.copy(oldest = lastScanLo)
            page
        }
    }

    /** The full head sync has covered every index record (spec 9.4): `end` is now possible. */
    fun markSyncComplete() {
        synchronized(lock) {
            requireKey()
            syncComplete = true
            for (conv in pendingOlder.toList()) emit(LocalChatEvent.OlderAvailable(conv))
            pendingOlder.clear()
        }
    }

    val isSyncComplete: Boolean get() = synchronized(lock) { syncComplete }

    /** UI measured a media item (spec 8.2). Writes only real measurements; estimates are never stored. */
    fun reportLayout(convKey: String, stableId: String, vp: LocalViewport, wPt: Double, hPt: Double): Boolean {
        return synchronized(lock) {
        requireKey()
        val rk = byStable[indexKey(convKey, stableId)] ?: return false
        val row = rows[rk] ?: return false
        if (row.deleted) return false
        val key = layoutKey(convKey, stableId, vp)
        val prev = layouts[key]
        if (prev != null && Math.abs(prev.hPt - hPt) <= LocalChatLayout.WRITE_TOLERANCE_PT) return false
        layouts[key] = LayoutValue(wPt, hPt, System.currentTimeMillis())
        true
        }
    }

    /** Media in memory only: a failed blob gets the failure placeholder height (spec 8.3). */
    fun markMediaFailed(convKey: String, stableId: String, failed: Boolean) = synchronized(lock) {
        val id = indexKey(convKey, stableId)
        if (failed) failedMedia.add(id) else failedMedia.remove(id)
    }

    fun subscribe(listener: (LocalChatEvent) -> Unit) = synchronized(lock) { listeners.add(listener) }

    /** Spec r2 11.2 `historyImportBatch`: the store computes sendKey and stable_id, dedupes and seals. */
    fun importRows(rows: List<ImportRow>): ImportResult = synchronized(lock) {
        requireKey()
        var inserted = 0
        var existing = 0
        var collapsed = 0
        var rejected = 0
        for (r in rows) {
            val rec = IncomingRecord(r.dir, r.ts, LocalMediaKind.TEXT, r.sendId, r.body, r.cid)
            when (applyRecord(r.convKey, rec, pendingPublish = r.pendingPublish)) {
                ApplyResult.INSERTED, ApplyResult.TOMBSTONED -> inserted++
                ApplyResult.COLLAPSED -> collapsed++
                ApplyResult.REJECTED -> rejected++
                ApplyResult.UPDATED, ApplyResult.CID_ONLY, ApplyResult.SKIPPED -> existing++
            }
        }
        ImportResult(inserted, existing, collapsed, rejected)
    }

    /**
     * M3 digest over every held row in (conv, K) order: HMAC-SHA256(K_idx, h1 || h2 || ...) where
     * hi = HMAC-SHA256(K_idx, sendKey 0x1f decimal(sort_ts) 0x1f dir 0x1f body). Interpretation of spec 11.1 M3:
     * the separators and the aggregation are not spelled out there; to be confirmed by the interface owner.
     */
    fun verifyDigest(): VerifyResult = synchronized(lock) {
        val idx = requireIdxKey()
        val agg = Mac.getInstance("HmacSHA256")
        agg.init(SecretKeySpec(idx, "HmacSHA256"))
        var count = 0
        for (row in rows.values) {
            if (row.deleted || row.bodyEnc == null) continue
            val sk = row.sendKey ?: continue
            val body = bodyOf(row) ?: continue
            val h = Mac.getInstance("HmacSHA256")
            h.init(SecretKeySpec(idx, "HmacSHA256"))
            h.update(sk.toByteArray(Charsets.UTF_8))
            h.update(byteArrayOf(0x1f))
            h.update(row.sortTs.toString().toByteArray(Charsets.US_ASCII))
            h.update(byteArrayOf(0x1f))
            h.update(row.dir.toByteArray(Charsets.UTF_8))
            h.update(byteArrayOf(0x1f))
            h.update(body.toByteArray(Charsets.UTF_8))
            agg.update(h.doFinal())
            count++
        }
        VerifyResult(count, LocalChatIds.base64Url(agg.doFinal()))
    }

    // ---- sync-layer helpers (not read API) ---------------------------------------------

    /**
     * A remote index record is already held with its body (spec 9.2 steps 1–2): no download, no
     * decrypt. A moved cid (PWA relinearize) is recorded here, never re-fetched. False = unknown.
     */
    fun knowsRemote(convKey: String, sendId: String?, cid: String): Boolean {
        return synchronized(lock) {
        requireKey()
        if (!sendId.isNullOrEmpty()) {
            if (aliases.containsKey(indexKey(convKey, LocalChatIds.stableIdOf(requireIdxKey(), sendId)))) return true
            val row = stableRowKey(convKey, sendId)?.let { rows[it] } ?: return false
            if (row.deleted || row.bodyEnc == null) return false
            if (row.cid != cid) moveCid(row, cid)
            return true
        }
        val row = byCid[cid]?.let { rows[it] } ?: return false
        row.convKey == convKey && !row.deleted && row.bodyEnc != null
        }
    }

    /** Decrypted body of a held record, looked up by sendId (when present) or cid. Null when absent. */
    fun bodyForRemote(convKey: String, sendId: String?, cid: String): String? {
        return synchronized(lock) {
        requireKey()
        val row = (if (!sendId.isNullOrEmpty() && !LocalChatIds.isLegacyUuid(sendId)) stableRowKey(convKey, sendId) else byCid[cid])
            ?.let { rows[it] } ?: return null
        if (row.convKey != convKey || row.deleted || row.bodyEnc == null) null else bodyOf(row)
        }
    }

    /** Every held (non-deleted, with body) row, optionally for one conversation, in key order. */
    fun snapshotEntries(convKey: String?): List<StoredEntry> = synchronized(lock) {
        requireKey()
        val out = ArrayList<StoredEntry>()
        for (row in rows.values) {
            if (convKey != null && row.convKey != convKey) continue
            if (row.deleted || row.bodyEnc == null) continue
            out.add(StoredEntry(row.convKey, row.stableId, row.sortTs, row.dir, row.sendId, bodyOf(row) ?: continue))
        }
        out
    }

    /** Spec 11.2: no legacy local store on Android, so the first complete head sync ends migration. */
    fun markMigrationComplete() = synchronized(lock) { migrationState = "complete" }

    val migration: String get() = synchronized(lock) { migrationState }

    fun setSyncState(state: String) {
        syncState = state
    }

    // ---- clearing (spec 10) ----------------------------------------------------------

    /** Clear one conversation; pending rows are kept and counted (T-12). */
    fun clearConversation(convKey: String): Int = synchronized(lock) {
        requireKey()
        val kept = dropRows { it.convKey == convKey }
        windows.remove(convKey)
        emit(LocalChatEvent.Cleared("conversation", convKey, kept))
        kept
    }

    /** Clear the whole account database, then the next sync is a full sync (headIndexHash cleared). */
    fun clearAccount(): Int = synchronized(lock) {
        requireKey()
        val kept = dropRows { true }
        windows.clear()
        headIndexHash = null
        emit(LocalChatEvent.Cleared("account", null, kept))
        kept
    }

    fun rowCount(convKey: String): Int = synchronized(lock) { rows.values.count { it.convKey == convKey && !it.deleted } }

    fun pendingCount(): Int = synchronized(lock) { rows.values.count { it.pendingPublish && !it.deleted } }

    fun setHeadIndexHash(hash: String?) = synchronized(lock) { headIndexHash = hash }

    // ---- internals -------------------------------------------------------------------

    private fun requireKey(): ByteArray = dek ?: throw IllegalStateException("locked")
    private fun requireIdKey(): ByteArray = idKey ?: throw IllegalStateException("locked")
    private fun requireIdxKey(): ByteArray = idxKey ?: throw IllegalStateException("locked")

    /** Row key for a non-UUID sendId: its sendKey is the sendId, so the stable id is derivable without a body. */
    private fun stableRowKey(convKey: String, sendId: String): RowKey? =
        byStable[indexKey(convKey, LocalChatIds.stableIdOf(requireIdxKey(), sendId))]

    private fun resetMemory() {
        rows.clear(); byStable.clear(); byCid.clear(); layouts.clear(); failedMedia.clear(); windows.clear()
        digestIndex.clear(); digestOf.clear(); aliases.clear()
        headIndexHash = null
        tsMismatchCount = 0
        epoch = newEpoch()
    }

    private fun lockMemory() {
        dek?.fill(0); idKey?.fill(0); idxKey?.fill(0)
        dek = null; idKey = null; idxKey = null; kcv = null
        pendingOlder.clear()
        syncComplete = false
        rows.clear(); byStable.clear(); byCid.clear(); layouts.clear(); failedMedia.clear(); windows.clear()
        digestIndex.clear(); digestOf.clear(); aliases.clear()
    }

    private fun insertRow(
        convKey: String, sid: String, rec: IncomingRecord, body: String?,
        pending: Boolean, deleted: Boolean,
    ): StoredRow {
        val k = requireKey()
        val row = StoredRow(
            convKey = convKey, stableId = sid, sortTs = rec.sortTs, dir = rec.dir,
            sendId = rec.sendId?.takeIf { it.isNotEmpty() }, kind = body?.let { parseBody(it).kind } ?: rec.kind, cid = rec.cid,
            revision = rec.revision, deleted = deleted, bodyEnc = null, mediaEnc = null,
            pendingPublish = pending,
        )
        if (!deleted && body != null) row.bodyEnc = seal(k, bodyAad(convKey, sid, rec.revision), body.toByteArray(Charsets.UTF_8))
        setMedia(row, body?.let { parseBody(it) })
        val key = RowKey(convKey, rec.sortTs, sid)
        rows[key] = row
        byStable[indexKey(convKey, sid)] = key
        if (!deleted) rec.cid?.let { byCid[it] = key }
        return row
    }

    /** Parsed body of a stored text or media row (spec r2 21.2). Missing parser: media_parser_missing. */
    private fun parseBody(body: String): ParsedBody {
        val parse = mediaParser ?: return ParsedBody(LocalMediaKind.UNKNOWN, failed = true, error = "media_parser_missing")
        return parse(body.toByteArray(Charsets.UTF_8))
    }

    /** Media meta (cid, mime, size, name, dimensions, failure) is sealed with the row. Text rows carry none. */
    private fun setMedia(row: StoredRow, parsed: ParsedBody?) {
        val k = requireKey()
        if (parsed == null || parsed.kind == LocalMediaKind.TEXT) {
            row.mediaEnc = null
            return
        }
        val m = JSONObject()
            .put("cid", parsed.blob ?: JSONObject.NULL)
            .put("mime", parsed.mime ?: JSONObject.NULL)
            .put("w", parsed.width ?: JSONObject.NULL)
            .put("h", parsed.height ?: JSONObject.NULL)
            .put("size", parsed.size ?: JSONObject.NULL)
            .put("name", parsed.name ?: JSONObject.NULL)
            .put("f", parsed.failed)
            .put("e", parsed.error ?: JSONObject.NULL)
        row.mediaEnc = seal(k, mediaAad(row.convKey, row.stableId, row.revision), m.toString().toByteArray(Charsets.UTF_8))
    }

    private fun moveCid(row: StoredRow, newCid: String?) {
        row.cid?.let { if (byCid[it] == row.key) byCid.remove(it) }
        row.cid = newCid
        newCid?.let { byCid[it] = row.key }
    }

    private fun tombstone(row: StoredRow) {
        row.cid?.let { if (byCid[it] == row.key) byCid.remove(it) }
        row.deleted = true
        row.bodyEnc = null
        row.mediaEnc = null
        removeLayouts(row.convKey, row.stableId)
    }

    /** Drops non-pending rows matching [pred]; returns the number of pending rows kept. */
    private fun dropRows(pred: (StoredRow) -> Boolean): Int {
        var kept = 0
        val it = rows.entries.iterator()
        while (it.hasNext()) {
            val (key, row) = it.next()
            if (!pred(row)) continue
            if (row.pendingPublish) { kept++; continue }
            it.remove()
            byStable.remove(indexKey(row.convKey, row.stableId))
            digestOf.remove(indexKey(row.convKey, row.stableId))?.let { d ->
                val dk = indexKey(row.convKey, d)
                if (digestIndex[dk] == row.stableId) digestIndex.remove(dk)
            }
            row.cid?.let { if (byCid[it] == key) byCid.remove(it) }
            removeLayouts(row.convKey, row.stableId)
        }
        aliases.entries.removeIf { e -> !byStable.containsKey(indexKey(e.key.substringBefore('\u0000'), e.value)) }
        return kept
    }

    private fun removeLayouts(convKey: String, sid: String) {
        layouts.keys.removeAll { it.convKey == convKey && it.stableId == sid }
    }

    /** Lazily drop size records of older layout versions (spec 8.5). */
    private fun sweepLayouts(currentVersion: Int) {
        layouts.keys.removeAll { it.layoutVersion != currentVersion }
    }

    /**
     * One page from [before] (spec v1.1 6.2–6.4; oracle `openPage`). Visible heights accumulate toward
     * older rows until the sum reaches heightPt (the last row may cross). Tombstones count as 0 and
     * advance the cursor. The raw-row budget and the visible cap apply to every page.
     */
    private fun readPage(convKey: String, before: RowKey?, vp: LocalViewport, first: Boolean): LocalPage {
        val hi = before ?: RowKey(convKey + "\u0000", Long.MIN_VALUE, "")
        val items = ArrayList<PageItem>()
        var sum = 0.0
        var scanned = 0
        var capped = false
        var scanExhausted = false
        var windowHi: RowKey? = null
        var windowLo: RowKey? = null
        val scan = rows.headMap(hi, false).descendingMap().values.iterator()
        while (scan.hasNext()) {
            val row = scan.next()
            if (row.convKey != convKey) break
            scanned++
            if (windowHi == null) windowHi = row.key
            windowLo = row.key
            var stop = false
            if (!row.deleted) {
                val item = buildItem(row, vp)
                items.add(item)
                sum += item.layoutH
                if (sum >= vp.heightPt) {
                    stop = true
                } else if (items.size >= CAP) {
                    capped = true
                    stop = true
                }
            }
            if (stop) break
            if (scanned >= SCAN_BUDGET) {
                scanExhausted = true
                break
            }
        }
        val lastScanned = windowLo
        val rawRemain = lastScanned != null && rows.lowerKey(lastScanned)?.convKey == convKey
        val olderState = when {
            rawRemain || scanExhausted -> "more"
            syncComplete -> "end"
            else -> "pending"
        }
        if (olderState == "pending") pendingOlder.add(convKey)
        val olderCursor = if (olderState == "end" || lastScanned == null) null else encodeCursor(lastScanned)
        lastScanHi = windowHi
        lastScanLo = windowLo
        items.reverse()
        return LocalPage(
            items = items,
            olderCursor = olderCursor,
            hasOlder = olderState != "end",
            source = LocalSource.LOCAL,
            error = null,
            short = olderState == "end" && sum < vp.heightPt,
            capped = capped,
            syncState = syncState,
            olderState = olderState,
            scanExhausted = scanExhausted,
            generation = generation,
        )
    }

    /** Raw-row window of the last page (spec O-6): lowest and highest scanned keys, tombstones included. */
    private var lastScanHi: RowKey? = null
    private var lastScanLo: RowKey? = null

    private fun buildItem(row: StoredRow, vp: LocalViewport): PageItem {
        val measured = layouts[layoutKey(row.convKey, row.stableId, vp)]
        val (w, h, isMeasured) = if (measured != null) {
            Triple(measured.wPt, measured.hPt, true)
        } else {
            val est = estimateFor(row, vp)
            Triple(est.first, est.second, false)
        }
        val media = mediaOf(row)
        val body = if (row.kind == LocalMediaKind.TEXT || row.kind == LocalMediaKind.SYSTEM) bodyOf(row) else null
        val failed = failedMedia.contains(indexKey(row.convKey, row.stableId)) || media?.failed == true
        return PageItem(
            stableId = row.stableId, sortTs = row.sortTs, dir = row.dir, sendId = row.sendId,
            kind = row.kind, body = body, revision = row.revision,
            layoutW = w, layoutH = h, measured = isMeasured,
            mediaCid = media?.cid, mediaMime = media?.mime, widthPx = media?.w, heightPx = media?.h,
            mediaState = if (row.kind == LocalMediaKind.IMAGE || row.kind == LocalMediaKind.VIDEO || row.kind == LocalMediaKind.FILE || row.kind == LocalMediaKind.UNKNOWN) {
                if (failed) "failed" else "pending"
            } else null,
        )
    }

    private fun estimateFor(row: StoredRow, vp: LocalViewport): Pair<Double, Double> {
        val media = mediaOf(row)
        val body = if (row.kind == LocalMediaKind.TEXT) bodyOf(row) else null
        return LocalChatLayout.estimate(
            row.kind, media?.w, media?.h,
            failedMedia.contains(indexKey(row.convKey, row.stableId)) || mediaOf(row)?.failed == true, body, vp,
        )
    }

    private fun bodyOf(row: StoredRow): String? {
        val k = requireKey()
        val enc = row.bodyEnc ?: return null
        return String(open(k, bodyAad(row.convKey, row.stableId, row.revision), enc), Charsets.UTF_8)
    }

    private fun mediaOf(row: StoredRow): MediaMeta? {
        val k = requireKey()
        val enc = row.mediaEnc ?: return null
        val o = JSONObject(String(open(k, mediaAad(row.convKey, row.stableId, row.revision), enc), Charsets.UTF_8))
        return MediaMeta(
            cid = o.optString("cid").takeIf { it.isNotEmpty() && it != "null" },
            mime = o.optString("mime").takeIf { it.isNotEmpty() && it != "null" },
            w = if (o.isNull("w")) null else o.optInt("w"),
            h = if (o.isNull("h")) null else o.optInt("h"),
            failed = o.optBoolean("f", false),
        )
    }

    private fun keyOf(convKey: String, item: PageItem): RowKey = RowKey(convKey, item.sortTs, item.stableId)

    private fun emitInserted(row: StoredRow, k: ByteArray) {
        val w = windows[row.convKey] ?: return
        val key = row.key
        val oldest = w.oldest
        if (oldest != null && rowComparator.compare(key, oldest) < 0) return
        val position = if (w.newest == null || rowComparator.compare(key, w.newest) > 0) "tail" else "middle"
        val item = buildItem(row, currentViewportFor(row.convKey))
        emit(LocalChatEvent.Inserted(row.convKey, listOf(item), position))
        if (position == "tail") windows[row.convKey] = w.copy(newest = key)
    }

    /** Window events use the viewport of the last open page; falls back to a 1-item estimate. */
    private fun currentViewportFor(convKey: String): LocalViewport =
        windowViewports[convKey] ?: DEFAULT_VIEWPORT

    private val windowViewports = HashMap<String, LocalViewport>()

    private fun emit(e: LocalChatEvent) {
        for (l in listeners.toList()) l(e)
    }

    private fun encodeCursor(key: RowKey): String = LocalChatIds.base64Url(
        JSONObject()
            .put("v", 1)
            .put("e", epoch.take(8))
            .put("c", key.convKey)
            .put("t", key.sortTs)
            .put("i", key.stableId)
            .toString()
            .toByteArray(Charsets.UTF_8),
    )

    /** Null when the cursor is malformed, from another epoch (spec A-3), or for another conversation. */
    private fun decodeCursor(cursor: String, convKey: String): RowKey? {
        return try {
            val o = JSONObject(String(base64UrlDecode(cursor), Charsets.UTF_8))
            if (o.getInt("v") != 1 || o.getString("e") != epoch.take(8)) return null
            if (o.getString("c") != convKey) return null
            RowKey(convKey, o.getLong("t"), o.getString("i"))
        } catch (e: Exception) {
            null
        }
    }

    private fun layoutKey(convKey: String, sid: String, vp: LocalViewport) = LayoutKey(
        convKey, sid, LocalChatLayout.widthBucket(vp.widthPt), vp.orientation,
        LocalChatLayout.fontBucket(vp.fontScale), vp.layoutVersion,
    )

    private fun loadPayload(o: JSONObject): Boolean {
        return try {
            epoch = o.getString("epoch")
            migrationState = o.optString("migration", "none")
            syncComplete = o.optBoolean("syncComplete", false)
            val dg = o.optJSONArray("digests")
            if (dg != null) for (i in 0 until dg.length()) {
                val e = dg.getJSONObject(i)
                val k5 = e.getString("k")
                val d5 = e.getString("v")
                digestOf[k5] = d5
                digestIndex[indexKey(k5.substringBefore('\u0000'), d5)] = k5.substringAfter('\u0000')
            }
            val al = o.optJSONArray("aliases")
            if (al != null) for (i in 0 until al.length()) {
                val e = al.getJSONObject(i)
                aliases[e.getString("k")] = e.getString("v")
            }
            headIndexHash = if (o.isNull("headIndexHash")) null else o.getString("headIndexHash")
            val rowArr = o.getJSONArray("rows")
            for (i in 0 until rowArr.length()) {
                val r = StoredRow.fromJson(rowArr.getJSONObject(i))
                val key = RowKey(r.convKey, r.sortTs, r.stableId)
                rows[key] = r
                byStable[indexKey(r.convKey, r.stableId)] = key
                if (!r.deleted) r.cid?.let { byCid[it] = key }
            }
            val layArr = o.getJSONArray("layouts")
            for (i in 0 until layArr.length()) {
                val l = layArr.getJSONObject(i)
                layouts[LayoutKey(l.getString("c"), l.getString("s"), l.getInt("w"), l.getString("o"), l.getInt("f"), l.getInt("v"))] =
                    LayoutValue(l.getDouble("wp"), l.getDouble("hp"), l.getLong("u"))
            }
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun mediaAad(convKey: String, sid: String, revision: Int): ByteArray =
        bodyAad(convKey, sid, revision) + "|media".toByteArray(Charsets.UTF_8)

    private fun snapshotAad(m: ByteArray): ByteArray = "chat-local-snapshot-v1".toByteArray(Charsets.UTF_8) + m

    private fun bodyAad(convKey: String, sid: String, revision: Int): ByteArray =
        "${LocalChatIds.convBlind(requireIdxKey(), convKey)}\u001f$sid\u001f$revision".toByteArray(Charsets.UTF_8)

    private fun bodyAadLegacy(convKey: String, sid: String, revision: Int): ByteArray =
        "$convKey\u001f$sid\u001f$revision".toByteArray(Charsets.UTF_8)

    private fun hkdf(master: ByteArray, info: String): ByteArray = ConetChatCryptoUtil.hkdf(master, info, 32)

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun seal(key: ByteArray, aad: ByteArray, plain: ByteArray): ByteArray {
        val nonce = ByteArray(12).also { rng.nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        return nonce + c.doFinal(plain)
    }

    private fun open(key: ByteArray, aad: ByteArray, blob: ByteArray): ByteArray {
        require(blob.size > 12 + 16) { "short blob" }
        val nonce = blob.copyOfRange(0, 12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        return c.doFinal(blob, 12, blob.size - 12)
    }

    private fun base64UrlDecode(s: String): ByteArray {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val out = java.io.ByteArrayOutputStream()
        var buf = 0
        var bits = 0
        for (ch in s) {
            val v = alphabet.indexOf(ch)
            require(v >= 0) { "bad base64url" }
            buf = (buf shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((buf shr bits) and 0xff)
            }
        }
        return out.toByteArray()
    }

    private fun newEpoch(): String {
        val b = ByteArray(8).also { SecureRandom().nextBytes(it) }
        return ConetChatCryptoUtil.toHex(b)
    }

    // ---- value types -----------------------------------------------------------------

    class StoredRow(
        val convKey: String,
        val stableId: String,
        val sortTs: Long,
        val dir: String,
        val sendId: String?,
        var kind: LocalMediaKind,
        var cid: String?,
        var revision: Int,
        var deleted: Boolean,
        var bodyEnc: ByteArray?,
        var mediaEnc: ByteArray?,
        var pendingPublish: Boolean,
        /** sendKey of the row (spec r2 4.1). Persisted only inside the sealed snapshot. */
        var sendKey: String? = null,
    ) {
        val key: RowKey get() = RowKey(convKey, sortTs, stableId)

        fun toJson(): JSONObject = JSONObject()
            .put("c", convKey).put("s", stableId).put("t", sortTs).put("d", dir)
            .put("sid", sendId ?: JSONObject.NULL).put("k", kind.name).put("cid", cid ?: JSONObject.NULL)
            .put("r", revision).put("del", deleted)
            .put("b", bodyEnc?.let { ConetChatCryptoUtil.toHex(it) } ?: JSONObject.NULL)
            .put("m", mediaEnc?.let { ConetChatCryptoUtil.toHex(it) } ?: JSONObject.NULL)
            .put("p", pendingPublish)
            .put("sk", sendKey ?: JSONObject.NULL)

        companion object {
            fun fromJson(o: JSONObject): StoredRow = StoredRow(
                convKey = o.getString("c"), stableId = o.getString("s"), sortTs = o.getLong("t"),
                dir = o.getString("d"),
                sendId = if (o.isNull("sid")) null else o.getString("sid"),
                kind = LocalMediaKind.valueOf(o.getString("k")),
                cid = if (o.isNull("cid")) null else o.getString("cid"),
                revision = o.getInt("r"), deleted = o.getBoolean("del"),
                bodyEnc = if (o.isNull("b")) null else ConetChatCryptoUtil.hexToBytes(o.getString("b")),
                mediaEnc = if (o.isNull("m")) null else ConetChatCryptoUtil.hexToBytes(o.getString("m")),
                pendingPublish = o.getBoolean("p"),
                sendKey = if (o.isNull("sk")) null else o.getString("sk"),
            )
        }
    }

    data class RowKey(val convKey: String, val sortTs: Long, val stableId: String)

    private data class LayoutKey(
        val convKey: String, val stableId: String, val widthBucket: Int,
        val orientation: String, val fontBucket: Int, val layoutVersion: Int,
    )

    private data class LayoutValue(val wPt: Double, val hPt: Double, val updatedMs: Long)

    private data class Window(val oldest: RowKey?, val newest: RowKey?, val opened: Boolean)

    private data class MediaMeta(val cid: String?, val mime: String?, val w: Int?, val h: Int?, val failed: Boolean)

    companion object {
        const val SCHEMA_VERSION = 1
        /** Safety cap on consumed rows for the first screen (spec v1.1 6.2). */
        const val CAP = 200
        /** Raw-row budget for one loadOlder scan (spec v1.1 6.3). */
        const val SCAN_BUDGET = 2000
        private const val FORMAT_TAG = "CLS1"
        private val DEFAULT_VIEWPORT = LocalViewport(390.0, 844.0, "portrait", 1.0, 1)

        private val rowComparator = Comparator<RowKey> { a, b ->
            val c = LocalChatIds.compareUtf8(a.convKey, b.convKey)
            if (c != 0) c else LocalChatIds.compareKey(a.sortTs, a.stableId, b.sortTs, b.stableId)
        }

        private fun indexKey(convKey: String, sid: String): String = "$convKey\u0000$sid"
    }
}

/** One row of a migration import (spec r2 11.2). */
data class ImportRow(
    val convKey: String,
    val sendId: String?,
    val dir: String,
    val ts: Long,
    val body: String,
    val pendingPublish: Boolean,
    val cid: String? = null,
)

data class ImportResult(val inserted: Int, val existing: Int, val collapsed: Int, val rejected: Int)

data class VerifyResult(val rows: Int, val digest: String)

/** A source record for [LocalChatStore.applyRecord]. */
class IncomingRecord(
    val dir: String,
    val sortTs: Long,
    val kind: LocalMediaKind,
    val sendId: String?,
    val body: String?,
    val cid: String?,
    val revision: Int = 0,
    val deleted: Boolean = false,
    /** Source's stable id for tombstones and sendId-less records (spec 4.1). */
    val stableIdHint: String? = null,
    /** sendKey for tombstones and revisions that reference it (spec v1.1 4.1, Q-3). */
    val sendKeyHint: String? = null,
    val widthPx: Int? = null,
    val heightPx: Int? = null,
    val mime: String? = null,
    val mediaCid: String? = null,
)

enum class ApplyResult { INSERTED, UPDATED, CID_ONLY, TOMBSTONED, SKIPPED, REJECTED, COLLAPSED }

enum class UnlockResult(val opened: Boolean) {
    OK(true),
    REBUILT_KCV_MISMATCH(true),
    LOCKED_KCV_MISMATCH_PENDING(false),
    LOCKED_SCHEMA_NEWER(false),
    SNAPSHOT_CORRUPT(false),
}

enum class LocalSource { LOCAL, MIGRATING, LOCKED }

data class PageItem(
    val stableId: String,
    val sortTs: Long,
    val dir: String,
    val sendId: String?,
    val kind: LocalMediaKind,
    val body: String?,
    val revision: Int,
    val layoutW: Double,
    val layoutH: Double,
    val measured: Boolean,
    val mediaCid: String?,
    val mediaMime: String?,
    val widthPx: Int?,
    val heightPx: Int?,
    val mediaState: String?,
)

/** Items ascend by key. [olderCursor] points at the oldest row this page consumed (tombstones included). */
data class LocalPage(
    val items: List<PageItem>,
    val olderCursor: String?,
    val hasOlder: Boolean,
    val source: LocalSource,
    val error: String?,
    /** Local data ended before one viewport was filled (legal). */
    val short: Boolean = false,
    /** The safety cap fired; should not happen at normal viewport sizes. */
    val capped: Boolean = false,
    val syncState: String = "idle",
    /** more | pending | end (spec v1.1 6.4). */
    val olderState: String = if (hasOlder) "more" else "end",
    /** A loadOlder scan hit its budget: the host must ask again (spec 6.3). */
    val scanExhausted: Boolean = false,
    /** The store generation the result belongs to (spec 6.5). */
    val generation: Long = 0L,
)

/** A held record for the legacy whole-history read (historyRead). */
data class StoredEntry(
    val convKey: String,
    val stableId: String,
    val sortTs: Long,
    val dir: String,
    val sendId: String?,
    val body: String,
)

sealed class LocalChatEvent {
    data class OlderAvailable(val convKey: String) : LocalChatEvent()
    /** The page must clear what it shows now (spec 6.5 step 2). */
    object Locked : LocalChatEvent()
    data class Inserted(val convKey: String, val items: List<PageItem>, val position: String) : LocalChatEvent()
    data class Updated(val convKey: String, val stableId: String, val revision: Int) : LocalChatEvent()
    data class Deleted(val convKey: String, val stableId: String) : LocalChatEvent()
    data class Cleared(val scope: String, val convKey: String?, val pendingKept: Int) : LocalChatEvent()
}
