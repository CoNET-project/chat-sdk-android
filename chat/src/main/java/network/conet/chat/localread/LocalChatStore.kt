package network.conet.chat.localread

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Local read store on SQLite (spec r3a 7.1–7.5, 9.1, D-A1 replacement). One store per account.
 *
 * - Bodies and metadata are sealed with the DEK (AES-256-GCM, 7.2). Identity columns are blind indexes.
 * - Reads run key-range queries on `msg` (no network, no waiting for sync: 9.1).
 * - [lock] closes the database handle and zeroes the keys (6.5). The file stays; it cannot be read without the DEK.
 *
 * Not thread-safe beyond `synchronized(lock)`; every public method takes the lock.
 */
class LocalChatStore(
    val accountKey: String,
    db: SqlDb,
    /** Body parser (spec r2 21.2). Null = the host did not set one: media-like bodies become failed `media_parser_missing`. */
    private val mediaParser: ((ByteArray) -> ParsedBody)? = MediaManifestParser::parse,
) {
    private val lock = Any()
    private val rng = SecureRandom()
    private var db: SqlDb? = db

    private var dek: ByteArray? = null
    private var idKey: ByteArray? = null
    private var idxKey: ByteArray? = null
    private var epoch: String = ""
    private var syncComplete = false
    private var migrationState = "none"

    /** Bumped on every lock(); results of an older generation must be dropped by the host (spec 6.5). */
    @Volatile
    var generation: Long = 0L
        private set

    /** Why the store is locked, when unlock refused (spec 6.6 codes). Null when unlocked or never tried. */
    @Volatile
    var lastError: String? = null
        private set

    @Volatile
    var syncState: String = "idle"
        private set

    private val windows = HashMap<String, Window>()
    private val windowViewports = HashMap<String, LocalViewport>()
    private val listeners = ArrayList<(LocalChatEvent) -> Unit>()
    private val failedMedia = HashSet<String>()
    private val pendingOlder = HashSet<String>()
    private val convKeyOf = HashMap<String, String>()
    private var lastScanHi: RowKey? = null
    private var lastScanLo: RowKey? = null

    /** Count of sync records whose sortTs differed from the stored one (spec 5, counted only). */
    var tsMismatchCount: Int = 0
        private set

    val isUnlocked: Boolean get() = synchronized(lock) { dek != null }

    /**
     * True while the database handle is open. A logged-out store (lock) has no handle: it is closed. A locked store keeps its handle
     * and loses only the key (markLocked, a failed unlock): it is open but not unlocked (R565).
     */
    val isOpen: Boolean get() = synchronized(lock) { db != null }

    // ---- unlock / lock ---------------------------------------------------------------

    /**
     * Test convenience only: derives the local root from [master] as if it were the private key.
     * Production code calls [unlock] with the wallet-boundary root (spec r3a 25).
     */
    fun unlock(master: ByteArray, snapshot: Nothing?): UnlockResult {
        val eoa = accountKey.substringBeforeLast(':')
        val ws = accountKey.substringAfterLast(':')
        return unlock(master, LocalChatIds.rootDbFromPrivateKey(master, eoa, ws))
    }

    /**
     * Unlock with the protocol root [master] (kept for the history path) and the local-DB root [dbRoot]
     * (R_db): DEK, kcv and K_idx come from R_db; K_id comes from R_db too (spec r3a 7.2, 25.1).
     */
    fun unlock(master: ByteArray, dbRoot: ByteArray): UnlockResult {
        val r = synchronized(lock) {
            try {
                unlockInner(dbRoot)
            } catch (e: Exception) {
                lockMemory(closeDb = false)
                UnlockResult.SNAPSHOT_CORRUPT
            }
        }
        lastError = when (r) {
            UnlockResult.OK, UnlockResult.REBUILT_KCV_MISMATCH -> null
            UnlockResult.LOCKED_KCV_MISMATCH_PENDING -> "kcv_mismatch"
            UnlockResult.LOCKED_SCHEMA_NEWER -> "schema_newer"
            UnlockResult.SNAPSHOT_CORRUPT -> "db_error"
        }
        return r
    }

    /** Refuse to open with an error code, e.g. `db_root_missing` when the wallet boundary holds no key. */
    fun markLocked(error: String) {
        synchronized(lock) {
            lockMemory(closeDb = false)
            lastError = error
        }
    }

    private fun unlockInner(dbRoot: ByteArray): UnlockResult {
        val eoa = accountKey.substringBeforeLast(':')
        val ws = accountKey.substringAfterLast(':')
        val key = LocalChatIds.dekFromRootDb(dbRoot, eoa, ws)
        val d = requireDb()
        dek = key
        idKey = LocalChatIds.idKeyFromRootDb(dbRoot)
        idxKey = LocalChatIds.idxKeyFromRootDb(dbRoot)
        for (s in SqlSchema.DDL) d.execute(s)
        val kcvPresent = d.query("SELECT v_enc FROM meta WHERE k = ?", arrayOf("kcv")).isNotEmpty()
        if (!kcvPresent) {
            initMeta()
            loadMemory()
            return UnlockResult.OK
        }
        val kcvOk = try {
            openMeta("kcv") == "kcv-ok"
        } catch (e: Exception) {
            false
        }
        if (!kcvOk) {
            val pending = d.query("SELECT COUNT(*) FROM msg WHERE pending_publish = 1").first()[0] as Long
            if (pending > 0) {
                // Keep the file; the caller shows the error and decides (spec 7.3).
                lockMemory(closeDb = false)
                return UnlockResult.LOCKED_KCV_MISMATCH_PENDING
            }
            // Nothing waiting to publish: rebuild under a new epoch (spec 7.3).
            d.transaction {
                for (t in listOf("msg", "layout", "alias", "conv", "meta")) d.execute("DELETE FROM $t")
            }
            initMeta()
            loadMemory()
            return UnlockResult.REBUILT_KCV_MISMATCH
        }
        val schema = openMeta("schemaVersion")?.toIntOrNull() ?: 0
        if (schema > SqlSchema.SCHEMA_VERSION) {
            lockMemory(closeDb = false)
            return UnlockResult.LOCKED_SCHEMA_NEWER
        }
        loadMemory()
        return UnlockResult.OK
    }

    private fun initMeta() {
        setMeta("schemaVersion", SqlSchema.SCHEMA_VERSION.toString())
        setMeta("kcv", "kcv-ok")
        setMeta("dbEpoch", newEpoch())
        setMeta("syncComplete", "0")
        setMeta("migrationState", "none")
        setMeta("layoutVersion", "1")
    }

    private fun loadMemory() {
        epoch = openMeta("dbEpoch") ?: newEpoch()
        syncComplete = openMeta("syncComplete") == "1"
        migrationState = openMeta("migrationState") ?: "none"
    }

    /** Test hook (schema and version tests only): writes a sealed meta value. Not used in production. */
    internal fun setMetaForTest(k: String, v: String) = synchronized(lock) { setMeta(k, v) }

    /** Logout (spec D2, 6.5): zero DEK and keys, close the handle. The file stays. */
    fun lock() = synchronized(lock) {
        generation++
        lockMemory(closeDb = true)
    }

    /** Step 1 of spec 6.5 only: results from before this point are stale from now on. */
    fun bumpGeneration(): Long = synchronized(lock) {
        generation++
        generation
    }

    private fun lockMemory(closeDb: Boolean) {
        dek?.fill(0)
        idKey?.fill(0)
        idxKey?.fill(0)
        dek = null
        idKey = null
        idxKey = null
        windows.clear()
        windowViewports.clear()
        failedMedia.clear()
        pendingOlder.clear()
        convKeyOf.clear()
        syncComplete = false
        if (closeDb) {
            try {
                db?.close()
            } catch (_: Exception) {
            }
            db = null
        }
    }

    private fun requireKey(): ByteArray = dek ?: throw IllegalStateException("locked")
    private fun requireIdKey(): ByteArray = idKey ?: throw IllegalStateException("locked")
    private fun requireIdxKey(): ByteArray = idxKey ?: throw IllegalStateException("locked")
    private fun requireDb(): SqlDb = db ?: throw IllegalStateException("closed")

    // ---- meta (sealed values) --------------------------------------------------------

    private fun setMeta(k: String, value: String) {
        val blob = seal(requireKey(), "meta|$k".toByteArray(Charsets.UTF_8), value.toByteArray(Charsets.UTF_8))
        requireDb().execute("INSERT OR REPLACE INTO meta (k, v_enc) VALUES (?, ?)", arrayOf(k, blob))
    }

    private fun openMeta(k: String): String? {
        val rows = requireDb().query("SELECT v_enc FROM meta WHERE k = ?", arrayOf(k))
        val blob = rows.firstOrNull()?.get(0) as? ByteArray ?: return null
        return String(open(requireKey(), "meta|$k".toByteArray(Charsets.UTF_8), blob), Charsets.UTF_8)
    }

    private fun bumpEpoch() {
        epoch = newEpoch()
        setMeta("dbEpoch", epoch)
    }

    // ---- sync write path -------------------------------------------------------------

    /**
     * Apply one source record (spec r3a 4–5). The caller has already downloaded and decrypted the body
     * when [IncomingRecord.body] is needed.
     */
    fun applyRecord(convKey: String, rec: IncomingRecord, pendingPublish: Boolean = false): ApplyResult {
        return synchronized(lock) {
        val k = requireKey()
        val idx = requireIdxKey()
        val cb = LocalChatIds.convBlind(idx, convKey)
        val sk: String? = rec.sendKeyHint ?: if (rec.stableIdHint == null) {
            LocalChatIds.sendKey(requireIdKey(), convKey, rec.sendId, rec.dir, rec.sortTs, rec.body)
                ?: return ApplyResult.REJECTED
        } else {
            null
        }
        val derived = rec.stableIdHint ?: LocalChatIds.stableIdOf(idx, sk!!)
        // A folded sendKey resolves to its survivor (spec 4.5): updates and tombstones follow the alias.
        val sid = aliasTarget(derived) ?: derived
        val existing = loadRow(cb, sid)
        if (existing == null) {
            if (rec.deleted) {
                insertRow(cb, convKey, sid, rec.sortTs, rec.revision, deleted = true, pending = pendingPublish,
                    cidBlind = null, body = null, meta = null)
                return ApplyResult.TOMBSTONED
            }
            val body = rec.body ?: return ApplyResult.REJECTED
            val digest = LocalChatIds.contentDigest(convKey, rec.dir, rec.sortTs, body)
            val survivor = digestSurvivor(cb, rec.sortTs, digest, exclude = sid)
            if (survivor != null) {
                // Same (peer, dir, ts, body digest) under another sendKey: fold it to the earliest (spec 4.5).
                if (sk != null) putAlias(derived, survivor)
                return ApplyResult.COLLAPSED
            }
            val parsed = parseBody(body)
            val meta = RowMeta(parsed.kind, rec.dir, rec.sendId?.takeIf { it.isNotEmpty() }, sk, digest, mediaOf(parsed), parsed.failed)
            insertRow(cb, convKey, sid, rec.sortTs, rec.revision, deleted = false, pending = pendingPublish,
                cidBlind = rec.cid?.let { cidBlind(idx, it) }, body = body, meta = meta)
            val row = loadRow(cb, sid)!!
            emitInserted(convKey, cb, row)
            if (pendingOlder.remove(convKey)) emit(LocalChatEvent.OlderAvailable(convKey))
            return ApplyResult.INSERTED
        }
        if (rec.deleted) {
            if (existing.state != SqlSchema.STATE_NORMAL) return ApplyResult.SKIPPED
            requireDb().execute("UPDATE msg SET state = ?, body_enc = NULL, meta_enc = NULL WHERE conv_blind = ? AND stable_id = ?",
                arrayOf(SqlSchema.STATE_TOMBSTONE.toLong(), cb, sid))
            removeLayouts(cb, sid)
            emit(LocalChatEvent.Deleted(convKey, sid))
            return ApplyResult.TOMBSTONED
        }
        if (existing.state != SqlSchema.STATE_NORMAL) return ApplyResult.SKIPPED
        if (rec.sortTs != existing.sortTs) tsMismatchCount++
        if (rec.revision > existing.revision) {
            val body = rec.body ?: return ApplyResult.REJECTED
            val digest = LocalChatIds.contentDigest(convKey, rec.dir, rec.sortTs, body)
            val parsed = parseBody(body)
            val meta = RowMeta(parsed.kind, rec.dir, rec.sendId?.takeIf { it.isNotEmpty() }, sk, digest, mediaOf(parsed), parsed.failed)
            val bodyEnc = seal(k, bodyAad(cb, sid, rec.revision), body.toByteArray(Charsets.UTF_8))
            requireDb().execute(
                "UPDATE msg SET revision = ?, body_enc = ?, meta_enc = ?, cid_blind = ? WHERE conv_blind = ? AND stable_id = ?",
                arrayOf(rec.revision.toLong(), bodyEnc, sealMeta(cb, sid, meta), rec.cid?.let { cidBlind(idx, it) } ?: existing.cidBlind, cb, sid),
            )
            removeLayouts(cb, sid)
            emit(LocalChatEvent.Updated(convKey, sid, rec.revision))
            return ApplyResult.UPDATED
        }
        if (rec.revision == existing.revision && rec.cid != null && cidBlind(idx, rec.cid) != existing.cidBlind) {
            requireDb().execute("UPDATE msg SET cid_blind = ? WHERE conv_blind = ? AND stable_id = ?",
                arrayOf(cidBlind(idx, rec.cid), cb, sid))
            return ApplyResult.CID_ONLY
        }
        ApplyResult.SKIPPED
        }
    }

    // ---- read path (no network, no waiting for sync) ---------------------------------

    /** First screen: newest rows up to one viewport (spec r3a 6.2). Nothing is read ahead. */
    fun openConversation(convKey: String, vp: LocalViewport): LocalPage {
        return synchronized(lock) {
            if (dek == null) return LocalPage(emptyList(), null, false, LocalSource.LOCKED, lastError ?: "locked", generation = generation)
            val page = readPage(convKey, null, vp, first = true)
            windowViewports[convKey] = vp
            windows[convKey] = Window(oldest = lastScanLo, newest = lastScanHi, opened = true)
            page
        }
    }

    /** Older page strictly before [cursor]; scans up to the budget of raw rows (spec r3a 6.3). */
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
            setMeta("syncComplete", "1")
            for (conv in pendingOlder.toList()) emit(LocalChatEvent.OlderAvailable(conv))
            pendingOlder.clear()
        }
    }

    val isSyncComplete: Boolean get() = synchronized(lock) { syncComplete }

    /** UI measured a media item (spec r3a 8.2). Writes only real measurements; estimates are never stored. */
    fun reportLayout(convKey: String, stableId: String, vp: LocalViewport, wPt: Double, hPt: Double): Boolean {
        return synchronized(lock) {
            val k = requireKey()
            val cb = LocalChatIds.convBlind(requireIdxKey(), convKey)
            val row = loadRow(cb, stableId) ?: return false
            if (row.state != SqlSchema.STATE_NORMAL) return false
            val lk = layoutKey(vp)
            val prev = loadLayout(cb, stableId, lk)
            if (prev != null && Math.abs(prev.second - hPt) <= LocalChatLayout.WRITE_TOLERANCE_PT) return false
            val val_ = JSONObject().put("w", wPt).put("h", hPt).put("u", System.currentTimeMillis()).toString()
            val blob = seal(k, layoutAad(cb, stableId, lk), val_.toByteArray(Charsets.UTF_8))
            requireDb().execute("INSERT OR REPLACE INTO layout (conv_blind, stable_id, layout_key, val_enc) VALUES (?, ?, ?, ?)",
                arrayOf(cb, stableId, lk, blob))
            true
        }
    }

    /** Media in memory only: a failed blob gets the failure placeholder height (spec 8.3). */
    fun markMediaFailed(convKey: String, stableId: String, failed: Boolean) = synchronized(lock) {
        val id = indexKey(convKey, stableId)
        if (failed) failedMedia.add(id) else failedMedia.remove(id)
    }

    fun subscribe(listener: (LocalChatEvent) -> Unit) = synchronized(lock) { listeners.add(listener) }

    // ---- migration import, verify (spec r3a 11.1, 11.2) ------------------------------

    /** Spec r3a 11.2 `historyImportBatch`: the store computes sendKey and stable_id, dedupes and seals. */
    fun importRows(rows: List<ImportRow>): ImportResult = synchronized(lock) {
        requireKey()
        // One transaction per batch: the batch is stored whole or not at all, and costs one commit
        // instead of one commit per statement (applyRecord itself does not open a transaction).
        requireDb().transaction {
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
    }

    /**
     * M3 digest over every held row in (conv_blind, K) order: HMAC-SHA256(K_idx, h1 || h2 || ...) where
     * hi = HMAC-SHA256(K_idx, sendKey 0x1f decimal(sort_ts) 0x1f dir 0x1f body). The separators and the
     * aggregation are my reading of spec 11.1 M3 (to be confirmed by the interface owner).
     */
    fun verifyDigest(): VerifyResult = synchronized(lock) {
        val k = requireKey()
        val idx = requireIdxKey()
        val agg = Mac.getInstance("HmacSHA256")
        agg.init(SecretKeySpec(idx, "HmacSHA256"))
        var count = 0
        val rows = requireDb().query(
            "SELECT conv_blind, stable_id, sort_ts, revision, body_enc, meta_enc FROM msg WHERE state = 0 ORDER BY conv_blind, sort_ts, stable_id",
        )
        for (r in rows) {
            val cb = r[0] as String
            val sid = r[1] as String
            val sortTs = r[2] as Long
            val rev = (r[3] as Long).toInt()
            val bodyEnc = r[4] as? ByteArray ?: continue
            val meta = openMetaJson(cb, sid, r[5] as? ByteArray ?: continue)
            val sk = meta.optString("sk", "")
            if (sk.isEmpty()) continue
            val body = String(open(k, bodyAad(cb, sid, rev), bodyEnc), Charsets.UTF_8)
            val h = Mac.getInstance("HmacSHA256")
            h.init(SecretKeySpec(idx, "HmacSHA256"))
            h.update(sk.toByteArray(Charsets.UTF_8))
            h.update(byteArrayOf(0x1f))
            h.update(sortTs.toString().toByteArray(Charsets.US_ASCII))
            h.update(byteArrayOf(0x1f))
            h.update(meta.getString("d").toByteArray(Charsets.UTF_8))
            h.update(byteArrayOf(0x1f))
            h.update(body.toByteArray(Charsets.UTF_8))
            agg.update(h.doFinal())
            count++
        }
        VerifyResult(count, LocalChatIds.base64Url(agg.doFinal()))
    }

    // ---- sync-layer helpers (not read API) -------------------------------------------

    /**
     * A remote index record is already held with its body (spec 9.2 steps 1–2): no download, no
     * decrypt. A moved cid (PWA relinearize) is recorded here, never re-fetched. False = unknown.
     */
    fun knowsRemote(convKey: String, sendId: String?, cid: String): Boolean {
        return synchronized(lock) {
            requireKey()
            val idx = requireIdxKey()
            val cb = LocalChatIds.convBlind(idx, convKey)
            if (!sendId.isNullOrEmpty()) {
                val sid = LocalChatIds.stableIdOf(idx, sendId)
                if (aliasTarget(sid) != null) return true
                val row = loadRow(cb, sid) ?: return false
                if (row.state != SqlSchema.STATE_NORMAL || row.bodyEnc == null) return false
                if (row.cidBlind != cidBlind(idx, cid)) {
                    requireDb().execute("UPDATE msg SET cid_blind = ? WHERE conv_blind = ? AND stable_id = ?",
                        arrayOf(cidBlind(idx, cid), cb, sid))
                }
                return true
            }
            val row = loadRowByCid(cb, cidBlind(idx, cid)) ?: return false
            row.state == SqlSchema.STATE_NORMAL && row.bodyEnc != null
        }
    }

    /** Decrypted body of a held record, looked up by sendId (when present) or cid. Null when absent. */
    fun bodyForRemote(convKey: String, sendId: String?, cid: String): String? {
        return synchronized(lock) {
            val k = requireKey()
            val idx = requireIdxKey()
            val cb = LocalChatIds.convBlind(idx, convKey)
            val row = if (!sendId.isNullOrEmpty()) loadRow(cb, LocalChatIds.stableIdOf(idx, sendId))
                else loadRowByCid(cb, cidBlind(idx, cid))
            if (row == null || row.state != SqlSchema.STATE_NORMAL || row.bodyEnc == null) null
            else String(open(k, bodyAad(cb, row.stable, row.revision), row.bodyEnc), Charsets.UTF_8)
        }
    }

    /** Every held (non-deleted, with body) row, optionally for one conversation, in key order. */
    fun snapshotEntries(convKey: String?): List<StoredEntry> = synchronized(lock) {
        val k = requireKey()
        val d = requireDb()
        val cbFilter = convKey?.let { LocalChatIds.convBlind(requireIdxKey(), it) }
        val rows = if (cbFilter == null) {
            d.query("SELECT conv_blind, stable_id, sort_ts, revision, body_enc, meta_enc FROM msg WHERE state = 0 AND body_enc IS NOT NULL ORDER BY conv_blind, sort_ts, stable_id")
        } else {
            d.query("SELECT conv_blind, stable_id, sort_ts, revision, body_enc, meta_enc FROM msg WHERE conv_blind = ? AND state = 0 AND body_enc IS NOT NULL ORDER BY sort_ts, stable_id", arrayOf(cbFilter))
        }
        val out = ArrayList<StoredEntry>()
        for (r in rows) {
            val cb = r[0] as String
            val sid = r[1] as String
            val meta = openMetaJson(cb, sid, r[5] as ByteArray)
            val body = String(open(k, bodyAad(cb, sid, (r[3] as Long).toInt()), r[4] as ByteArray), Charsets.UTF_8)
            out.add(StoredEntry(convKeyFor(cb), sid, r[2] as Long, meta.getString("d"), meta.optString("sid", "").ifEmpty { null }, body))
        }
        out
    }

    /** Spec 11.2: no legacy store on Android, so the first complete head sync ends migration. */
    fun markMigrationComplete() = synchronized(lock) {
        requireKey()
        migrationState = "complete"
        setMeta("migrationState", "complete")
    }

    val migration: String get() = synchronized(lock) { migrationState }

    fun setSyncState(state: String) {
        syncState = state
    }

    // ---- native deletion (spec r3by §25.52AC.2, §25.52AC.3) ------------------------------

    /**
     * `historyDeleteMessage`: tombstones the one row whose sendKey is [sendKey] (§25.52AC.2). The row is found by the stable id that the
     * sendKey derives, so a tombstone (which has lost its metadata) is still found. Nothing else changes. Returns true when a live row was
     * tombstoned; false when the row is missing or already a tombstone (idempotent).
     */
    fun tombstoneMessage(convKey: String, sendKey: String): Boolean {
        synchronized(lock) {
            requireKey()
            val idx = requireIdxKey()
            val cb = LocalChatIds.convBlind(idx, convKey)
            val derived = LocalChatIds.stableIdOf(idx, sendKey)
            val sid = aliasTarget(derived) ?: derived
            val row = loadRow(cb, sid) ?: return false
            if (row.state != SqlSchema.STATE_NORMAL) return false
            requireDb().transaction { tombstoneRows(cb, listOf(sid)) }
            emit(LocalChatEvent.Deleted(convKey, sid))
            return true
        }
    }

    /**
     * `historyDeleteConversation`: tombstones every live message of one conversation, then removes that conversation's index row and its
     * layout rows (§25.52AC.3), in one transaction. Other conversations, and messages that arrive later, are not touched. Returns true when
     * something was removed (a live message, or the index row); false when the conversation is absent (idempotent).
     */
    fun tombstoneConversation(convKey: String): Boolean {
        synchronized(lock) {
            requireKey()
            val cb = LocalChatIds.convBlind(requireIdxKey(), convKey)
            val d = requireDb()
            val (live, existed) = d.transaction {
                val live = d.query("SELECT stable_id FROM msg WHERE conv_blind = ? AND state = ?", arrayOf(cb, SqlSchema.STATE_NORMAL.toLong()))
                    .map { it[0] as String }
                val existed = (d.query("SELECT COUNT(*) FROM conv WHERE conv_blind = ?", arrayOf(cb)).first()[0] as Long) > 0L
                tombstoneRows(cb, live)
                d.execute("DELETE FROM conv WHERE conv_blind = ?", arrayOf(cb))
                d.execute("DELETE FROM layout WHERE conv_blind = ?", arrayOf(cb))
                Pair(live, existed)
            }
            windows.remove(convKey)
            for (sid in live) emit(LocalChatEvent.Deleted(convKey, sid))
            val deleted = live.isNotEmpty() || existed
            if (deleted) bumpEpoch()
            return deleted
        }
    }

    /** The tombstone write for each row: body and metadata gone, layout rows removed (§25.52AC.2). Called inside a transaction. */
    private fun tombstoneRows(cb: String, sids: List<String>) {
        val d = requireDb()
        for (sid in sids) {
            d.execute(
                "UPDATE msg SET state = ?, body_enc = NULL, meta_enc = NULL WHERE conv_blind = ? AND stable_id = ?",
                arrayOf(SqlSchema.STATE_TOMBSTONE.toLong(), cb, sid),
            )
            removeLayouts(cb, sid)
        }
    }

    /** Test helper: the state of the row for [sendKey] (0 live, 1 tombstone, 2 superseded), or null when there is no row. */
    internal fun stateOfSendKey(convKey: String, sendKey: String): Int? {
        synchronized(lock) {
            val idx = requireIdxKey()
            val cb = LocalChatIds.convBlind(idx, convKey)
            val derived = LocalChatIds.stableIdOf(idx, sendKey)
            val sid = aliasTarget(derived) ?: derived
            return loadRow(cb, sid)?.state
        }
    }

    // ---- clearing (spec 10, T-12) ----------------------------------------------------

    /** Clear one conversation; pending rows are kept and counted; dbEpoch changes (T-12). */
    fun clearConversation(convKey: String): Int = synchronized(lock) {
        requireKey()
        val cb = LocalChatIds.convBlind(requireIdxKey(), convKey)
        val d = requireDb()
        val kept = d.transaction {
            val n = (d.query("SELECT COUNT(*) FROM msg WHERE conv_blind = ? AND pending_publish = 1", arrayOf(cb)).first()[0] as Long).toInt()
            d.execute("DELETE FROM msg WHERE conv_blind = ? AND pending_publish = 0", arrayOf(cb))
            d.execute("DELETE FROM layout WHERE conv_blind = ? AND stable_id NOT IN (SELECT stable_id FROM msg WHERE conv_blind = ?)", arrayOf(cb, cb))
            d.execute("DELETE FROM conv WHERE conv_blind = ? AND NOT EXISTS (SELECT 1 FROM msg WHERE msg.conv_blind = conv.conv_blind)", arrayOf(cb))
            n
        }
        windows.remove(convKey)
        bumpEpoch()
        emit(LocalChatEvent.Cleared("conversation", convKey, kept))
        kept
    }

    /** Clear the whole account database, then the next sync is a full sync (headIndexHash cleared). */
    fun clearAccount(): Int = synchronized(lock) {
        requireKey()
        val d = requireDb()
        val kept = d.transaction {
            val n = (d.query("SELECT COUNT(*) FROM msg WHERE pending_publish = 1").first()[0] as Long).toInt()
            d.execute("DELETE FROM msg WHERE pending_publish = 0")
            d.execute("DELETE FROM layout WHERE NOT EXISTS (SELECT 1 FROM msg m WHERE m.conv_blind = layout.conv_blind AND m.stable_id = layout.stable_id)")
            d.execute("DELETE FROM alias")
            d.execute("DELETE FROM conv WHERE NOT EXISTS (SELECT 1 FROM msg WHERE msg.conv_blind = conv.conv_blind)")
            n
        }
        windows.clear()
        setMeta("headIndexHash", "")
        bumpEpoch()
        emit(LocalChatEvent.Cleared("account", null, kept))
        kept
    }

    fun rowCount(convKey: String): Int = synchronized(lock) {
        val cb = LocalChatIds.convBlind(requireIdxKey(), convKey)
        (requireDb().query("SELECT COUNT(*) FROM msg WHERE conv_blind = ? AND state = 0", arrayOf(cb)).first()[0] as Long).toInt()
    }

    fun pendingCount(): Int = synchronized(lock) {
        requireKey()
        (requireDb().query("SELECT COUNT(*) FROM msg WHERE pending_publish = 1 AND state = 0").first()[0] as Long).toInt()
    }

    fun setHeadIndexHash(hash: String?) = synchronized(lock) {
        requireKey()
        setMeta("headIndexHash", hash ?: "")
    }

    // ---- paging ----------------------------------------------------------------------

    /**
     * One page from [before] (spec r3a 6.2–6.4; oracle `openPage`). Visible heights accumulate toward
     * older rows until the sum reaches heightPt (the last row may cross). Tombstones count as 0 and advance
     * the cursor. Raw rows are read in batches of [PAGE_BATCH] by key range (7.4); the raw-row budget and
     * the visible cap apply to every page.
     */
    private fun readPage(convKey: String, before: RowKey?, vp: LocalViewport, first: Boolean): LocalPage {
        val cb = LocalChatIds.convBlind(requireIdxKey(), convKey)
        val items = ArrayList<PageItem>()
        var sum = 0.0
        var scanned = 0
        var capped = false
        var scanExhausted = false
        var windowHi: RowKey? = null
        var windowLo: RowKey? = null
        var cursor: Pair<Long, String>? = before?.let { Pair(it.sortTs, it.stableId) }
        var done = false
        while (!done) {
            val batch = pageBatch(cb, cursor, PAGE_BATCH)
            if (batch.isEmpty()) break
            for (r in batch) {
                scanned++
                val rk = RowKey(convKey, r.sortTs, r.stable)
                if (windowHi == null) windowHi = rk
                windowLo = rk
                var stop = false
                if (r.state == SqlSchema.STATE_NORMAL) {
                    val item = buildItem(convKey, r, vp)
                    items.add(item)
                    sum += item.layoutH
                    if (sum >= vp.heightPt) {
                        stop = true
                    } else if (items.size >= CAP) {
                        capped = true
                        stop = true
                    }
                }
                if (stop) {
                    done = true
                    break
                }
                if (scanned >= SCAN_BUDGET) {
                    scanExhausted = true
                    done = true
                    break
                }
            }
            cursor = batch.last().let { Pair(it.sortTs, it.stable) }
            if (batch.size < PAGE_BATCH) done = true
        }
        val lastScanned = windowLo
        val rawRemain = lastScanned != null &&
            pageBatch(cb, Pair(lastScanned.sortTs, lastScanned.stableId), 1).isNotEmpty()
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

    private fun pageBatch(cb: String, cursor: Pair<Long, String>?, limit: Int): List<Row> {
        val rows = requireDb().query(
            SqlSchema.pageSql(hasCursor = cursor != null),
            if (cursor == null) arrayOf(cb, limit.toLong())
            else arrayOf(cb, cursor.first, cursor.first, cursor.second, limit.toLong()),
        )
        return rows.map { r -> rowOf(cb, r) }
    }

    private fun buildItem(convKey: String, r: Row, vp: LocalViewport): PageItem {
        val k = requireKey()
        val cb = LocalChatIds.convBlind(requireIdxKey(), convKey)
        val meta = r.metaEnc?.let { RowMeta.from(openMetaJson(cb, r.stable, it)) }
            ?: RowMeta(LocalMediaKind.TEXT, "in", null, null, null, null, false)
        val body = if (meta.kind == LocalMediaKind.TEXT || meta.kind == LocalMediaKind.SYSTEM) {
            r.bodyEnc?.let { String(open(k, bodyAad(cb, r.stable, r.revision), it), Charsets.UTF_8) }
        } else {
            null
        }
        val failed = failedMedia.contains(indexKey(convKey, r.stable)) || meta.failed
        val measured = loadLayout(cb, r.stable, layoutKey(vp))
        val (w, h, isMeasured) = if (measured != null) {
            Triple(measured.first, measured.second, true)
        } else {
            val est = LocalChatLayout.estimate(meta.kind, meta.media?.w, meta.media?.h, failed, body, vp)
            Triple(est.first, est.second, false)
        }
        return PageItem(
            stableId = r.stable, sortTs = r.sortTs, dir = meta.dir, sendId = meta.sendId,
            kind = meta.kind, body = body, revision = r.revision,
            layoutW = w, layoutH = h, measured = isMeasured,
            mediaCid = meta.media?.blob, mediaMime = meta.media?.mime, widthPx = meta.media?.w, heightPx = meta.media?.h,
            mediaState = if (meta.kind == LocalMediaKind.IMAGE || meta.kind == LocalMediaKind.VIDEO || meta.kind == LocalMediaKind.FILE || meta.kind == LocalMediaKind.UNKNOWN) {
                if (failed) "failed" else "pending"
            } else {
                null
            },
            messageId = meta.sendKey,
        )
    }

    private fun emitInserted(convKey: String, cb: String, row: Row) {
        val w = windows[convKey] ?: return
        val key = RowKey(convKey, row.sortTs, row.stable)
        val oldest = w.oldest
        if (oldest != null && RowKeyOrder.compare(key, oldest) < 0) return
        val position = if (w.newest == null || RowKeyOrder.compare(key, w.newest) > 0) "tail" else "middle"
        val item = buildItem(convKey, row, windowViewports[convKey] ?: DEFAULT_VIEWPORT)
        emit(LocalChatEvent.Inserted(convKey, listOf(item), position))
        if (position == "tail") windows[convKey] = w.copy(newest = key)
    }

    // ---- row storage -----------------------------------------------------------------

    private fun insertRow(
        cb: String, convKey: String, sid: String, sortTs: Long, revision: Int,
        deleted: Boolean, pending: Boolean, cidBlind: String?, body: String?, meta: RowMeta?,
    ) {
        val k = requireKey()
        val d = requireDb()
        d.execute("INSERT OR IGNORE INTO conv (conv_blind, meta_enc) VALUES (?, ?)",
            arrayOf(cb, seal(k, "conv|$cb".toByteArray(Charsets.UTF_8), JSONObject().put("c", convKey).toString().toByteArray(Charsets.UTF_8))))
        convKeyOf[cb] = convKey
        val bodyEnc = if (!deleted && body != null) seal(k, bodyAad(cb, sid, revision), body.toByteArray(Charsets.UTF_8)) else null
        val metaEnc = if (!deleted && meta != null) sealMeta(cb, sid, meta) else null
        d.execute(
            "INSERT INTO msg (conv_blind, stable_id, sort_ts, revision, state, pending_publish, cid_blind, body_enc, meta_enc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            arrayOf(cb, sid, sortTs, revision.toLong(), (if (deleted) SqlSchema.STATE_TOMBSTONE else SqlSchema.STATE_NORMAL).toLong(),
                (if (pending) 1L else 0L), cidBlind, bodyEnc, metaEnc),
        )
    }

    private class Row(
        val cb: String,
        val stable: String,
        val sortTs: Long,
        val revision: Int,
        val state: Int,
        val pending: Boolean,
        val cidBlind: String?,
        val bodyEnc: ByteArray?,
        val metaEnc: ByteArray?,
    )

    private fun rowOf(cb: String, r: Array<Any?>): Row = Row(
        cb = cb,
        stable = r[0] as String,
        sortTs = r[1] as Long,
        revision = (r[2] as Long).toInt(),
        state = (r[3] as Long).toInt(),
        pending = (r[4] as Long) == 1L,
        cidBlind = r[5] as String?,
        bodyEnc = r[6] as ByteArray?,
        metaEnc = r[7] as ByteArray?,
    )

    private fun loadRow(cb: String, sid: String): Row? {
        val rows = requireDb().query(
            "SELECT stable_id, sort_ts, revision, state, pending_publish, cid_blind, body_enc, meta_enc FROM msg WHERE conv_blind = ? AND stable_id = ? LIMIT 1",
            arrayOf(cb, sid),
        )
        return rows.firstOrNull()?.let { rowOf(cb, it) }
    }

    private fun loadRowByCid(cb: String, cidBlind: String): Row? {
        val rows = requireDb().query(
            "SELECT stable_id, sort_ts, revision, state, pending_publish, cid_blind, body_enc, meta_enc FROM msg WHERE conv_blind = ? AND cid_blind = ? LIMIT 1",
            arrayOf(cb, cidBlind),
        )
        return rows.firstOrNull()?.let { rowOf(cb, it) }
    }

    private fun digestSurvivor(cb: String, sortTs: Long, digest: String, exclude: String): String? {
        val rows = requireDb().query(
            "SELECT stable_id, meta_enc FROM msg WHERE conv_blind = ? AND sort_ts = ? AND state = 0",
            arrayOf(cb, sortTs),
        )
        for (r in rows) {
            val sid = r[0] as String
            if (sid == exclude) continue
            val meta = openMetaJson(cb, sid, r[1] as? ByteArray ?: continue)
            if (meta.optString("dg") == digest) return sid
        }
        return null
    }

    private fun aliasTarget(derived: String): String? {
        val rows = requireDb().query("SELECT target_enc FROM alias WHERE alias_blind = ?", arrayOf(derived))
        val blob = rows.firstOrNull()?.get(0) as? ByteArray ?: return null
        return String(open(requireKey(), "alias|$derived".toByteArray(Charsets.UTF_8), blob), Charsets.UTF_8)
    }

    private fun putAlias(derived: String, survivor: String) {
        val blob = seal(requireKey(), "alias|$derived".toByteArray(Charsets.UTF_8), survivor.toByteArray(Charsets.UTF_8))
        requireDb().execute("INSERT OR REPLACE INTO alias (alias_blind, target_enc) VALUES (?, ?)", arrayOf(derived, blob))
    }

    private fun removeLayouts(cb: String, sid: String) {
        requireDb().execute("DELETE FROM layout WHERE conv_blind = ? AND stable_id = ?", arrayOf(cb, sid))
    }

    private fun loadLayout(cb: String, sid: String, lk: String): Pair<Double, Double>? {
        val rows = requireDb().query("SELECT val_enc FROM layout WHERE conv_blind = ? AND stable_id = ? AND layout_key = ?", arrayOf(cb, sid, lk))
        val blob = rows.firstOrNull()?.get(0) as? ByteArray ?: return null
        val o = JSONObject(String(open(requireKey(), layoutAad(cb, sid, lk), blob), Charsets.UTF_8))
        return Pair(o.getDouble("w"), o.getDouble("h"))
    }

    private fun convKeyFor(cb: String): String {
        convKeyOf[cb]?.let { return it }
        val rows = requireDb().query("SELECT meta_enc FROM conv WHERE conv_blind = ?", arrayOf(cb))
        val blob = rows.firstOrNull()?.get(0) as? ByteArray ?: return ""
        val c = JSONObject(String(open(requireKey(), "conv|$cb".toByteArray(Charsets.UTF_8), blob), Charsets.UTF_8)).getString("c")
        convKeyOf[cb] = c
        return c
    }

    // ---- metadata and sealing --------------------------------------------------------

    /** Kind, direction, sendKey, digest and media fields of a row, sealed with the row (spec 7.8). */
    private data class RowMeta(
        val kind: LocalMediaKind,
        val dir: String,
        val sendId: String?,
        val sendKey: String?,
        val digest: String?,
        val media: MediaMeta?,
        val failed: Boolean,
    ) {
        companion object {
            fun from(o: JSONObject): RowMeta {
                val m = o.optJSONObject("m")
                val media = m?.let {
                    MediaMeta(
                        blob = it.optString("blob").takeIf { s -> s.isNotEmpty() },
                        mime = it.optString("mime").takeIf { s -> s.isNotEmpty() },
                        w = if (it.isNull("w")) null else it.optInt("w"),
                        h = if (it.isNull("h")) null else it.optInt("h"),
                        size = if (it.isNull("size")) null else it.optLong("size"),
                        name = it.optString("name").takeIf { s -> s.isNotEmpty() },
                        failed = it.optBoolean("f", false),
                    )
                }
                return RowMeta(
                    kind = LocalMediaKind.valueOf(o.optString("k", "TEXT")),
                    dir = o.optString("d", "in"),
                    sendId = o.optString("sid").takeIf { it.isNotEmpty() },
                    sendKey = o.optString("sk").takeIf { it.isNotEmpty() },
                    digest = o.optString("dg").takeIf { it.isNotEmpty() },
                    media = media,
                    failed = o.optBoolean("ff", false),
                )
            }
        }

        fun toJson(): JSONObject {
            val o = JSONObject()
                .put("k", kind.name)
                .put("d", dir)
                .put("sid", sendId ?: "")
                .put("sk", sendKey ?: "")
                .put("dg", digest ?: "")
                .put("ff", failed)
            media?.let {
                o.put(
                    "m",
                    JSONObject()
                        .put("blob", it.blob ?: "")
                        .put("mime", it.mime ?: "")
                        .put("w", it.w ?: JSONObject.NULL)
                        .put("h", it.h ?: JSONObject.NULL)
                        .put("size", it.size ?: JSONObject.NULL)
                        .put("name", it.name ?: "")
                        .put("f", it.failed),
                )
            }
            return o
        }
    }

    private data class MediaMeta(
        val blob: String?,
        val mime: String?,
        val w: Int?,
        val h: Int?,
        val size: Long?,
        val name: String?,
        val failed: Boolean,
    )

    private fun mediaOf(parsed: ParsedBody): MediaMeta? {
        if (parsed.kind == LocalMediaKind.TEXT) return null
        return MediaMeta(parsed.blob, parsed.mime, parsed.width, parsed.height, parsed.size, parsed.name, parsed.failed)
    }

    private fun parseBody(body: String): ParsedBody {
        val parse = mediaParser ?: return ParsedBody(LocalMediaKind.UNKNOWN, failed = true, error = "media_parser_missing")
        return parse(body.toByteArray(Charsets.UTF_8))
    }

    private fun sealMeta(cb: String, sid: String, meta: RowMeta): ByteArray =
        seal(requireKey(), "$cb\u001f$sid".toByteArray(Charsets.UTF_8), meta.toJson().toString().toByteArray(Charsets.UTF_8))

    private fun openMetaJson(cb: String, sid: String, blob: ByteArray): JSONObject =
        JSONObject(String(open(requireKey(), "$cb\u001f$sid".toByteArray(Charsets.UTF_8), blob), Charsets.UTF_8))

    private fun bodyAad(cb: String, sid: String, revision: Int): ByteArray =
        "$cb\u001f$sid\u001f$revision".toByteArray(Charsets.UTF_8)

    private fun layoutAad(cb: String, sid: String, lk: String): ByteArray =
        "$cb\u001f$sid\u001f$lk".toByteArray(Charsets.UTF_8)

    private fun cidBlind(idx: ByteArray, cid: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(idx, "HmacSHA256"))
        return LocalChatIds.base64Url(mac.doFinal(cid.toByteArray(Charsets.UTF_8)))
    }

    private fun layoutKey(vp: LocalViewport): String {
        val idx = requireIdxKey()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(idx, "HmacSHA256"))
        val text = "${LocalChatLayout.widthBucket(vp.widthPt)}|${vp.orientation}|${LocalChatLayout.fontBucket(vp.fontScale)}|${vp.layoutVersion}"
        return LocalChatIds.base64Url(mac.doFinal(text.toByteArray(Charsets.UTF_8)))
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

    private fun newEpoch(): String {
        val b = ByteArray(8).also { rng.nextBytes(it) }
        return b.joinToString("") { "%02x".format(it) }
    }

    // ---- cursor ----------------------------------------------------------------------

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

    private fun indexKey(convKey: String, sid: String): String = "$convKey\u0000$sid"

    private fun emit(e: LocalChatEvent) {
        for (l in listeners.toList()) l(e)
    }

    private data class Window(val oldest: RowKey?, val newest: RowKey?, val opened: Boolean)

    companion object {
        const val SCHEMA_VERSION = SqlSchema.SCHEMA_VERSION
        /** Safety cap on consumed rows for the first screen (spec r3a 6.2). */
        const val CAP = 200
        /** Raw-row budget for one scan (spec r3a 6.3). */
        const val SCAN_BUDGET = 2000
        /** Raw rows fetched per key-range query (spec r3a 6.3). */
        const val PAGE_BATCH = 64
        private val DEFAULT_VIEWPORT = LocalViewport(390.0, 844.0, "portrait", 1.0, 1)
    }
}

/** Key of a row inside the store: conversation, sort key (spec r3a 3). */
data class RowKey(val convKey: String, val sortTs: Long, val stableId: String)

/** Sort order of K (spec r3a 5): sort_ts numeric, then stable_id by UTF-8 bytes; conversation first. */
object RowKeyOrder : Comparator<RowKey> {
    override fun compare(a: RowKey, b: RowKey): Int {
        val c = LocalChatIds.compareUtf8(a.convKey, b.convKey)
        return if (c != 0) c else LocalChatIds.compareKey(a.sortTs, a.stableId, b.sortTs, b.stableId)
    }
}

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
    /** sendKey for tombstones and revisions that reference it (spec r3a 4.1). */
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
    /** A database error during unlock (the file is not readable with this key or is damaged). */
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
    /** The row's sendKey (§25.52AC.2): the `messageId` that `historyDeleteMessage` takes. Null for a row without one. */
    val messageId: String? = null,
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
    /** more | pending | end (spec r3a 6.4). */
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
    data class Inserted(val convKey: String, val items: List<PageItem>, val position: String) : LocalChatEvent()
    data class Updated(val convKey: String, val stableId: String, val revision: Int) : LocalChatEvent()
    data class Deleted(val convKey: String, val stableId: String) : LocalChatEvent()
    data class Cleared(val scope: String, val convKey: String?, val pendingKept: Int) : LocalChatEvent()
    /** A late older row reached a conversation whose last page ended at a pending cursor (spec 6.4). */
    data class OlderAvailable(val convKey: String) : LocalChatEvent()
    /** The page must clear what it shows now (spec 6.5 step 2). */
    object Locked : LocalChatEvent()
}

/** One row of a migration import (spec r3a 11.2). */
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
