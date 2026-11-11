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
class LocalChatStore(val accountKey: String) {
    private val lock = Any()
    private val rng = SecureRandom()

    private var dek: ByteArray? = null
    private var idKey: ByteArray? = null
    private var kcv: ByteArray? = null
    private var epoch: String = newEpoch()
    private var headIndexHash: String? = null

    private val rows = TreeMap<RowKey, StoredRow>(rowComparator)
    private val byStable = HashMap<String, RowKey>()
    private val layouts = HashMap<LayoutKey, LayoutValue>()
    private val failedMedia = HashSet<String>()
    private val windows = HashMap<String, Window>()
    private val listeners = ArrayList<(LocalChatEvent) -> Unit>()
    private val corrector = LocalChatLayoutCorrector()

    /** Count of sync records whose sortTs differed from the stored one (spec 5, counted only). */
    var tsMismatchCount: Int = 0
        private set

    val isUnlocked: Boolean get() = synchronized(lock) { dek != null }

    // ---- lock / unlock / persistence --------------------------------------------------

    /**
     * Derive the DEK and open the store. [snapshot] is the bytes of the last [snapshot] call,
     * or null for a new account. Follows spec 7.3 (kcv mismatch) and 7.5 (schema).
     */
    fun unlock(master: ByteArray, snapshot: ByteArray?): UnlockResult {
        return synchronized(lock) {
        val key = hkdf(master, "chat-local-db-v1|$accountKey")
        val mac = hmac(key, "kcv".toByteArray(Charsets.UTF_8))
        if (snapshot == null) {
            resetMemory()
            dek = key
            idKey = LocalChatIds.idKey(master)
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
            idKey = LocalChatIds.idKey(master)
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
        idKey = LocalChatIds.idKey(master)
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
        val blob = seal(k, snapshotAad(m), payload.toString().toByteArray(Charsets.UTF_8))
        val header = JSONObject()
            .put("fmt", FORMAT_TAG)
            .put("schema", SCHEMA_VERSION)
            .put("kcv", ConetChatCryptoUtil.toHex(m))
            .put("pending", rows.values.count { it.pendingPublish && !it.deleted })
        header.toString().toByteArray(Charsets.UTF_8) + byteArrayOf('\n'.code.toByte()) + blob
    }

    /** Logout (spec D2): drop DEK, identity key and every decrypted or in-memory structure. */
    fun lock() = synchronized(lock) { lockMemory() }

    // ---- sync write path (called by the single sync writer) ---------------------------

    /**
     * Apply one source record (spec 5 and 9.2 rules). The caller has already downloaded and
     * decrypted the body when [IncomingRecord.body] is needed.
     */
    fun applyRecord(convKey: String, rec: IncomingRecord, pendingPublish: Boolean = false): ApplyResult {
        return synchronized(lock) {
        val k = requireKey()
        val sid = rec.stableIdHint
            ?: rec.sendId?.takeIf { it.isNotEmpty() }
            ?: rec.body?.let { LocalChatIds.stableId(requireIdKey(), convKey, rec.dir, rec.sortTs, it, null) }
            ?: return ApplyResult.REJECTED
        val existingKey = byStable[indexKey(convKey, sid)]
        val existing = existingKey?.let { rows[it] }
        if (existing == null) {
            if (rec.deleted) {
                insertRow(convKey, sid, rec, null, pendingPublish, deleted = true)
                return ApplyResult.TOMBSTONED
            }
            val body = rec.body ?: return ApplyResult.REJECTED
            val row = insertRow(convKey, sid, rec, body, pendingPublish, deleted = false)
            emitInserted(row, k)
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
            existing.cid = rec.cid ?: existing.cid
            setMedia(existing, rec)
            removeLayouts(convKey, sid)
            emit(LocalChatEvent.Updated(convKey, sid, rec.revision))
            return ApplyResult.UPDATED
        }
        if (rec.revision == existing.revision && rec.cid != null && rec.cid != existing.cid) {
            existing.cid = rec.cid
            return ApplyResult.CID_ONLY
        }
        ApplyResult.SKIPPED
        }
    }

    // ---- read path (never touches the network, never waits for sync) -----------------

    /** First screen: newest rows, filling `heightPt × 1.5` with 8..80 items (spec 6.2). */
    fun openConversation(convKey: String, vp: LocalViewport): LocalPage {
        return synchronized(lock) {
        if (dek == null) return LocalPage(emptyList(), null, false, LocalSource.LOCKED, "locked")
        sweepLayouts(vp.layoutVersion)
        val page = readPage(convKey, null, vp)
        windowViewports[convKey] = vp
        windows[convKey] = Window(
            oldest = page.items.firstOrNull()?.let { keyOf(convKey, it) },
            newest = page.items.lastOrNull()?.let { keyOf(convKey, it) },
            opened = true,
        )
        page
        }
    }

    /** Older page strictly before [cursor] (spec 6.2). Cursor from another epoch is refused. */
    fun loadOlder(convKey: String, cursor: String, vp: LocalViewport): LocalPage {
        return synchronized(lock) {
        if (dek == null) return LocalPage(emptyList(), null, false, LocalSource.LOCKED, "locked")
        val before = decodeCursor(cursor, convKey)
            ?: return LocalPage(emptyList(), null, false, LocalSource.LOCKED, "cursor_invalid")
        val page = readPage(convKey, before, vp)
        windowViewports[convKey] = vp
        val w = windows[convKey]
        if (w != null && page.items.isNotEmpty()) {
            windows[convKey] = w.copy(oldest = keyOf(convKey, page.items.first()))
        }
        page
        }
    }

    /** UI measured a media item (spec 8.2). Writes only real measurements; estimates are never stored. */
    fun reportLayout(convKey: String, stableId: String, vp: LocalViewport, wPt: Double, hPt: Double): Boolean {
        return synchronized(lock) {
        requireKey()
        val rk = byStable[indexKey(convKey, stableId)] ?: return false
        val row = rows[rk] ?: return false
        if (row.deleted) return false
        val key = layoutKey(convKey, stableId, vp)
        val prev = layouts[key]
        val est = estimateFor(row, vp).second
        corrector.observe(LocalChatLayout.widthBucket(vp.widthPt), est, hPt)
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

    private fun resetMemory() {
        rows.clear(); byStable.clear(); layouts.clear(); failedMedia.clear(); windows.clear()
        headIndexHash = null
        tsMismatchCount = 0
        epoch = newEpoch()
    }

    private fun lockMemory() {
        dek = null; idKey = null; kcv = null
        rows.clear(); byStable.clear(); layouts.clear(); failedMedia.clear(); windows.clear()
    }

    private fun insertRow(
        convKey: String, sid: String, rec: IncomingRecord, body: String?,
        pending: Boolean, deleted: Boolean,
    ): StoredRow {
        val k = requireKey()
        val row = StoredRow(
            convKey = convKey, stableId = sid, sortTs = rec.sortTs, dir = rec.dir,
            sendId = rec.sendId?.takeIf { it.isNotEmpty() }, kind = rec.kind, cid = rec.cid,
            revision = rec.revision, deleted = deleted, bodyEnc = null, mediaEnc = null,
            pendingPublish = pending,
        )
        if (!deleted && body != null) row.bodyEnc = seal(k, bodyAad(convKey, sid, rec.revision), body.toByteArray(Charsets.UTF_8))
        setMedia(row, rec)
        val key = RowKey(convKey, rec.sortTs, sid)
        rows[key] = row
        byStable[indexKey(convKey, sid)] = key
        return row
    }

    private fun setMedia(row: StoredRow, rec: IncomingRecord) {
        val k = requireKey()
        if (rec.mediaCid == null && rec.widthPx == null && rec.heightPx == null && rec.mime == null) return
        val m = JSONObject()
            .put("cid", rec.mediaCid ?: JSONObject.NULL)
            .put("mime", rec.mime ?: JSONObject.NULL)
            .put("w", rec.widthPx ?: JSONObject.NULL)
            .put("h", rec.heightPx ?: JSONObject.NULL)
        row.mediaEnc = seal(k, mediaAad(row.convKey, row.stableId, row.revision), m.toString().toByteArray(Charsets.UTF_8))
    }

    private fun tombstone(row: StoredRow) {
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
            removeLayouts(row.convKey, row.stableId)
        }
        return kept
    }

    private fun removeLayouts(convKey: String, sid: String) {
        layouts.keys.removeAll { it.convKey == convKey && it.stableId == sid }
    }

    /** Lazily drop size records of older layout versions (spec 8.5). */
    private fun sweepLayouts(currentVersion: Int) {
        layouts.keys.removeAll { it.layoutVersion != currentVersion }
    }

    private fun readPage(convKey: String, before: RowKey?, vp: LocalViewport): LocalPage {
        val target = vp.heightPt * 1.5
        val hi = before ?: RowKey(convKey + "\u0000", Long.MIN_VALUE, "")
        val items = ArrayList<PageItem>()
        var est = 0.0
        var last: StoredRow? = null
        for (row in rows.headMap(hi, false).descendingMap().values) {
            if (row.convKey != convKey) break
            last = row
            if (row.deleted) continue
            val item = buildItem(row, vp)
            items.add(item)
            est += item.layoutH
            if (items.size >= MAX_PAGE_ITEMS) break
            if (items.size >= MIN_PAGE_ITEMS && est >= target) break
        }
        val lastKey = last?.key
        val hasOlder = lastKey != null && rows.lowerKey(lastKey)?.convKey == convKey
        val olderCursor = lastKey?.takeIf { hasOlder }?.let { encodeCursor(it) }
        items.reverse()
        return LocalPage(items, olderCursor, hasOlder, LocalSource.LOCAL, null)
    }

    private fun buildItem(row: StoredRow, vp: LocalViewport): PageItem {
        val wB = LocalChatLayout.widthBucket(vp.widthPt)
        val measured = layouts[layoutKey(row.convKey, row.stableId, vp)]
        val (w, h, isMeasured) = if (measured != null) {
            Triple(measured.wPt, measured.hPt, true)
        } else {
            val est = estimateFor(row, vp)
            Triple(est.first, corrector.correct(wB, est.second), false)
        }
        val media = mediaOf(row)
        val body = if (row.kind == LocalMediaKind.TEXT || row.kind == LocalMediaKind.SYSTEM) bodyOf(row) else null
        val failed = failedMedia.contains(indexKey(row.convKey, row.stableId))
        return PageItem(
            stableId = row.stableId, sortTs = row.sortTs, dir = row.dir, sendId = row.sendId,
            kind = row.kind, body = body, revision = row.revision,
            layoutW = w, layoutH = h, measured = isMeasured,
            mediaCid = media?.cid, mediaMime = media?.mime, widthPx = media?.w, heightPx = media?.h,
            mediaState = if (row.kind == LocalMediaKind.IMAGE || row.kind == LocalMediaKind.VIDEO || row.kind == LocalMediaKind.FILE) {
                if (failed) "failed" else "pending"
            } else null,
        )
    }

    private fun estimateFor(row: StoredRow, vp: LocalViewport): Pair<Double, Double> {
        val media = mediaOf(row)
        return LocalChatLayout.estimate(
            row.kind, media?.w, media?.h,
            failedMedia.contains(indexKey(row.convKey, row.stableId)), vp,
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

    private fun encodeCursor(key: RowKey): String =
        LocalChatIds.base64Url("$epoch|${key.sortTs}|${key.stableId}".toByteArray(Charsets.UTF_8))

    private fun decodeCursor(cursor: String, convKey: String): RowKey? {
        val text = try { String(base64UrlDecode(cursor), Charsets.UTF_8) } catch (e: Exception) { return null }
        val parts = text.split("|", limit = 3)
        if (parts.size != 3 || parts[0] != epoch) return null
        val ts = parts[1].toLongOrNull() ?: return null
        return RowKey(convKey, ts, parts[2])
    }

    private fun layoutKey(convKey: String, sid: String, vp: LocalViewport) = LayoutKey(
        convKey, sid, LocalChatLayout.widthBucket(vp.widthPt), vp.orientation,
        LocalChatLayout.fontBucket(vp.fontScale), vp.layoutVersion,
    )

    private fun loadPayload(o: JSONObject): Boolean {
        return try {
            epoch = o.getString("epoch")
            headIndexHash = if (o.isNull("headIndexHash")) null else o.getString("headIndexHash")
            val rowArr = o.getJSONArray("rows")
            for (i in 0 until rowArr.length()) {
                val r = StoredRow.fromJson(rowArr.getJSONObject(i))
                val key = RowKey(r.convKey, r.sortTs, r.stableId)
                rows[key] = r
                byStable[indexKey(r.convKey, r.stableId)] = key
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
    ) {
        val key: RowKey get() = RowKey(convKey, sortTs, stableId)

        fun toJson(): JSONObject = JSONObject()
            .put("c", convKey).put("s", stableId).put("t", sortTs).put("d", dir)
            .put("sid", sendId ?: JSONObject.NULL).put("k", kind.name).put("cid", cid ?: JSONObject.NULL)
            .put("r", revision).put("del", deleted)
            .put("b", bodyEnc?.let { ConetChatCryptoUtil.toHex(it) } ?: JSONObject.NULL)
            .put("m", mediaEnc?.let { ConetChatCryptoUtil.toHex(it) } ?: JSONObject.NULL)
            .put("p", pendingPublish)

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

    private data class MediaMeta(val cid: String?, val mime: String?, val w: Int?, val h: Int?)

    companion object {
        const val SCHEMA_VERSION = 1
        const val MIN_PAGE_ITEMS = 8
        const val MAX_PAGE_ITEMS = 80
        private const val FORMAT_TAG = "CLS1"
        private val DEFAULT_VIEWPORT = LocalViewport(390.0, 844.0, "portrait", 1.0, 1)

        private val rowComparator = Comparator<RowKey> { a, b ->
            val c = LocalChatIds.compareUtf8(a.convKey, b.convKey)
            if (c != 0) c else LocalChatIds.compareKey(a.sortTs, a.stableId, b.sortTs, b.stableId)
        }

        private fun indexKey(convKey: String, sid: String): String = "$convKey\u0000$sid"
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
    val widthPx: Int? = null,
    val heightPx: Int? = null,
    val mime: String? = null,
    val mediaCid: String? = null,
)

enum class ApplyResult { INSERTED, UPDATED, CID_ONLY, TOMBSTONED, SKIPPED, REJECTED }

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
)

sealed class LocalChatEvent {
    data class Inserted(val convKey: String, val items: List<PageItem>, val position: String) : LocalChatEvent()
    data class Updated(val convKey: String, val stableId: String, val revision: Int) : LocalChatEvent()
    data class Deleted(val convKey: String, val stableId: String) : LocalChatEvent()
    data class Cleared(val scope: String, val convKey: String?, val pendingKept: Int) : LocalChatEvent()
}
