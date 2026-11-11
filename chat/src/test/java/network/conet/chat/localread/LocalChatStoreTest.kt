package network.conet.chat.localread

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM tests for the local read store (interface spec v1.0). Fixtures are synthetic:
 * a deterministic java.util.Random seed, a test master key, and FIXTURE markers.
 * No real chat, key, or media is read. Environment: JVM on the developer host.
 */
class LocalChatStoreTest {

    private val master = ByteArray(32) { (it * 7 + 3).toByte() }
    private val otherMaster = ByteArray(32) { (it * 11 + 5).toByte() }
    private val vp = LocalViewport(390.0, 844.0, "portrait", 1.0, 1)

    private class Msg(
        val conv: String,
        val n: Int,
        val dir: String,
        val sortTs: Long,
        val kind: LocalMediaKind,
        val sendId: String?,
        var body: String,
        val cid: String,
        val w: Int?,
        val h: Int?,
    ) {
        var revised = false
        var deleted = false
    }

    /** Synthetic history: clusters, same-millisecond ties, revisions and tombstones. */
    private fun fixture(seed: Long, convKeys: List<String>, perConv: Int, idKey: ByteArray): Pair<List<Msg>, Map<String, String>> {
        val rnd = java.util.Random(seed)
        val msgs = ArrayList<Msg>()
        for (conv in convKeys) {
            var ts = 1_700_000_000_000L
            for (n in 0 until perConv) {
                if (rnd.nextDouble() >= 0.05) ts += 1L + rnd.nextInt(4000) // else: same-millisecond tie
                val r = rnd.nextDouble()
                val kind = when {
                    r < 0.60 -> LocalMediaKind.TEXT
                    r < 0.85 -> LocalMediaKind.IMAGE
                    r < 0.90 -> LocalMediaKind.VIDEO
                    r < 0.95 -> LocalMediaKind.FILE
                    else -> LocalMediaKind.SYSTEM
                }
                val dir = if (rnd.nextBoolean()) "in" else "out"
                val sendId = if (rnd.nextDouble() < 0.9) "sid-$seed-$conv-$n" else null
                val (w, h) = if (kind == LocalMediaKind.IMAGE || kind == LocalMediaKind.VIDEO) {
                    listOf(Pair(4, 3), Pair(3, 4), Pair(16, 9), Pair(9, 16), Pair(1, 1))[rnd.nextInt(5)].let {
                        Pair(it.first * 100, it.second * 100)
                    }
                } else Pair(null, null)
                // Media bodies are v1 manifests (spec r2 21.1); text is plain UTF-8.
                val body = when (kind) {
                    LocalMediaKind.IMAGE, LocalMediaKind.VIDEO, LocalMediaKind.FILE -> {
                        val kn = kind.name.lowercase()
                        val dims = if (w != null && h != null) ",\"width\":$w,\"height\":$h" else ""
                        "{\"v\":1,\"kind\":\"$kn\",\"text\":\"FIXTURE-$seed-$n\",\"media\":{\"mime\":\"application/octet-stream\",\"size\":1,\"blob\":\"b$n\"$dims}}"
                    }
                    LocalMediaKind.TEXT -> "FIXTURE-$seed-$n hello $n"
                    else -> "FIXTURE-$seed-$n system $n"
                }
                val m = Msg(conv, n, dir, ts, kind, sendId, body, "cid-$seed-$conv-$n", w, h)
                msgs.add(m)
            }
        }
        // Revisions (sendId messages only) and tombstones (0.5%).
        for (m in msgs) {
            if (m.sendId != null && rnd.nextDouble() < 0.01) {
                m.revised = true
                m.body = m.body + " (edited)"
            }
            if (rnd.nextDouble() < 0.005) m.deleted = true
        }
        val idxKey = keysFor(master).second
        val ids = HashMap<String, String>()
        for (m in msgs) {
            val sk = LocalChatIds.sendKey(idKey, m.conv, m.sendId, m.dir, m.sortTs, originalBody(m))!!
            ids[m.conv + "|" + m.n] = LocalChatIds.stableIdOf(idxKey, sk)
        }
        return Pair(msgs, ids)
    }

    /** Body as first delivered (before any revision), needed for content-derived ids. */
    private fun originalBody(m: Msg): String = if (m.revised) m.body.removeSuffix(" (edited)") else m.body

    private fun apply(store: LocalChatStore, msgs: List<Msg>, ids: Map<String, String>) {
        // The synthetic history stands for a finished full sync: older pages end instead of pending.
        store.markSyncComplete()
        for (m in msgs) {
            val r = store.applyRecord(
                m.conv,
                IncomingRecord(m.dir, m.sortTs, m.kind, m.sendId, originalBody(m), m.cid, widthPx = m.w, heightPx = m.h,
                    mime = if (m.w != null) "image/jpeg" else null, mediaCid = if (m.w != null) "m-${m.cid}" else null),
            )
            assertEquals("insert ${m.n}", ApplyResult.INSERTED, r)
        }
        for (m in msgs) {
            if (m.revised) {
                val r = store.applyRecord(m.conv, IncomingRecord(m.dir, m.sortTs, m.kind, m.sendId, m.body, m.cid, revision = 1,
                    widthPx = m.w, heightPx = m.h, mime = null, mediaCid = null))
                assertEquals(ApplyResult.UPDATED, r)
            }
        }
        for (m in msgs) {
            if (m.deleted) {
                val sk = LocalChatIds.sendKey(keysFor(master).first, m.conv, m.sendId, m.dir, m.sortTs, originalBody(m))!!
                val r = store.applyRecord(m.conv, IncomingRecord(m.dir, m.sortTs, m.kind, m.sendId, null, m.cid,
                    deleted = true, sendKeyHint = sk))
                assertEquals(ApplyResult.TOMBSTONED, r)
            }
        }
    }

    /** Expected visible rows for [conv]: not deleted, final body, ascending by (sortTs, stableId). */
    private fun truth(msgs: List<Msg>, conv: String, ids: Map<String, String>): List<Triple<String, Long, String>> =
        msgs.filter { it.conv == conv && !it.deleted }
            .map { Triple(ids[it.conv + "|" + it.n]!!, it.sortTs, if (it.kind == LocalMediaKind.TEXT || it.kind == LocalMediaKind.SYSTEM) it.body else "") }
            .sortedWith { a, b -> LocalChatIds.compareKey(a.second, a.first, b.second, b.first) }

    /** Walks from the newest page to the oldest and returns items ascending. */
    private fun pageAll(store: LocalChatStore, conv: String, v: LocalViewport): Pair<List<PageItem>, Int> {
        var page = store.openConversation(conv, v)
        assertNull(page.error)
        val all = ArrayList<PageItem>()
        all.addAll(0, page.items)
        var pages = 1
        while (page.hasOlder) {
            page = store.loadOlder(conv, page.olderCursor!!, v)
            assertNull(page.error)
            all.addAll(0, page.items)
            pages++
        }
        return Pair(all, pages)
    }

    /** K_id and K_idx for the test account the convenience unlock uses (eoa 0xaaaa, workspace default). */
    private fun keysFor(m: ByteArray): Pair<ByteArray, ByteArray> {
        val rDb = LocalChatIds.rootDbFromPrivateKey(m, "0xaaaa", "default")
        return Pair(LocalChatIds.idKeyFromRootDb(rDb), LocalChatIds.idxKeyFromRootDb(rDb))
    }

    private fun fresh(account: String = "0xaaaa:default"): LocalChatStore {
        val s = LocalChatStore(account)
        assertEquals(UnlockResult.OK, s.unlock(master, null))
        return s
    }

    // ---- ids and ordering ---------------------------------------------------------------

    @Test
    fun sendKeyAndStableIdFollowSpecV11() {
        val k = keysFor(master).first
        val idx = keysFor(master).second
        // Any non-empty sendId is the sendKey, UUID included (spec v1.1-r1 4.1 rule 1).
        assertEquals("abc.def", LocalChatIds.sendKey(k, "c", "abc.def", "in", 1L, "x"))
        val uuid = "123e4567-e89b-12d3-a456-426614174000"
        assertEquals(uuid, LocalChatIds.sendKey(k, "c", uuid, "in", 1L, "x"))
        // Only an empty sendId derives the sendKey from the body.
        assertEquals(LocalChatIds.sendKeyDerived(k, "c", "in", 1L, "x"), LocalChatIds.sendKey(k, "c", "", "in", 1L, "x"))
        assertNull(LocalChatIds.sendKey(k, "c", null, "in", 1L, null))
        // stable_id: 43 ASCII base64url characters, bound to K_idx.
        val sid = LocalChatIds.stableIdOf(idx, "abc.def")
        assertEquals(43, sid.length)
        assertTrue(sid.all { it.isLetterOrDigit() && it.code < 128 || it == '-' || it == '_' })
        assertFalse(sid == LocalChatIds.stableIdOf(keysFor(otherMaster).second, "abc.def"))
    }

    @Test
    fun derivedSendKeyIsDeterministicAndSensitive() {
        val k = keysFor(master).first
        val base = LocalChatIds.sendKeyDerived(k, "c", "in", 100L, "hello")
        assertEquals(base, LocalChatIds.sendKeyDerived(k, "c", "in", 100L, "hello"))
        assertTrue(base.startsWith("x"))
        assertTrue(base.substring(1).all { it.isLetterOrDigit() || it == '-' || it == '_' })
        assertFalse(base == LocalChatIds.sendKeyDerived(k, "c", "out", 100L, "hello"))
        assertFalse(base == LocalChatIds.sendKeyDerived(k, "c", "in", 101L, "hello"))
        assertFalse(base == LocalChatIds.sendKeyDerived(k, "c", "in", 100L, "hellp"))
        assertFalse(base == LocalChatIds.sendKeyDerived(keysFor(otherMaster).first, "c", "in", 100L, "hello"))
    }

    @Test
    fun allTombstonePageKeepsScanningUntilBudgetAndThenContinues() {
        val store = fresh()
        store.applyRecord("0xt", IncomingRecord("in", 1L, LocalMediaKind.TEXT, "keep", "visible", "c0"))
        for (i in 0 until 2100) {
            store.applyRecord("0xt", IncomingRecord("in", 2L + i, LocalMediaKind.TEXT, null, null, null,
                deleted = true, sendKeyHint = "gone-$i"))
        }
        store.markSyncComplete()
        val vp1 = LocalViewport(390.0, 844.0, "portrait", 1.0, 1)
        // The first 2000 raw rows are tombstones: no visible item, and the budget is reported (T-25).
        val first = store.openConversation("0xt", vp1)
        assertTrue(first.items.isEmpty())
        assertTrue(first.scanExhausted)
        assertEquals("more", first.olderState)
        assertNotNull(first.olderCursor)
        // Continuing with the returned cursor reaches the visible row; no page is returned empty as "end".
        val next = store.loadOlder("0xt", first.olderCursor!!, vp1)
        assertEquals(listOf("keep"), next.items.map { it.sendId })
        assertEquals("end", next.olderState)
    }

    @Test
    fun cidMoveIsRecordedWithoutRefetch() {
        val store = fresh()
        store.applyRecord("0xm", IncomingRecord("in", 1L, LocalMediaKind.TEXT, "s1", "body", "c1"))
        // PWA relinearize moves the cid; the held row answers without a body (spec 9.2, T-17).
        assertTrue(store.knowsRemote("0xm", "s1", "c2"))
        assertEquals("body", store.bodyForRemote("0xm", "s1", "c2"))
        // A sendId-less record is found by its cid, and only inside its own conversation.
        store.applyRecord("0xm", IncomingRecord("in", 2L, LocalMediaKind.TEXT, null, "plain", "c9"))
        assertTrue(store.knowsRemote("0xm", null, "c9"))
        assertFalse(store.knowsRemote("0xother", null, "c9"))
    }

    @Test
    fun pendingSyncEndsOnlyAfterFullSyncAndNotifiesOpenWindows() {
        val store = LocalChatStore("0xpend")
        assertEquals(UnlockResult.OK, store.unlock(master, null))
        store.applyRecord("0xp", IncomingRecord("in", 5L, LocalMediaKind.TEXT, "s5", "five", "c5"))
        store.applyRecord("0xp", IncomingRecord("in", 6L, LocalMediaKind.TEXT, "s6", "six", "c6"))
        val events = ArrayList<LocalChatEvent>()
        store.subscribe { events.add(it) }
        // Local rows ran out before the full sync: olderState is pending, not end (T-23).
        val first = store.openConversation("0xp", LocalViewport(390.0, 10000.0, "portrait", 1.0, 1))
        assertEquals("pending", first.olderState)
        assertNotNull(first.olderCursor)
        assertFalse(first.short)
        // A late older row reaches the pending window: olderAvailable, and the page can then continue.
        store.applyRecord("0xp", IncomingRecord("in", 1L, LocalMediaKind.TEXT, "s1", "one", "c1"))
        assertTrue(events.any { it is LocalChatEvent.OlderAvailable && it.convKey == "0xp" })
        store.markSyncComplete()
        val later = store.loadOlder("0xp", first.olderCursor!!, LocalViewport(390.0, 10000.0, "portrait", 1.0, 1))
        assertEquals(listOf("s1"), later.items.map { it.sendId })
        assertEquals("end", later.olderState)
        assertNull(later.olderCursor)
    }

    @Test
    fun sameMillisecondOrdersByUtf8StableId() {
        assertTrue(LocalChatIds.compareKey(5L, "a", 5L, "b") < 0)
        assertTrue(LocalChatIds.compareKey(5L, "é", 5L, "z") > 0) // é is 0xC3 0xA9, above 'z' (0x7A)
        assertTrue(LocalChatIds.compareKey(4L, "zzz", 5L, "a") < 0)
    }

    // ---- T-2, T-3: paging with no loss or duplicate, same-millisecond ties ------------

    @Test
    fun pagingMatchesTruthWithTiesTombstonesAndRevisions() {
        val idKey = keysFor(master).first
        val (msgs, ids) = fixture(20261111L, listOf("0xpeer1", "0xpeer2"), 3000, idKey)
        val store = fresh()
        apply(store, msgs, ids)

        val ties = msgs.groupingBy { it.conv + "|" + it.sortTs }.eachCount().values.count { it > 1 }
        assertTrue("fixture needs same-ms ties", ties > 0)

        val expected = truth(msgs, "0xpeer1", ids)
        val (got, pages) = pageAll(store, "0xpeer1", vp)
        assertTrue("several pages", pages > 3)
        assertEquals(expected.size, got.size)
        assertEquals(got.size, got.map { it.stableId }.toSet().size)
        for (i in expected.indices) {
            assertEquals("stableId at $i", expected[i].first, got[i].stableId)
            assertEquals("sortTs at $i", expected[i].second, got[i].sortTs)
            if (got[i].kind == LocalMediaKind.TEXT) assertEquals(expected[i].third, got[i].body)
        }
        // Items never include tombstones.
        assertTrue(got.none { it.body == null && it.kind == LocalMediaKind.TEXT })
    }

    @Test
    fun firstScreenIsOneViewportWithoutReadAhead() {
        val idKey = keysFor(master).first
        val (msgs, ids) = fixture(7L, listOf("0xp"), 500, idKey)
        val store = fresh()
        apply(store, msgs, ids)
        val page = store.openConversation("0xp", vp)
        assertTrue(page.hasOlder)
        assertFalse(page.short)
        val sum = page.items.sumOf { it.layoutH }
        val last = page.items.first().layoutH // the boundary-crossing row is the oldest one (items ascend)
        // v0.2 6.2: heightPt <= sum <= heightPt + last item, no minimum count, no read-ahead in the payload.
        assertTrue("sum $sum >= heightPt", sum >= vp.heightPt)
        assertTrue("sum $sum - last < heightPt", sum - last < vp.heightPt)
        // A viewport shorter than one row returns exactly one row.
        val tiny = LocalViewport(390.0, 10.0, "portrait", 1.0, 1)
        assertEquals(1, store.openConversation("0xp", tiny).items.size)
    }

    @Test
    fun shortHistoryReturnsEverythingAndFlagsShort() {
        val store = fresh()
        store.applyRecord("0xshort", IncomingRecord("in", 1L, LocalMediaKind.TEXT, "a", "one", "c"))
        store.markSyncComplete()
        val page = store.openConversation("0xshort", vp)
        assertEquals(1, page.items.size)
        assertTrue(page.short)
        assertFalse(page.hasOlder)
        assertFalse(page.capped)
    }

    // ---- T-4: layout cache ----------------------------------------------------------

    @Test
    fun layoutMeasuredOnceIsHitOnSecondVisit() {
        val idKey = keysFor(master).first
        val (msgs, ids) = fixture(11L, listOf("0xq"), 400, idKey)
        val store = fresh()
        apply(store, msgs, ids)
        val first = store.openConversation("0xq", vp)
        for (it in first.items) store.reportLayout("0xq", it.stableId, vp, it.layoutW, it.layoutH * 1.1)
        val second = store.openConversation("0xq", vp)
        val hits = second.items.count { it.measured }
        assertTrue("hit rate ${hits}/${second.items.size}", hits >= second.items.size * 0.95)
        // A 1 pt difference is not written again (tolerance 2 pt) and keeps the value.
        val h0 = second.items.first().layoutH
        assertFalse(store.reportLayout("0xq", second.items.first().stableId, vp, second.items.first().layoutW, h0 + 1.0))
    }

    // ---- T-5: rotation and font size use new keys, old keys kept ----------------------

    @Test
    fun rotationAndFontSwitchKeysAndKeepOldOnes() {
        val idKey = keysFor(master).first
        val (msgs, ids) = fixture(13L, listOf("0xr"), 200, idKey)
        val store = fresh()
        apply(store, msgs, ids)
        val portrait = store.openConversation("0xr", vp)
        for (it in portrait.items) store.reportLayout("0xr", it.stableId, vp, it.layoutW, 77.0)
        val landscape = LocalViewport(844.0, 390.0, "landscape", 1.0, 1)
        val ls = store.openConversation("0xr", landscape)
        assertTrue("landscape starts unmeasured", ls.items.none { it.measured })
        val big = LocalViewport(390.0, 844.0, "portrait", 1.5, 1)
        assertTrue("font change starts unmeasured", store.openConversation("0xr", big).items.none { it.measured })
        assertTrue("portrait measurements kept", store.openConversation("0xr", vp).items.count { it.measured } >= 8)
    }

    // ---- T-10: revision keeps K, invalidates layout; deletion keeps K and paging ------

    @Test
    fun revisionKeepsKeyAndDeletionPagesOn() {
        val store = fresh()
        val rec = IncomingRecord("in", 1000L, LocalMediaKind.TEXT, "sid-x", "v0", "c1")
        assertEquals(ApplyResult.INSERTED, store.applyRecord("0xs", rec))
        val before = store.openConversation("0xs", vp).items.single()
        store.reportLayout("0xs", before.stableId, vp, 300.0, 90.0)
        assertTrue(store.openConversation("0xs", vp).items.single().measured)
        assertEquals(ApplyResult.UPDATED, store.applyRecord("0xs", IncomingRecord("in", 1000L, LocalMediaKind.TEXT, "sid-x", "v1", "c2", revision = 1)))
        val after = store.openConversation("0xs", vp).items.single()
        assertEquals(before.stableId, after.stableId)
        assertEquals(before.sortTs, after.sortTs)
        assertEquals("v1", after.body)
        assertFalse(after.measured)
        // Stale revision is ignored.
        assertEquals(ApplyResult.SKIPPED, store.applyRecord("0xs", IncomingRecord("in", 1000L, LocalMediaKind.TEXT, "sid-x", "v0", "c1", revision = 0)))
        // Tombstone keeps the key and removes the body.
        assertEquals(ApplyResult.TOMBSTONED, store.applyRecord("0xs", IncomingRecord("in", 1000L, LocalMediaKind.TEXT, "sid-x", null, null, deleted = true, sendKeyHint = "sid-x")))
        assertTrue(store.openConversation("0xs", vp).items.isEmpty())
    }

    // ---- T-11: middle insertion emits 'middle' and paging has no duplicate -----------

    @Test
    fun middleInsertionEmitsMiddleAndPagesStayExact() {
        val idKey = keysFor(master).first
        val (msgs, ids) = fixture(17L, listOf("0xm"), 300, idKey)
        val store = fresh()
        apply(store, msgs, ids)
        val events = ArrayList<LocalChatEvent>()
        store.subscribe { events.add(it) }
        val page = store.openConversation("0xm", vp)
        // A row between the loaded middle item and the newest loaded item: inside the window.
        val lo = page.items[page.items.size / 2]
        val midTs = lo.sortTs + 1
        assertEquals(ApplyResult.INSERTED, store.applyRecord("0xm", IncomingRecord("in", midTs, LocalMediaKind.TEXT, "mid-sid", "middle!", "cm")))
        val ev = events.filterIsInstance<LocalChatEvent.Inserted>().single()
        assertEquals("middle", ev.position)
        // Full paging afterwards includes the new row exactly once.
        val (all, _) = pageAll(store, "0xm", vp)
        assertEquals(1, all.count { it.sendId == "mid-sid" })
        assertEquals(all.size, all.map { it.stableId }.toSet().size)
    }

    // ---- T-12: clear keeps pending rows --------------------------------------------

    @Test
    fun clearKeepsPendingRows() {
        val store = fresh()
        store.applyRecord("0xc", IncomingRecord("out", 1L, LocalMediaKind.TEXT, "a", "one", "c1"))
        store.applyRecord("0xc", IncomingRecord("out", 2L, LocalMediaKind.TEXT, "b", "two", "c2"), pendingPublish = true)
        store.applyRecord("0xd", IncomingRecord("in", 3L, LocalMediaKind.TEXT, "c", "three", "c3"))
        val kept = store.clearConversation("0xc")
        assertEquals(1, kept)
        assertEquals(1, store.rowCount("0xc"))
        assertEquals(1, store.rowCount("0xd"))
    }

    // ---- T-8: account isolation ------------------------------------------------------

    @Test
    fun accountsAreIsolated() {
        val a = LocalChatStore("0xaaaa")
        assertEquals(UnlockResult.OK, a.unlock(master, null))
        a.applyRecord("0xshared", IncomingRecord("in", 1L, LocalMediaKind.TEXT, "x", "A-secret", "c"))
        val snapA = a.snapshot()

        val b = LocalChatStore("0xbbbb")
        assertEquals(UnlockResult.OK, b.unlock(otherMaster, null))
        assertTrue(b.openConversation("0xshared", vp).items.isEmpty())
        // A's snapshot cannot be read with B's key: kcv mismatch, and with no pending rows it rebuilds empty.
        val c = LocalChatStore("0xaaaa")
        assertEquals(UnlockResult.REBUILT_KCV_MISMATCH, c.unlock(otherMaster, snapA))
        assertEquals(0, c.rowCount("0xshared"))
    }

    // ---- T-13: no plaintext in the snapshot ------------------------------------------

    @Test
    fun snapshotHasNoPlaintextMarker() {
        val store = fresh()
        store.applyRecord("0xp", IncomingRecord("in", 1L, LocalMediaKind.TEXT, "SIDMARK-7f3a", "FIXTURE-MARK-42", "c"))
        store.applyRecord("0xp", IncomingRecord("in", 2L, LocalMediaKind.IMAGE, "s2", "FIXTURE-MARK-43", "c2", widthPx = 400, heightPx = 300, mediaCid = "m"))
        val snap = store.snapshot()
        val text = String(snap, Charsets.ISO_8859_1)
        assertFalse(text.contains("FIXTURE-MARK"))
        assertFalse(text.contains("SIDMARK"))
        // Restore and read back.
        val re = LocalChatStore("0xaaaa:default")
        assertEquals(UnlockResult.OK, re.unlock(master, snap))
        assertEquals("FIXTURE-MARK-42", re.openConversation("0xp", vp).items.first().body)
    }

    // ---- T-14: newer schema is refused ---------------------------------------------

    @Test
    fun newerSchemaIsRefused() {
        val store = fresh()
        store.applyRecord("0xn", IncomingRecord("in", 1L, LocalMediaKind.TEXT, "s", "t", "c"))
        val snap = store.snapshot()
        val nl = snap.indexOf('\n'.code.toByte())
        val header = String(snap, 0, nl, Charsets.UTF_8).replace("\"schema\":1", "\"schema\":2")
        val patched = header.toByteArray(Charsets.UTF_8) + snap.copyOfRange(nl, snap.size)
        val re = LocalChatStore("0xaaaa")
        assertEquals(UnlockResult.LOCKED_SCHEMA_NEWER, re.unlock(master, patched))
        assertFalse(re.isUnlocked)
    }

    // ---- T-19 and A-3: kcv mismatch branches and cursor epoch ----------------------

    @Test
    fun kcvMismatchWithPendingStaysLockedAndWithoutPendingRebuilds() {
        val s = fresh()
        s.applyRecord("0xk", IncomingRecord("out", 1L, LocalMediaKind.TEXT, "p", "queued", "c"), pendingPublish = true)
        val locked = LocalChatStore("0xaaaa")
        assertEquals(UnlockResult.LOCKED_KCV_MISMATCH_PENDING, locked.unlock(otherMaster, s.snapshot()))

        val t = fresh()
        for (i in 0 until 30) t.applyRecord("0xk", IncomingRecord("in", i + 1L, LocalMediaKind.TEXT, "s$i", "row $i", "c$i"))
        val oldCursor = t.openConversation("0xk", vp).olderCursor
        assertNotNull(oldCursor)
        val rebuilt = LocalChatStore("0xaaaa")
        assertEquals(UnlockResult.REBUILT_KCV_MISMATCH, rebuilt.unlock(otherMaster, t.snapshot()))
        assertEquals("cursor_invalid", rebuilt.loadOlder("0xk", oldCursor ?: "x", vp).error)
    }

    @Test
    fun lockDropsMemoryAndUnlockRestoresWithSameEpochCursor() {
        val s = fresh()
        val idKey = keysFor(master).first
        val (msgs, ids) = fixture(23L, listOf("0xl"), 120, idKey)
        apply(s, msgs, ids)
        val p = s.openConversation("0xl", vp)
        assertTrue(p.hasOlder)
        val cursor = p.olderCursor!!
        val snap = s.snapshot()
        s.lock()
        assertEquals(LocalSource.LOCKED, s.openConversation("0xl", vp).source)
        assertEquals(UnlockResult.OK, s.unlock(master, snap))
        val next = s.loadOlder("0xl", cursor, vp)
        assertNull(next.error)
        assertTrue(next.items.isNotEmpty())
    }

    // ---- performance (JVM, synthetic, 50k messages, 5k in one conversation) ----------

    @Test
    fun firstScreenTimingOn50kStoreJvm() {
        val idKey = keysFor(master).first
        val store = fresh()
        val convs = (0 until 10).map { "0xconv$it" }
        val (msgs, ids) = fixture(99L, convs, 5000, idKey)
        apply(store, msgs, ids)
        val times = ArrayList<Long>()
        for (i in 0 until 60) {
            val t0 = System.nanoTime()
            val p = store.openConversation("0xconv3", vp)
            times.add((System.nanoTime() - t0) / 1_000)
            assertTrue(p.items.isNotEmpty())
        }
        times.sort()
        // Recorded in the receipt. Environment: JVM on developer host, not a device.
        println("LOCALREAD_METRIC first_screen_us p50=${times[times.size / 2]} p95=${times[(times.size * 95) / 100]} rows=${msgs.size} env=jvm-host")
    }
}
