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
                val body = "FIXTURE-$seed-$n " + (if (kind == LocalMediaKind.TEXT) "hello $n" else "media $n")
                val (w, h) = if (kind == LocalMediaKind.IMAGE || kind == LocalMediaKind.VIDEO) {
                    listOf(Pair(4, 3), Pair(3, 4), Pair(16, 9), Pair(9, 16), Pair(1, 1))[rnd.nextInt(5)].let {
                        Pair(it.first * 100, it.second * 100)
                    }
                } else Pair(null, null)
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
        val ids = HashMap<String, String>()
        for (m in msgs) {
            val sid = m.sendId ?: LocalChatIds.stableId(idKey, m.conv, m.dir, m.sortTs, originalBody(m), null)
            ids[m.conv + "|" + m.n] = sid
        }
        return Pair(msgs, ids)
    }

    /** Body as first delivered (before any revision), needed for content-derived ids. */
    private fun originalBody(m: Msg): String = if (m.revised) m.body.removeSuffix(" (edited)") else m.body

    private fun apply(store: LocalChatStore, msgs: List<Msg>, ids: Map<String, String>) {
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
                val r = store.applyRecord(m.conv, IncomingRecord(m.dir, m.sortTs, m.kind, m.sendId, null, m.cid,
                    deleted = true, stableIdHint = ids[m.conv + "|" + m.n]))
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

    private fun fresh(account: String = "0xaaaa"): LocalChatStore {
        val s = LocalChatStore(account)
        assertEquals(UnlockResult.OK, s.unlock(master, null))
        return s
    }

    // ---- ids and ordering ---------------------------------------------------------------

    @Test
    fun stableIdUsesSendIdWhenPresent() {
        val k = LocalChatIds.idKey(master)
        assertEquals("abc.def", LocalChatIds.stableId(k, "c", "in", 1L, "x", "abc.def"))
        assertEquals("abc.def", LocalChatIds.stableId(k, "c", "out", 9L, "y", "abc.def"))
    }

    @Test
    fun contentDerivedIdIsDeterministicAndSensitive() {
        val k = LocalChatIds.idKey(master)
        val base = LocalChatIds.stableId(k, "c", "in", 100L, "hello", null)
        assertEquals(base, LocalChatIds.stableId(k, "c", "in", 100L, "hello", ""))
        assertTrue(base.startsWith("h:"))
        assertTrue(base.substring(2).all { it.isLetterOrDigit() || it == '-' || it == '_' })
        assertFalse(base == LocalChatIds.stableId(k, "c", "out", 100L, "hello", null))
        assertFalse(base == LocalChatIds.stableId(k, "c", "in", 101L, "hello", null))
        assertFalse(base == LocalChatIds.stableId(k, "c", "in", 100L, "hellp", null))
        assertFalse(base == LocalChatIds.stableId(LocalChatIds.idKey(otherMaster), "c", "in", 100L, "hello", null))
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
        val idKey = LocalChatIds.idKey(master)
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
        val idKey = LocalChatIds.idKey(master)
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
        val page = store.openConversation("0xshort", vp)
        assertEquals(1, page.items.size)
        assertTrue(page.short)
        assertFalse(page.hasOlder)
        assertFalse(page.capped)
    }

    // ---- T-4: layout cache ----------------------------------------------------------

    @Test
    fun layoutMeasuredOnceIsHitOnSecondVisit() {
        val idKey = LocalChatIds.idKey(master)
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
        val idKey = LocalChatIds.idKey(master)
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
        store.reportLayout("0xs", "sid-x", vp, 300.0, 90.0)
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
        assertEquals(ApplyResult.TOMBSTONED, store.applyRecord("0xs", IncomingRecord("in", 1000L, LocalMediaKind.TEXT, "sid-x", null, null, deleted = true, stableIdHint = "sid-x")))
        assertTrue(store.openConversation("0xs", vp).items.isEmpty())
    }

    // ---- T-11: middle insertion emits 'middle' and paging has no duplicate -----------

    @Test
    fun middleInsertionEmitsMiddleAndPagesStayExact() {
        val idKey = LocalChatIds.idKey(master)
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
        assertEquals(1, all.count { it.stableId == "mid-sid" })
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
        val re = LocalChatStore("0xaaaa")
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
        val idKey = LocalChatIds.idKey(master)
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
        val idKey = LocalChatIds.idKey(master)
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
