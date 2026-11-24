package network.conet.chat.nativekey

import android.content.Context
import network.conet.chat.BeamioConetChatModule
import network.conet.chat.MainPoster
import network.conet.chat.SenderReceipt
import android.content.ContextWrapper
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Bridge level: the delivery-receipt vectors (shared vectors DR-01..18) through the real entry
 * [BeamioConetChatModule.handleCommand] (`setRoutes`, `ackInbound`) on a session of the module. The receipt send itself is replaced by the module's
 * test seam ([BeamioConetChatModule.receiptSendHook]): no PGP host and no network run here, so the PGP and POST counts are device evidence, not
 * this test's. Synthetic data.
 */
class ReceiptBridgeTest {
    private val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private val me: String = checkNotNull(WalletAddress.fromPrivateKey(checkNotNull(MnemonicDerivation.deriveKey(phrase)))).lowercase()
    private val peer = "0x2222222222222222222222222222222222222222"
    private val other = "0x3333333333333333333333333333333333333333"
    private val pgp = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxxxx\n-----END PGP PUBLIC KEY BLOCK-----"
    private lateinit var dir: File
    private lateinit var context: Context
    private var reqId = 100
    private val sends = java.util.concurrent.CopyOnWriteArrayList<Pair<JSONObject, String>>()
    private val dones = java.util.concurrent.CopyOnWriteArrayList<() -> Unit>()

    private class TestContext(private val dir: File) : ContextWrapper(null) {
        override fun getApplicationContext(): Context = this
        override fun getFilesDir(): File = dir
        override fun getCacheDir(): File = dir
        override fun getNoBackupFilesDir(): File = dir
    }

    private val module = BeamioConetChatModule
    private fun field(name: String) = BeamioConetChatModule::class.java.getDeclaredField(name).apply { isAccessible = true }

    @Before
    fun setUp() {
        dir = kotlin.io.path.createTempDirectory("receipt-bridge").toFile()
        context = TestContext(dir)
        MainPoster.runner = { it.run() }
        field("appContext").set(module, context)
        MnemonicPreread.resetForTests()
        NativeSessionState.reset()
        val vault = NativeWalletVault(NativeTestWrap(), AndroidVaultFiles(File(dir, "native_vault_v1").also { it.mkdirs() }))
        NativeWallet.installVaultForTest(vault)
        vault.state()
        NativeWallet.migrateLegacy(context)
        for (i in 0 until 100) {
            if (NativeWallet.isLegacyWalletAdoptionSettled() && !NativeWallet.isLegacyWalletAdoptionInFlight()) break
            Thread.sleep(50)
        }
        check(NativeWallet.isLegacyWalletAdoptionSettled())
        check(LegacyStoreReport.reportLegacyStore(context, LegacyStoreReport.ABSENT) == "ok")
        // The account is made by the product flow (the page's phrase sync); the store then answers the gate as G2, so chat commands are dispatched.
        val sync = ackOf(JSONObject().put("type", "pwaWalletSync").put("reqId", reqId++).put("phrase", phrase).put("eoa", me).put("trustedOrigin", true).put("seq", 9000L))
        check(sync.optBoolean("ok")) { sync.toString() }
        module.receiptSendHook = { route, payload, done ->
            sends.add(route to payload)
            dones.add(done)
        }
    }

    @After
    fun tearDown() {
        module.receiptSendHook = null
        field("session").set(module, null)
        field("appContext").set(module, null)
        MainPoster.runner = null
        NativeSessionState.reset()
        NativeWallet.installVaultForTest(null)
        MnemonicPreread.resetForTests()
        dir.deleteRecursively()
    }

    private fun install(eoa: String = me): BeamioConetChatModule.Session {
        val s = BeamioConetChatModule.Session()
        s.eoa = eoa
        s.deferAck = true
        field("session").set(module, s)
        return s
    }

    private fun routeRow(address: String, user: String = pgp, router: String = pgp) =
        JSONObject().put("eoaAddress", address).put("userPublicKeyArmored", user).put("routerArmoredPublicKey", router)

    private fun ackOf(body: JSONObject): JSONObject {
        val out = mutableListOf<JSONObject>()
        module.handleCommand(context, body) { out.add(it) }
        return out.mapNotNull { it.optJSONObject("event") }.lastOrNull { it.optString("type") == "ack" } ?: error("no ack: $out")
    }

    private fun setRoutes(routes: Any?, eoa: String? = me): JSONObject {
        val b = JSONObject().put("type", "setRoutes").put("reqId", reqId++)
        if (routes != null) b.put("routes", routes)
        if (eoa != null) b.put("eoa", eoa)
        return ackOf(b)
    }

    private fun ackInbound(vararg hashes: String) {
        module.handleCommand(context, JSONObject().put("type", "ackInbound").put("reqId", reqId++).put("armorHashes", JSONArray(hashes.toList()))) { }
    }

    private fun chatLine(sendId: String?, text: String = "hello"): String {
        val pending = JSONObject().put("from", "me").put("text", text).put("createdAt", 1L)
        if (sendId != null) pending.put("sendId", sendId)
        return JSONObject().put("timestamp", 1L).put("text", pending.toString()).put("from", peer).put("signMessage", "0xsig").toString()
    }

    private fun lineOf(inner: JSONObject, sendId: String = "own-id"): String {
        val pending = JSONObject().put("sendId", sendId).put("from", "me").put("text", inner.toString()).put("createdAt", 1L)
        return JSONObject().put("timestamp", 1L).put("text", pending.toString()).put("from", peer).put("signMessage", "0xsig").toString()
    }

    private fun pend(s: BeamioConetChatModule.Session, hash: String, line: String, from: String = peer) {
        s.pendingAcks[hash] = BeamioConetChatModule.PendingAck(line, from, "d", System.currentTimeMillis())
    }

    /** The receipt send runs on the worker: wait until [n] sends were handed over (or time out). */
    private fun awaitSends(n: Int) {
        val end = System.currentTimeMillis() + 5000
        while (sends.size < n && System.currentTimeMillis() < end) Thread.sleep(5)
        assertEquals(n, sends.size)
    }

    private fun settle() = Thread.sleep(150)

    // ---- setRoutes answers (DR-10, 12, 15) ------------------------------------------------------------------------

    @Test
    fun dr15_everySetRoutesIsAnsweredWithTheRightCodeAndFailuresChangeNothing() {
        // no session
        field("session").set(module, null)
        assertEquals("not_ready", setRoutes(JSONArray()).getString("error"))
        val s = install()
        assertEquals(0, s.receipts.routeCount())
        pend(s, "q1", chatLine("Q1")) // a receipt waiting for a route
        ackInbound("q1")
        settle()
        assertEquals(1, s.receipts.queueSize())

        for ((label, ack) in listOf(
            "not an array" to setRoutes("nope"),
            "no routes" to setRoutes(null),
            "no eoa" to setRoutes(JSONArray().put(routeRow(peer)), eoa = null),
            "other eoa" to setRoutes(JSONArray().put(routeRow(peer)), eoa = other),
        )) {
            assertFalse("$label: ${ack}", ack.getBoolean("ok"))
        }
        assertEquals("bad_request", setRoutes("nope").getString("error"))
        assertEquals("bad_request", setRoutes(JSONArray().put(routeRow(peer)), eoa = null).getString("error"))
        assertEquals("signer_mismatch", setRoutes(JSONArray().put(routeRow(peer)), eoa = other).getString("error"))
        // failures changed neither the routes nor the queue, and sent nothing
        assertEquals(0, s.receipts.routeCount())
        assertEquals(1, s.receipts.queueSize())
        settle()
        assertTrue(sends.isEmpty())

        val ok = setRoutes(JSONArray().put(routeRow(peer)).put(routeRow(other, user = "no key")))
        assertTrue(ok.toString(), ok.getBoolean("ok"))
        assertEquals(1, ok.getJSONObject("result").getInt("accepted"))
        assertEquals(1, ok.getJSONObject("result").getInt("dropped"))
        awaitSends(1) // DR-07: the queued receipt goes out at once
        assertEquals(0, s.receipts.queueSize())
    }

    @Test
    fun dr12_257RowsAndAnOversizeArmorRefuseTheWholeCommandAndKeepTheRoutes() {
        val s = install()
        assertTrue(setRoutes(JSONArray().put(routeRow(peer))).getBoolean("ok"))
        assertEquals(1, s.receipts.routeCount())
        val many = JSONArray()
        for (i in 0 until 257) many.put(routeRow("0x" + i.toString(16).padStart(40, '0')))
        assertEquals("bad_request", setRoutes(many).getString("error"))
        assertEquals("bad_request", setRoutes(JSONArray().put(routeRow(other, user = pgp + "x".repeat(32 * 1024)))).getString("error"))
        assertEquals("the old routes stay", 1, s.receipts.routeCount())
    }

    @Test
    fun dr10_aTableForAnotherAccountIsIgnoredAndTheOldRoutesStay() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        val bad = setRoutes(JSONArray().put(routeRow(other)), eoa = other)
        assertEquals("signer_mismatch", bad.getString("error"))
        assertEquals(1, s.receipts.routeCount())
        pend(s, "h-peer", chatLine("S-peer"))
        ackInbound("h-peer")
        awaitSends(1)
    }

    // ---- ackInbound (DR-01, 02, 03, 04, 05, 06, 07, 13, 16, 17, 18) -----------------------------------------------

    @Test
    fun dr01_dr14_setRoutesThenAckInboundSendsOneReceiptToTheSender() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        pend(s, "h1", chatLine("S1", "private words"))
        ackInbound("h1")
        awaitSends(1)
        assertEquals(peer, sends[0].first.getString("eoaAddress"))
        assertEquals(pgp, sends[0].first.getString("routerArmoredPublicKey"))
        val outer = JSONObject(sends[0].second)
        val inner = JSONObject(outer.getString("text"))
        assertEquals("S1", inner.getString("sendId"))
        assertEquals("h1", inner.getString("armorHash"))
        assertEquals(me, inner.getString("from"))
        assertEquals("me", outer.getString("from"))
        assertFalse(sends[0].second.contains("private words"))
        assertNull("the pending message left pendingAcks", s.pendingAcks["h1"])
    }

    @Test
    fun dr05_aSecondAckInboundOfTheSameMessageSendsNothingMore() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        pend(s, "h5", chatLine("S5"))
        ackInbound("h5")
        awaitSends(1)
        ackInbound("h5") // nothing is pending any more
        pend(s, "h5", chatLine("S5")) // and even if the module held it again (a redelivery), the dedupe holds
        ackInbound("h5")
        settle()
        assertEquals(1, sends.size)
    }

    @Test
    fun dr16_theSameFromAndSendIdOnAnotherArmorSendsOnce() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        pend(s, "armor-A", chatLine("S16"))
        pend(s, "armor-B", chatLine("S16"))
        ackInbound("armor-A", "armor-B")
        awaitSends(1)
        settle()
        assertEquals(1, sends.size)
    }

    @Test
    fun dr02_dr03_dr04_dr13_dr18_noReceiptForReceiptsControlVoiceUnknownOrWithoutSendId() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        val lines = listOf(
            "receipt" to lineOf(JSONObject().put("type", SenderReceipt.TYPE).put("sendId", "mine").put("from", peer)),
            "control" to lineOf(JSONObject().put("type", "voice_call_offer_v1").put("callId", "call-0000000001").put("sessionId", "sess-0001").put("from", peer)),
            "voice" to lineOf(JSONObject().put("type", "voice_frame_v1").put("sessionId", "sess-0001")),
            "unknown" to lineOf(JSONObject().put("type", "mystery_v3")),
            "system" to lineOf(JSONObject().put("type", "system_notice")),
            "nosendid" to chatLine(null),
        )
        for ((name, line) in lines) pend(s, "h-$name", line)
        ackInbound(*lines.map { "h-${it.first}" }.toTypedArray())
        settle()
        assertTrue("no receipt for any of them: ${sends.size}", sends.isEmpty())
        assertEquals(0, s.receipts.queueSize())
        // the control group: an ordinary message still earns one
        pend(s, "h-ok", chatLine("S-ok"))
        ackInbound("h-ok")
        awaitSends(1)
        // none of the receipts we make is in pendingAcks
        assertTrue(s.pendingAcks.isEmpty())
    }

    @Test
    fun dr06_dr07_aMissingRouteQueuesAndTheLaterSetRoutesSendsIt() {
        val s = install()
        pend(s, "h6", chatLine("S6"))
        ackInbound("h6")
        settle()
        assertTrue(sends.isEmpty())
        assertEquals(1, s.receipts.queueSize())
        assertTrue(setRoutes(JSONArray().put(routeRow(other))).getBoolean("ok"))
        settle()
        assertTrue(sends.isEmpty())
        assertTrue(setRoutes(JSONArray().put(routeRow(other)).put(routeRow(peer))).getBoolean("ok"))
        awaitSends(1)
        assertEquals(0, s.receipts.queueSize())
    }

    @Test
    fun dr17_oneAckInboundOfFiveSendsTwoAtATimeAndTheCommandReturnsAtOnce() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        val hashes = (0 until 5).map { "h17-$it" }
        for ((i, h) in hashes.withIndex()) pend(s, h, chatLine("S17-$i"))
        val started = System.nanoTime()
        ackInbound(*hashes.toTypedArray())
        val ms = (System.nanoTime() - started) / 1_000_000
        assertTrue("the command did not wait for the sends ($ms ms)", ms < 1000)
        awaitSends(2)
        settle()
        assertEquals("two in flight, three waiting", 2, sends.size)
        assertEquals(3, s.receipts.queueSize())
        while (dones.isNotEmpty()) {
            val d = dones.removeAt(0)
            d()
            settle()
            assertTrue("never above two at once", s.receipts.inFlightCount() <= 2)
        }
        assertEquals(5, sends.size)
    }

    @Test
    fun dr31_dr32_dr34_theLeafAndDepthRulesThroughAckInbound() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        fun env(payload: String) = JSONObject().put("timestamp", 1L).put("text", payload).put("from", peer).put("signMessage", "0xsig").toString()
        fun nest(n: Int, leaf: String): String {
            var o = JSONObject().put("sendId", "L$n").put("text", leaf)
            for (i in n - 1 downTo 1) o = JSONObject().put("sendId", "L$i").put("text", o.toString())
            return o.toString()
        }
        // earn nothing: a first layer that is an array or a number; a seventh object layer
        pend(s, "h-arr", env("[1,2]"))
        pend(s, "h-num", env("123"))
        pend(s, "h-7", env(nest(7, "words")))
        ackInbound("h-arr", "h-num", "h-7")
        settle()
        assertTrue(sends.isEmpty())
        // earn a receipt: user text that is an array or a number below the first layer; exactly six layers
        pend(s, "h-leaf-arr", env(JSONObject().put("sendId", "S-arr").put("text", "[1,2]").toString()))
        pend(s, "h-leaf-num", env(JSONObject().put("sendId", "S-num").put("text", "123").toString()))
        pend(s, "h-6", env(nest(6, "words")))
        ackInbound("h-leaf-arr", "h-leaf-num", "h-6")
        // two in flight at a time: free them as they come
        val end = System.currentTimeMillis() + 5000
        while (sends.size < 3 && System.currentTimeMillis() < end) {
            dones.toList().also { dones.clear() }.forEach { it() }
            Thread.sleep(10)
        }
        assertEquals(3, sends.size)
        assertEquals(setOf("S-arr", "S-num", "L1"), sends.map { JSONObject(JSONObject(it.second).getString("text")).getString("sendId") }.toSet())
    }

    @Test
    fun dr36_dr37_dr38_theEnvelopeIsNoLayerAndTheFirstLayerHasItsOwnSendIdThroughAckInbound() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        fun env(payload: String) = JSONObject().put("timestamp", 1L).put("text", payload).put("from", peer).put("signMessage", "0xsig").toString()
        fun nest(n: Int): String {
            var o = JSONObject().put("sendId", "L$n").put("text", "words")
            for (i in n - 1 downTo 1) o = JSONObject().put("sendId", "L$i").put("text", o.toString())
            return o.toString()
        }
        // DR-37 and DR-38 and the seventh layer of DR-36: nothing
        pend(s, "h-37", env(JSONObject().put("text", JSONObject().put("sendId", "INNER").put("text", "x").toString()).toString()))
        pend(s, "h-38a", env("plain words"))
        pend(s, "h-38b", env("[1,2]"))
        pend(s, "h-36-7", env(nest(7)))
        ackInbound("h-37", "h-38a", "h-38b", "h-36-7")
        settle()
        assertTrue(sends.isEmpty())
        // DR-36: six layers inside the envelope earn one receipt, with the first layer's sendId
        pend(s, "h-36-6", env(nest(6)))
        ackInbound("h-36-6")
        awaitSends(1)
        assertEquals("L1", JSONObject(JSONObject(sends[0].second).getString("text")).getString("sendId"))
    }

    @Test
    fun dr39_dr40_dr41_objectLeavesAndTheInnermostLayerThroughAckInbound() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        fun env(payload: String) = JSONObject().put("timestamp", 1L).put("text", payload).put("from", peer).put("signMessage", "0xsig").toString()
        fun first(text: String) = env(JSONObject().put("sendId", "S").put("text", text).toString())
        var seven = JSONObject().put("a", 1)
        for (i in 6 downTo 1) seven = JSONObject().put("sendId", "L$i").put("text", seven.toString())
        val names = listOf("type", "group", "reply", "call", "seven")
        pend(s, "h-type", first("{\"type\":\"x\"}"))
        pend(s, "h-group", first("{\"groupId\":\"g\"}"))
        pend(s, "h-reply", first("{\"reply\":{}}"))
        pend(s, "h-call", first("{\"callRecord\":{}}"))
        pend(s, "h-seven", env(seven.toString()))
        ackInbound(*names.map { "h-$it" }.toTypedArray())
        settle()
        assertTrue(sends.isEmpty())
        // a plain object leaf, and six layers with {"a":1} innermost, earn one receipt each
        var six = JSONObject().put("a", 1)
        for (i in 5 downTo 1) six = JSONObject().put("sendId", "L$i").put("text", six.toString())
        pend(s, "h-a", first("{\"a\":1}"))
        pend(s, "h-six", env(six.toString()))
        ackInbound("h-a", "h-six")
        awaitSends(2)
    }

    @Test
    fun dr42_dr43_dr44_nullEmptyAndKeyNamesThroughAckInbound() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        var n = 0 // each message has its own sendId: the same (from, sendId) would be answered once
        fun first(text: String) = JSONObject().put("timestamp", 1L).put("from", peer).put("signMessage", "0xsig")
            .put("text", JSONObject().put("sendId", "S${n++}").put("text", text).toString()).toString()
        val none = listOf("{\"type\":\"\"}", "{\"type\":0}", "{\"type\":false}", "{\"reply\":{}}", "{\"callRecord\":[]}")
        for ((i, text) in none.withIndex()) pend(s, "h-none-$i", first(text))
        ackInbound(*none.indices.map { "h-none-$it" }.toTypedArray())
        settle()
        assertTrue("non-null values of an exclusion field earn nothing", sends.isEmpty())
        val yes = listOf("{\"type\":null}", "{\"reply\":null}", "{\"groupId\":null}", "{\"callRecord\":null}", "{\"typeOf\":1}", "{\"Type\":\"x\"}")
        for ((i, text) in yes.withIndex()) pend(s, "h-yes-$i", first(text))
        ackInbound(*yes.indices.map { "h-yes-$it" }.toTypedArray())
        // two at a time: free the slots as they come
        val end = System.currentTimeMillis() + 5000
        while (sends.size < yes.size && System.currentTimeMillis() < end) {
            dones.toList().also { dones.clear() }.forEach { it() }
            Thread.sleep(10)
        }
        assertEquals(yes.size, sends.size)
    }

    // ---- session end (DR-11) --------------------------------------------------------------------------------------

    @Test
    fun dr11_afterAnIdentityClearNothingIsSentAndRoutesAndQueueAreEmpty() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        pend(s, "h-q", chatLine("S-q"), from = other) // queued: no route for other
        ackInbound("h-q")
        settle()
        assertEquals(1, s.receipts.queueSize())
        pend(s, "h-late", chatLine("S-late"))
        // the clear ends the page session (the module's own function)
        BeamioConetChatModule::class.java.getDeclaredMethod("endPageSession").apply { isAccessible = true }.invoke(module)
        assertEquals(0, s.receipts.routeCount())
        assertEquals(0, s.receipts.queueSize())
        assertTrue(s.pendingAcks.isEmpty())
        // the page's late ackInbound and setRoutes find no session
        ackInbound("h-late")
        assertEquals("not_ready", setRoutes(JSONArray().put(routeRow(peer))).getString("error"))
        settle()
        assertTrue(sends.isEmpty())
    }

    @Test
    fun dr11_aNewAccountsSessionHasNoRoutesOfTheOldOne() {
        val old = install(me)
        setRoutes(JSONArray().put(routeRow(peer)))
        assertEquals(1, old.receipts.routeCount())
        // what init does for another account: the old session's receipt state ends, a new session is put in place
        old.clearReceiptState()
        val fresh = install(other)
        assertEquals(0, fresh.receipts.routeCount())
        pend(fresh, "h-new", chatLine("S-new"))
        ackInbound("h-new")
        settle()
        assertTrue("no route for the new account: queued, not sent", sends.isEmpty())
        // the old account's page cannot fill the new session
        assertEquals("signer_mismatch", setRoutes(JSONArray().put(routeRow(peer)), eoa = me).getString("error"))
    }

    @Test
    fun theReceiptIsNotMadeOnTheCommandThread() {
        val s = install()
        setRoutes(JSONArray().put(routeRow(peer)))
        val threads = java.util.concurrent.CopyOnWriteArrayList<String>()
        module.receiptSendHook = { route, payload, done ->
            threads.add(Thread.currentThread().name)
            sends.add(route to payload)
            done()
        }
        pend(s, "h-t", chatLine("S-t"))
        val me = Thread.currentThread().name
        ackInbound("h-t")
        awaitSends(1)
        assertTrue("sent on ${threads[0]}, not on $me", threads[0] != me)
    }
}
