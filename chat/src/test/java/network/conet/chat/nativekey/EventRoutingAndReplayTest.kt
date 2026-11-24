package network.conet.chat.nativekey

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * A page sync command (pwaWalletSync) ran while `init` was unlocking, took over the module's single event emit (a shell lambda that keeps only the
 * first ack), and `init`'s `ready` went into it and vanished; and the stored-inbox replay of `init` decrypted on the main thread for 3.5 s.
 */
class EventRoutingAndReplayTest {
    private val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readLines().filterNot { it.trim().startsWith("//") }.joinToString("\n")

    private class Sink { val got = ArrayList<JSONObject>(); val emit: (JSONObject) -> Unit = { got += it } }
    private fun ack(id: Any?) = JSONObject().put("type", "ack").put("reqId", id ?: JSONObject.NULL).put("ok", true)
    private fun ready(id: Any?) = JSONObject().put("type", "ready").put("reqId", id)

    /** What the module does when it emits [payload] on this thread: the reply sink, else the event sink. */
    private fun deliver(r: EventRouter, p: JSONObject) { (r.replyFor(p) ?: r.events)?.invoke(p) }

    // ---- the page sync command does not take over the event sink ----------------------------------------------------------------------------

    @Test
    fun aChatCommandBecomesTheEventSink() {
        val r = EventRouter()
        val chat = Sink()
        r.command(false, chat.emit, 1) { }
        deliver(r, ready(1))
        assertEquals(1, chat.got.size)
    }

    @Test
    fun readyStillReachesTheChatEmitWhenAPageSyncCommandRanInTheUnlockWindow() {
        val r = EventRouter()
        val chat = Sink()
        val bridge = Sink() // the shell's window-channel lambda: it would swallow everything but its ack
        r.command(false, chat.emit, 1) { }          // init (reqId 1) is accepted; its unlock is still running on the worker
        r.command(true, bridge.emit, 1796395191301L) {   // pwaWalletSync arrives meanwhile
            deliver(r, ack(1796395191301L))
        }
        // init finishes: ready is emitted later, on another thread, with the init's reqId
        val t = Thread { deliver(r, ready(1)) }
        t.start(); t.join()
        assertEquals("the page sync command got only its own ack", 1, bridge.got.size)
        assertEquals("ack", bridge.got[0].getString("type"))
        assertEquals("ready reached the chat emit", listOf("ready"), chat.got.map { it.getString("type") })
    }

    @Test
    fun anInboundEventAndAStatusAfterAPageSyncCommandStillGoToTheChatEmit() {
        val r = EventRouter()
        val chat = Sink(); val bridge = Sink()
        r.command(false, chat.emit, 7) { }
        r.command(true, bridge.emit, 8) { deliver(r, ack(8)) }
        deliver(r, JSONObject().put("type", "event:message"))
        deliver(r, JSONObject().put("type", "event:status"))
        assertEquals(listOf("event:message", "event:status"), chat.got.map { it.getString("type") })
        assertEquals(1, bridge.got.size)
    }

    @Test
    fun aPageSyncCommandsOwnEventsOtherThanItsFirstAckGoToTheChatEmit() {
        val r = EventRouter()
        val chat = Sink(); val bridge = Sink()
        r.command(false, chat.emit, 1) { }
        r.command(true, bridge.emit, 5) {
            deliver(r, JSONObject().put("type", "event:log"))   // not an ack
            deliver(r, ack(5))                                   // its ack
            deliver(r, ack(5))                                   // a second one: the registration is consumed
        }
        assertEquals(listOf("ack"), bridge.got.map { it.getString("type") })
        assertEquals(listOf("event:log", "ack"), chat.got.map { it.getString("type") })
    }

    @Test
    fun theRegistrationIsGoneWhenTheCallReturnsAndAfterItsAck() {
        val r = EventRouter()
        val chat = Sink(); val bridge = Sink()
        r.command(false, chat.emit, 1) { }
        r.command(true, bridge.emit, 5) { }
        deliver(r, ack(5)) // after the call returned: an ordinary event
        assertEquals(0, bridge.got.size)
        assertEquals(1, chat.got.size)
        // and consumed by its ack: a later ack of the same id inside the same call is not taken again (above); nothing remains on this thread
        assertNull(r.replyFor(ack(5)))
    }

    // ---- no mix-up: ack first come first served, request ids are not unique across channels ---------------------------------------------

    @Test
    fun aChatCommandsAckWithTheSameRequestIdIsNotTakenByAPageSyncCommand() {
        val r = EventRouter()
        val chat = Sink(); val bridge = Sink()
        r.command(false, chat.emit, 700000010L) { }
        val inCall = CountDownLatch(1)
        val chatAckSent = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            pool.submit {
                // the page sync command, in flight on thread A, with the SAME request id as the chat command
                r.command(true, bridge.emit, 700000010L) {
                    inCall.countDown()
                    chatAckSent.await(5, TimeUnit.SECONDS)
                    deliver(r, ack(700000010L)) // its own ack, on its own thread
                }
            }
            assertTrue(inCall.await(5, TimeUnit.SECONDS))
            // thread B: the chat command's ack with the same id, emitted while the page sync command is in flight
            pool.submit { deliver(r, ack(700000010L)); chatAckSent.countDown() }.get(5, TimeUnit.SECONDS)
        } finally {
            pool.shutdown(); pool.awaitTermination(5, TimeUnit.SECONDS)
        }
        assertEquals("the chat command's ack went to the chat emit", 1, chat.got.size)
        assertEquals("the page sync command got exactly its own ack", 1, bridge.got.size)
    }

    @Test
    fun aPageSyncCommandsAckWithAnotherIdIsNotTakenAndAckWithItsOwnIdIs() {
        val r = EventRouter()
        val chat = Sink(); val bridge = Sink()
        r.command(false, chat.emit, 1) { }
        r.command(true, bridge.emit, 5) {
            deliver(r, ack(6))   // someone else's id emitted on this thread
            deliver(r, ack(5))
        }
        assertEquals(1, bridge.got.size)
        assertEquals(5, bridge.got[0].getInt("reqId"))
        assertEquals(6, chat.got[0].getInt("reqId"))
    }

    @Test
    fun aStringAndAnIntegerIdAreDifferentKeysOnlyWhenTheirTextDiffers() {
        val r = EventRouter()
        val chat = Sink(); val bridge = Sink()
        r.command(false, chat.emit, 1) { }
        r.command(true, bridge.emit, "p-1") { deliver(r, ack("p-1")) }
        assertEquals(1, bridge.got.size)
    }

    @Test
    fun aPageSyncCommandWithNoValidRequestIdStillGetsItsNullAck() {
        val r = EventRouter()
        val chat = Sink(); val bridge = Sink()
        r.command(false, chat.emit, 1) { }
        r.command(true, bridge.emit, null) { deliver(r, ack(null)) } // the bad_request envelope answers with a null id
        assertEquals(1, bridge.got.size)
        assertEquals(0, chat.got.size)
    }

    @Test
    fun theLatestChatCommandWinsAndPageSyncCommandsNestSafely() {
        val r = EventRouter()
        val c1 = Sink(); val c2 = Sink(); val b1 = Sink(); val b2 = Sink()
        r.command(false, c1.emit, 1) { }
        r.command(false, c2.emit, 2) { }
        r.command(true, b1.emit, 10) {
            r.command(true, b2.emit, 11) { deliver(r, ack(11)) } // nested: the outer registration is restored on return
            deliver(r, ack(10))
        }
        assertEquals(1, b1.got.size); assertEquals(1, b2.got.size)
        deliver(r, ready(2))
        assertEquals("the latest chat command is the sink", 1, c2.got.size)
        assertEquals(0, c1.got.size)
    }

    @Test
    fun withNoChatCommandYetAnEventHasNowhereToGoAndNothingFails() {
        val r = EventRouter()
        val bridge = Sink()
        r.command(true, bridge.emit, 5) { deliver(r, ack(5)) }
        deliver(r, ready(1))
        assertEquals(1, bridge.got.size)
        assertNull(r.events)
    }

    // ---- the module's wiring --------------------------------------------------------------------------------------------------------------

    @Test
    fun theModuleRoutesThroughTheRouterAndNoCommandReplacesTheEmitByHand() {
        assertTrue(module.contains("router.commandGuarded(type in REPLY_ONLY_COMMANDS, emit, reqId, onException = { e ->"))
        assertTrue(module.contains("}) { handleCommandInner(context, body, emit) }"))
        // the failure answer is inside that call, not in a catch around it (the registration would be gone by then)
        val frame = module.substringAfter("fun handleCommand(context: Context, body: JSONObject, emit: (JSONObject) -> Unit) {").substringBefore("private fun handleCommandInner(")
        assertFalse("no catch outside the router's scope", frame.contains("catch (e: Exception)"))
        assertTrue(frame.indexOf("router.commandGuarded(") < frame.indexOf("ack(reqId, false, error = NoKeyGate.NOT_READY)"))
        assertFalse("no assignment of the emit inside a command", Regex("""\bemitFn = emit\b""").containsMatchIn(module))
        val emit = module.substringAfter("private fun emitEvent(payload: JSONObject) {").substringBefore("/** The reqId as the page sent it")
        assertTrue(emit.contains("val replySink = router.replyFor(payload)"))
        assertTrue(emit.contains("(replySink ?: router.events)?.invoke(out)"))
        assertFalse("the global emit is not read directly", emit.contains("emitFn"))
    }

    @Test
    fun theReplyOnlySetCoversTheShellsPageSyncCommands() {
        val names = Regex("""REPLY_ONLY_COMMANDS: Set<String> = setOf\(([^)]*)\)""").find(module)!!.groupValues[1]
            .split(",").map { it.trim().trim('"') }.filter { it.isNotEmpty() }.toSet()
        // the shell's PageSyncRoute.COMMANDS: pwaWalletSync, nativeMnemonicPreread, pwaEmptySignal and the six passcode commands
        val shell = setOf(
            "pwaWalletSync", "nativeMnemonicPreread", "pwaEmptySignal",
            "passcodeProvision", "passcodeUnlock", "passcodeChange", "passcodeDisable", "nativeRepairProvide", "passcodeStatus",
        )
        assertTrue("missing: ${shell - names}", names.containsAll(shell))
        assertTrue(names.containsAll(setOf("shellRecordRead", "shellRecordWrite")))
        // the chat commands are never reply-only
        for (chat in listOf("init", "hello", "send", "walletStatus", "identityPublic", "pgpMigrate", "ackInbound", "historyLoad")) assertFalse(chat, chat in names)
    }

    // ---- the inbox replay is off the main thread and the dedupe lets a message through once ----------------------------------------------

    @Test
    fun theReplayDecryptsOnTheExecutorAndNotOnTheCallingThread() {
        val caller = Thread.currentThread()
        val pool = Executors.newSingleThreadExecutor { r -> Thread(r, "replay-worker") }
        val decryptedOn = ArrayList<Thread>()
        val done = CountDownLatch(1)
        try {
            InboxReplay.start(
                execute = { pool.execute(it) },
                load = { listOf("h1", "h2") },
                hashOf = { it }, isPending = { false }, forget = { },
                decrypt = { decryptedOn += Thread.currentThread(); if (decryptedOn.size == 2) done.countDown() },
                log = { },
            )
            // returned at once: the decrypts have not necessarily happened yet, and none on this thread
            assertTrue(done.await(5, TimeUnit.SECONDS))
        } finally {
            pool.shutdown()
        }
        assertEquals(2, decryptedOn.size)
        for (t in decryptedOn) { assertEquals("replay-worker", t.name); assertTrue(t !== caller) }
    }

    @Test
    fun theReplayReturnsBeforeAnySlowDecryptFinishes() {
        val pool = Executors.newSingleThreadExecutor()
        val release = CountDownLatch(1)
        val finished = AtomicInteger(0)
        try {
            val t0 = System.nanoTime()
            InboxReplay.start(
                execute = { pool.execute(it) }, load = { listOf("h") }, hashOf = { it }, isPending = { false }, forget = { },
                decrypt = { release.await(10, TimeUnit.SECONDS); finished.incrementAndGet() }, log = { },
            )
            assertTrue("start() did not wait for the decrypt", (System.nanoTime() - t0) < 2_000_000_000L)
            assertEquals(0, finished.get())
            release.countDown()
        } finally {
            pool.shutdown(); pool.awaitTermination(5, TimeUnit.SECONDS)
        }
        assertEquals(1, finished.get())
    }

    @Test
    fun theReplaySkipsPendingMessagesForgetsTheRestAndAnUnreadableInboxReplaysNothing() {
        val log = ArrayList<String>(); val forgotten = ArrayList<String>(); val decrypted = ArrayList<String>()
        InboxReplay.start(
            execute = { it.run() }, load = { listOf("a", "b", "c") }, hashOf = { it }, isPending = { it == "b" },
            forget = { forgotten += it }, decrypt = { decrypted += it }, log = { log += it },
        )
        assertEquals(listOf("a", "c"), decrypted)
        assertEquals(listOf("a", "c"), forgotten)
        assertEquals(listOf("inbox replay count=2"), log)
        val log2 = ArrayList<String>(); val dec2 = ArrayList<String>()
        InboxReplay.start<String>(execute = { it.run() }, load = { throw IOException("x") }, hashOf = { it }, isPending = { false }, forget = { }, decrypt = { dec2 += it }, log = { log2 += it })
        assertTrue(dec2.isEmpty())
        assertEquals(listOf("inbox unreadable; not replayed"), log2)
        val dec3 = ArrayList<String>()
        InboxReplay.start(execute = { it.run() }, load = { emptyList<String>() }, hashOf = { it }, isPending = { false }, forget = { }, decrypt = { dec3 += it }, log = { })
        assertTrue(dec3.isEmpty())
    }

    @Test
    fun theReplayAndTheListenDeliveringTheSameMessageAtOnceHandleItOnce() {
        // The replay forgets the hash first (so a message seen earlier in this process can be handed over again), then decrypts; the listen decrypts the
        // same armor. Both reach handleInbound, whose first step is markSeen: exactly one of the two gets through, whichever thread is first.
        repeat(300) {
            val seen = SeenArmor()
            seen.markSeen("h")      // seen earlier in this process
            seen.forget("h")        // the replay's step, before both deliveries
            val handled = AtomicInteger(0)
            val start = CountDownLatch(1)
            val pool = Executors.newFixedThreadPool(2)
            try {
                val replay = pool.submit { start.await(); if (seen.markSeen("h")) handled.incrementAndGet() }
                val listen = pool.submit { start.await(); if (seen.markSeen("h")) handled.incrementAndGet() }
                start.countDown()
                replay.get(5, TimeUnit.SECONDS); listen.get(5, TimeUnit.SECONDS)
            } finally {
                pool.shutdown()
            }
            assertEquals("handled exactly once", 1, handled.get())
        }
    }

    @Test
    fun forgetLetsAReplayThroughAgainAndTheSetIsBounded() {
        val seen = SeenArmor(limit = 3)
        assertTrue(seen.markSeen("a")); assertFalse(seen.markSeen("a"))
        seen.forget("a")
        assertTrue(seen.markSeen("a"))
        seen.clear()
        assertTrue(seen.markSeen("a"))
        for (h in listOf("b", "c", "d", "e")) seen.markSeen(h)
        assertTrue("the oldest fell out of the last 3", seen.markSeen("a"))
    }

    @Test
    fun theFinishInitReplayRunsOnTheIoPoolAndNoDecryptRemainsInTheReplayFunction() {
        val finish = module.substringAfter("private fun finishInit(").substringBefore("private fun ")
        assertTrue(finish.contains("if (s.deferAck) replayInbox(ctx, s)"))
        val replay = module.substringAfter("private fun replayInbox(ctx: Context, s: Session) {").substringBefore("/**")
        assertTrue("the replay is scheduled on the io pool", replay.contains("execute = { io.execute(it) }"))
        assertTrue(replay.contains("InboxReplay.start("))
        assertFalse("no direct decrypt loop on the calling thread", replay.contains("for (e in stored)"))
        assertTrue("the dedupe is the thread-safe one", module.contains("private val seenArmor = network.conet.chat.nativekey.SeenArmor()"))
        // the init answer (ready) is emitted before the replay is scheduled, exactly as before
        assertTrue(finish.indexOf("emitEvent(InitReadyAnswer.payload(reqId, pgpStoreUnreadable(ctx)))") < finish.indexOf("if (s.deferAck) replayInbox(ctx, s)"))
    }

    // ---- a failing handler's not_ready reaches the caller's own emit --------------------------------------------------

    private val replyOnlyNames: List<String> = Regex("""REPLY_ONLY_COMMANDS: Set<String> = setOf\(([^)]*)\)""").find(module)!!.groupValues[1]
        .split(",").map { it.trim().trim('"') }.filter { it.isNotEmpty() }

    /** What handleCommand does: an exception that escapes the handler is answered not_ready once, unless the request was already answered. */
    private fun run(r: EventRouter, replyOnly: Boolean, emit: (JSONObject) -> Unit, reqId: Any?, handler: () -> Unit) {
        val answered = java.util.Collections.synchronizedSet(HashSet<String>())
        r.commandGuarded(replyOnly, emit, reqId, onException = { _ ->
            if (CommandAnswerGuard.firstAnswer(answered, reqId)) {
                val p = JSONObject().put("type", "ack").put("reqId", reqId ?: JSONObject.NULL).put("ok", false).put("error", "not_ready")
                CommandAnswerGuard.keyOf(p.opt("reqId"))?.let { answered.add(it) }
                (r.replyFor(p) ?: r.events)?.invoke(p)
            }
        }) { handler() }
    }

    @Test
    fun everyReplyOnlyCommandThatThrowsAnswersNotReadyOnItsOwnEmitAndTheChatEmitGetsNothing() {
        assertEquals("the eleven page sync commands", 11, replyOnlyNames.size)
        for ((i, name) in replyOnlyNames.withIndex()) {
            val r = EventRouter()
            val chat = Sink(); val own = Sink()
            r.command(false, chat.emit, 1) { }
            val id = 1000L + i
            run(r, true, own.emit, id) { throw IllegalStateException("handler failed: $name") }
            assertEquals("$name: the caller got the answer", 1, own.got.size)
            assertEquals("$name", "not_ready", own.got[0].getString("error"))
            assertFalse(own.got[0].getBoolean("ok"))
            assertEquals("$name: reqId echoed", id, own.got[0].getLong("reqId"))
            assertEquals("$name: the chat emit received nothing", 0, chat.got.size)
        }
    }

    @Test
    fun aChatCommandThatThrowsStillAnswersOnTheChatEmit() {
        val r = EventRouter()
        val chat = Sink()
        run(r, false, chat.emit, 7) { throw IllegalStateException("x") }
        assertEquals(1, chat.got.size)
        assertEquals("not_ready", chat.got[0].getString("error"))
    }

    @Test
    fun aReplyOnlyHandlerThatAnsweredAndThenThrewIsNotAnsweredTwice() {
        val r = EventRouter()
        val chat = Sink(); val own = Sink()
        r.command(false, chat.emit, 1) { }
        val answered = java.util.Collections.synchronizedSet(HashSet<String>())
        r.commandGuarded(true, own.emit, 5, onException = { _ ->
            if (CommandAnswerGuard.firstAnswer(answered, 5)) own.got += JSONObject().put("type", "ack").put("error", "not_ready")
        }) {
            val p = ack(5)
            answered.add("5") // emitEvent records an answered id
            (r.replyFor(p) ?: r.events)?.invoke(p)
            throw IllegalStateException("after the answer")
        }
        assertEquals("one ack, its own", 1, own.got.size)
        assertEquals(0, chat.got.size)
    }

    @Test
    fun anErrorFromAReplyOnlyHandlerIsNotAnsweredAndTheRegistrationIsGone() {
        val r = EventRouter()
        val chat = Sink(); val own = Sink()
        r.command(false, chat.emit, 1) { }
        var failureHandled = false
        val oom = OutOfMemoryError("simulated")
        try {
            r.commandGuarded(true, own.emit, 5, onException = { failureHandled = true }) { throw oom }
            throw AssertionError("the Error was swallowed")
        } catch (e: OutOfMemoryError) {
            assertSame(oom, e)
        }
        assertFalse("an Error is not an answer", failureHandled)
        assertEquals(0, own.got.size); assertEquals(0, chat.got.size)
        assertNull("the registration did not outlive the Error", r.replyFor(ack(5)))
    }
}
