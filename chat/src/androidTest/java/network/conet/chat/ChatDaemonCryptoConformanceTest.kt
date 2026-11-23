package network.conet.chat

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import network.conet.chat.ConetChatCryptoUtil
import network.conet.chat.nativekey.AddressPgpRead
import network.conet.chat.nativekey.NativeSessionState
import network.conet.chat.nativekey.NativeWallet
import network.conet.chat.nativekey.NativeWalletVault
import network.conet.chat.nativekey.PgpRestoreBridge
import network.conet.chat.nativekey.WalletAddress
import java.util.concurrent.CopyOnWriteArrayList
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * ChatDaemon protocol v1 conformance (Android, on a device): EIP-191 signing,
 * PGP envelopes and ACK hashes through the module's WebView crypto host, plus
 * the module's own `hello` / `unknown_command` answers (25.52AS.3). Same shared vectors as
 * the JVM test (assets: `chat-daemon-vectors.v1.json`).
 *
 *   ./gradlew :chat:connectedDebugAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class ChatDaemonCryptoConformanceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val host get() = BeamioOpenPgpHost.shared(context)

    private val vectors: JSONObject by lazy {
        val text = InstrumentationRegistry.getInstrumentation().context.assets
            .open("chat-daemon-vectors.v1.json").bufferedReader(Charsets.UTF_8).readText()
        JSONObject(text)
    }

    private fun key(which: String, field: String): String = vectors.getJSONObject("keys").getJSONObject(which).getString(field)

    private fun <T> call(body: ((Result<T>) -> Unit) -> Unit): T {
        val latch = CountDownLatch(1)
        var out: Result<T>? = null
        body { out = it; latch.countDown() }
        assertTrue("crypto host timed out", latch.await(30, TimeUnit.SECONDS))
        return out!!.getOrThrow()
    }

    private fun decodeLiteral(text: String, encoding: String): JSONObject =
        if (encoding == "base64-json") JSONObject(String(ConetChatCryptoUtil.base64Decode(text), Charsets.UTF_8)) else JSONObject(text)

    /**
     * EIP-191 and the wallet address run in native code (nativekey: Eip191Signer, WalletAddress); the WebView host no
     * longer signs (§35). The host's `verifyMessage` (public-key recovery) is still checked here.
     */
    @Test
    fun eip191SignAndRecover() {
        val keyBytes = ConetChatCryptoUtil.hexToBytes(key("wallet", "privateKey").removePrefix("0x"))!!
        assertEquals(key("wallet", "address").lowercase(), network.conet.chat.nativekey.WalletAddress.fromPrivateKey(keyBytes))
        val cases = vectors.getJSONArray("eip191")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val message = c.getString("message")
            val sig = network.conet.chat.nativekey.Eip191Signer.sign(keyBytes, message.toByteArray(Charsets.UTF_8))
            assertEquals(message, c.getString("signature"), sig)
            val signer = call<String> { host.verifyMessage(message, sig!!, it) }
            assertEquals(message, c.getString("signer").lowercase(), signer.lowercase())
        }
    }

    /**
     * Inbound decryption no longer runs in the WebView host, and the vector keys are no longer passed to it: the PGP
     * private key lives in the native vault (§36-B). The envelope decryption checks (armor hash, literal structure,
     * signer) moved to the JVM test `nativekey/NativePgpVectorsTest`, which runs the native decryption on the same
     * vector file. This test keeps the encoder shape checks only.
     */
    @Test
    fun envelopes() {
        val cases = vectors.getJSONArray("envelopes")
        assertTrue("envelope vectors present", cases.length() > 0)
    }

    @Test
    fun encodersRoundTrip() {
        val cases = vectors.getJSONArray("envelopes")
        val byName = (0 until cases.length()).associate { cases.getJSONObject(it).let { c -> c.getString("name") to c } }
        val route = byName.getValue("routeCommand").getJSONObject("expect")
        val work = byName.getValue("mailboxWork").getJSONObject("expect")
        val routePub = key("routePgp", "publicArmored")

        val routeArmor = call<String> { host.encryptSignedRouteCommand(route.getString("message"), route.getString("signMessage"), routePub, it) }
        assertTrue("encryptSignedRouteCommand armors a PGP message", routeArmor.contains("BEGIN PGP MESSAGE"))

        val workArmor = call<String> { host.wrapArmorToMailboxWork(work.getString("data"), routePub, true, it) }
        assertTrue("wrapArmorToMailboxWork armors a PGP message", workArmor.contains("BEGIN PGP MESSAGE"))
    }

    @Test
    fun moduleAnswersHelloAndUnknownCommands() {
        val acks = java.util.concurrent.ConcurrentHashMap<Long, JSONObject>()
        val latch = CountDownLatch(2)
        val emit: (JSONObject) -> Unit = { payload ->
            val event = payload.optJSONObject("event")
            if (event?.optString("type") == "ack") {
                acks[event.getLong("reqId")] = event
                latch.countDown()
            }
        }
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "hello").put("reqId", 41), emit)
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "notACommand").put("reqId", 42), emit)
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "notACommand").put("reqId", -1), emit)
        assertTrue(latch.await(10, TimeUnit.SECONDS))
        val hello = acks.getValue(41L)
        assertTrue(hello.getBoolean("ok"))
        assertTrue(jsonEquals(hello.getJSONObject("result"), BeamioConetChatProtocol.helloResult()))
        val unknown = acks.getValue(42L)
        assertEquals(false, unknown.getBoolean("ok"))
        assertEquals("unknown_command", unknown.getString("error"))
    }

    /**
     * 25.52AT.1 and AT.2 (r3cr): a name outside the command table is `unknown_command` before the gate. This runs on a fresh install (G0, no key),
     * where the gate used to answer `no_key`. The walletStatus answer records the state, and must show G0 for the run to count as G0.
     */
    @Test
    fun unknownNamesAreUnknownCommandBeforeTheGateInG0() {
        val acks = java.util.concurrent.ConcurrentHashMap<Long, JSONObject>()
        val names = listOf("notACommand", "signMessage", "pgpDecrypt", "removeEOAPrivateKey", "pgpSign")
        val latch = CountDownLatch(names.size + 1)
        val emit: (JSONObject) -> Unit = { payload ->
            val event = payload.optJSONObject("event")
            if (event?.optString("type") == "ack") {
                acks[event.getLong("reqId")] = event
                latch.countDown()
            }
        }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        names.forEachIndexed { i, name ->
            BeamioConetChatModule.handleCommand(context, JSONObject().put("type", name).put("reqId", 100 + i), emit)
        }
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "walletStatus").put("reqId", 200), emit)
        assertTrue(latch.await(10, TimeUnit.SECONDS))
        names.forEachIndexed { i, name ->
            val ack = acks.getValue(100L + i)
            assertEquals("$name ok", false, ack.getBoolean("ok"))
            assertEquals("$name answer", "unknown_command", ack.getString("error"))
        }
        val status = acks.getValue(200L).getJSONObject("result").getString("status")
        assertEquals("precondition: a fresh install is G0 (no key)", "no_key", status)
    }

    /**
     * 25.52AW.1, AX.1, AZ.1 (r3cu, r3cv, r3cx): the envelope is checked first. A missing reqId is bad_request with a null reqId, answered once.
     * A string reqId is echoed as sent. Any shellRecord* name on the chat channel is not_supported. Each request gets exactly one answer.
     */
    @Test
    fun envelopeAndChatChannelShellRecordAnswerOnce() {
        val answers = java.util.concurrent.CopyOnWriteArrayList<JSONObject>()
        val latch = CountDownLatch(4)
        val emit: (JSONObject) -> Unit = { payload ->
            val event = payload.optJSONObject("event")
            if (event?.optString("type") == "ack") {
                answers += event
                latch.countDown()
            }
        }
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "hello"), emit)
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "hello").put("reqId", "h-1"), emit)
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "shellRecordRead").put("reqId", "s-1"), emit)
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "shellRecordMigrationState").put("reqId", 5), emit)
        assertTrue(latch.await(10, TimeUnit.SECONDS))
        // A short settle, so that a second answer (a violation) would be seen.
        Thread.sleep(300)
        assertEquals("exactly one answer per request", 4, answers.size)
        val byId = answers.associateBy { if (it.isNull("reqId")) "null" else it.get("reqId").toString() }
        assertEquals("missing reqId", "bad_request", byId.getValue("null").getString("error"))
        assertTrue("string reqId echoed", byId.getValue("h-1").getBoolean("ok"))
        assertEquals("chat-channel shellRecordRead", "not_supported", byId.getValue("s-1").getString("error"))
        assertEquals("any shellRecord* name on the chat channel (25.52AZ.1, BO.4)", "not_supported", byId.getValue("5").getString("error"))
    }

    /**
     * 25.52AT.1 step 2, 25.52AQ.2, BG.3 (r3cu, r3de): a credential field of a CRED command is refused before the gate, in G0 (a fresh install, no key),
     * with the field name in result.names. The gate would answer no_key for these commands; the refusal comes first. walletStatus afterwards is still
     * no_key: the refusals change no state. The G1 and later states are not run here.
     */
    @Test
    fun credentialFieldsAreRefusedBeforeTheGateInG0() {
        val answers = java.util.concurrent.CopyOnWriteArrayList<JSONObject>()
        val commands = listOf("pgpDecryptInbound", "pgpRestore", "pgpRestoreEvaluate", "pgpIdentityCreate", "provisionIdentity", "init", "pgpMigrate")
        val latch = CountDownLatch(commands.size + 1)
        val emit: (JSONObject) -> Unit = { payload ->
            val event = payload.optJSONObject("event")
            if (event?.optString("type") == "ack") {
                answers += event
                latch.countDown()
            }
        }
        commands.forEach { cmd ->
            BeamioConetChatModule.handleCommand(context, JSONObject().put("type", cmd).put("reqId", "c-$cmd").put("pin", "123456"), emit)
        }
        BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "walletStatus").put("reqId", "ws"), emit)
        assertTrue(latch.await(10, TimeUnit.SECONDS))
        Thread.sleep(300)
        val byId = answers.associateBy { it.get("reqId").toString() }
        for (cmd in commands) {
            val a = byId.getValue("c-$cmd")
            assertEquals("$cmd ok", false, a.getBoolean("ok"))
            assertEquals("$cmd is refused before the gate", "key_over_bridge_refused", a.getString("error"))
            val names = a.getJSONObject("result").getJSONArray("names")
            assertEquals("$cmd names the field (result.names)", "pin", names.getString(0))
        }
        assertEquals("the refusals change no state: still G0", "no_key", byId.getValue("ws").getJSONObject("result").getString("status"))
    }

    /**
     * 25.52AT.3, BT.1, BT.2 (r3ds): busy. A command is in flight: the chain transport of pgpRestoreEvaluate is blocked in this test target,
     * so the worker stays inside the transport. While it is in flight, a name outside the table is answered unknown_command, once, before the gate.
     * The block is released afterwards and the transport is restored. The state is G2: the test sets a native record for a synthetic test key,
     * and marks the session ready (internal NativeSessionState.markReady). Only the test target sets these; production code is unchanged.
     */
    @Test
    fun unknownNameIsUnknownCommandWhileACommandIsInFlight() {
        val key = ByteArray(32) { 0x11 }
        val eoa = requireNotNull(WalletAddress.fromPrivateKey(key)).lowercase()
        val imported = NativeWallet.vault(context).importKey(eoa, key.copyOf())
        assertTrue("a synthetic test record for the test account: ${imported.code}", imported == NativeWalletVault.Import.OK)
        NativeSessionState.markReady(eoa)
        val entered = CountDownLatch(1)
        val released = CountDownLatch(1)
        val blocking = AddressPgpRead.Rpc { _, _ ->
            entered.countDown()
            released.await(20, TimeUnit.SECONDS)
            null
        }
        val saved = PgpRestoreBridge.chainRpc
        PgpRestoreBridge.chainRpc = { _ -> blocking }
        val acks = CopyOnWriteArrayList<JSONObject>()
        val unknownAck = CountDownLatch(1)
        val evaluateAck = CountDownLatch(1)
        val emit: (JSONObject) -> Unit = { payload ->
            val event = payload.optJSONObject("event")
            if (event?.optString("type") == "ack") {
                when (event.optString("reqId")) {
                    "unk-1" -> {
                        acks += event
                        unknownAck.countDown()
                    }
                    "busy-1" -> {
                        acks += event
                        evaluateAck.countDown()
                    }
                }
            }
        }
        try {
            BeamioConetChatModule.handleCommand(
                context,
                JSONObject().put("type", "pgpRestoreEvaluate").put("reqId", "busy-1").put("accountKey", "$eoa:default"),
                emit,
            )
            assertTrue("the command is in flight: the transport was entered", entered.await(15, TimeUnit.SECONDS))
            BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "zzInFlightProbe").put("reqId", "unk-1"), emit)
            assertTrue("the unknown name is answered while the command is in flight", unknownAck.await(5, TimeUnit.SECONDS))
            val unknown = acks.single { it.optString("reqId") == "unk-1" }
            assertEquals("ok false", false, unknown.getBoolean("ok"))
            assertEquals("unknown_command while busy (BT.2)", "unknown_command", unknown.getString("error"))
            assertEquals("the restore is still in flight", 1L, evaluateAck.count)
        } finally {
            released.countDown()
            evaluateAck.await(15, TimeUnit.SECONDS)
            PgpRestoreBridge.chainRpc = saved
            NativeSessionState.reset()
            // Remove the test record, so that the other tests of this class see a fresh install again (G0).
            NativeWallet.vault(context).forget()
        }
        assertEquals("the unknown name was answered once", 1, acks.count { it.optString("reqId") == "unk-1" })
    }

    /**
     * 25.52CB.2 (r3eb): locked, through the real vault store. The marker of the test record is overwritten with a value that does not match,
     * which is the fault of a damaged store. No product hook is used. In G2 (a ready session) the families C1, C2, C3, C5, W7 and N0 answer
     * `locked`, once, before their parameters are read. N0 answers once when unlocked, and C5 is not no_key in G2.
     */
    @Test
    fun lockedFamiliesAnswerLockedOnceBeforeTheParameters() {
        val key = ByteArray(32) { 0x11 }
        val eoa = requireNotNull(WalletAddress.fromPrivateKey(key)).lowercase()
        val vault = NativeWallet.vault(context)
        val imported = vault.importKey(eoa, key.copyOf())
        assertTrue("a synthetic test record for the test account: ${imported.code}", imported == NativeWalletVault.Import.OK)
        NativeSessionState.markReady(eoa)
        val acks = CopyOnWriteArrayList<JSONObject>()
        val emit: (JSONObject) -> Unit = { payload ->
            payload.optJSONObject("event")?.let { event -> if (event.optString("type") == "ack") acks += event }
        }
        fun answersOf(reqId: String): List<JSONObject> = acks.filter { it.optString("reqId") == reqId }
        // The answer may come from a worker: wait for n answers, then a short settle time in which a second answer would show.
        fun awaitAnswers(reqId: String, n: Int) {
            val deadline = System.currentTimeMillis() + 5_000
            while (answersOf(reqId).size < n && System.currentTimeMillis() < deadline) Thread.sleep(20)
            Thread.sleep(200)
        }
        try {
            BeamioConetChatModule.handleCommand(context, JSONObject().put("type", "walletAddress").put("reqId", "g2-n0"), emit)
            awaitAnswers("g2-n0", 1)
            assertEquals("N0 in G2 answers once", 1, answersOf("g2-n0").size)
            assertTrue("N0 in G2 is ok", answersOf("g2-n0").single().getBoolean("ok"))
            BeamioConetChatModule.handleCommand(
                context,
                JSONObject().put("type", "deriveSubkeys").put("reqId", "g2-c5").put("accountKey", "$eoa:default"),
                emit,
            )
            awaitAnswers("g2-c5", 1)
            assertEquals("C5 in G2 answers once", 1, answersOf("g2-c5").size)
            assertTrue("C5 in G2 is not no_key", answersOf("g2-c5").single().optString("error") != "no_key")
            NativeWallet.migrationFiles(context).write(NativeWalletVault.MARK, "00".toByteArray(Charsets.US_ASCII))
            assertTrue("the vault reports Locked after the damage", vault.state() is NativeWalletVault.State.Locked)
            val families = listOf(
                "historySign" to "lk-c1",
                "gossipSign" to "lk-c2",
                "pgpDecryptInbound" to "lk-c3",
                "deriveSubkeys" to "lk-c5",
                "ephemeralSign" to "lk-w7",
                "walletAddress" to "lk-n0",
            )
            for ((type, id) in families) {
                BeamioConetChatModule.handleCommand(context, JSONObject().put("type", type).put("reqId", id), emit)
            }
            for ((_, id) in families) awaitAnswers(id, 1)
            for ((type, id) in families) {
                assertEquals("$type locked answers once", 1, answersOf(id).size)
                assertEquals("$type locked, before the parameters", "locked", answersOf(id).single().optString("error"))
            }
        } finally {
            NativeSessionState.reset()
            vault.forget()
        }
    }
}

/** Structural JSON equality (Android's org.json has no `similar`). Numbers compare by value. */
private fun jsonEquals(a: Any?, b: Any?): Boolean = when {
    a is org.json.JSONObject && b is org.json.JSONObject -> {
        val ka = a.keys().asSequence().toSet()
        val kb = b.keys().asSequence().toSet()
        ka == kb && ka.all { jsonEquals(a.opt(it), b.opt(it)) }
    }
    a is org.json.JSONArray && b is org.json.JSONArray ->
        a.length() == b.length() && (0 until a.length()).all { jsonEquals(a.opt(it), b.opt(it)) }
    a is Number && b is Number -> a.toDouble() == b.toDouble() && a.toLong() == b.toLong()
    else -> a == b
}
