package network.conet.chat.nativekey

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * The first identity of a new account: the S0 to S6 machine over synthetic fixtures (a fake chain, a fake poster, an in-memory
 * vault and K store). No network, no transaction, no production key.
 */
class FirstIdentityCoordinatorTest {
    private val random = SecureRandom()
    private val account = "0x" + "ab".repeat(20)
    private val accountKey = ByteArray(32).also { it[31] = 1 }
    private val route = "ABCDEF0123456789"

    @org.junit.Before
    fun resetAttempts() {
        FirstIdentityCoordinator.resetAttemptsForTests()
        PublicIdentitySnapshot.resetForTests()
    }

    /** One fake world: a vault directory, a K store, a scripted chain, a poster that records what it was given. */
    private inner class World {
        val files = NativeTestFiles()
        val wrap = NativeTestWrap()
        val dev = PgpRestoreDevice("d", account, wrap, files)
        val kBackend = MemoryAccountPgpKBackend()
        val k = AccountPgpK(kBackend)
        var keyRead: RegisteredKeyRead = RegisteredKeyRead.Absent
        var legacy: Boolean? = false
        var routeId: String? = route
        var routeUnreadable = false
        /** What the identity read answers, one entry per read; the last one repeats. */
        var identityScript: MutableList<(RegistrationReadback.Expected?) -> ChainIdentityRead> = mutableListOf()
        var lastExpected: RegistrationReadback.Expected? = null
        var generated = 0
        var posts = mutableListOf<JSONObject>()
        var postAnswer: () -> ChatRouteSubmit.Transport = { ChatRouteSubmit.Transport.Answer(200, "{\"ok\":true}") }
        var flightFree = true
        val events = mutableListOf<String>()
        val statuses = mutableListOf<FirstIdentityStatus>()
        val logs = mutableListOf<String>()
        var injectedKey: RecPgp? = null
        var failOnGenerate = false
        var lock: () -> LockState = { LockState.UNLOCKED }

        /** The chain holds [key] on [route] once the poster has been called [afterPosts] times (0 = already). */
        fun chainHoldsOurKeyAfterPosts(afterPosts: Int, key: () -> PgpIdentity?) {
            identityScript = mutableListOf({ _ ->
                val id = key()
                if (posts.size >= afterPosts && id != null) ChainIdentityRead.Present(ChainIdentityView(id.fingerprint, id.subkeyKeyId, route)) else ChainIdentityRead.Absent
            })
        }

        fun coordinator(mode: FirstIdentityCoordinator.Mode = FirstIdentityCoordinator.Mode.FULL): FirstIdentityCoordinator = FirstIdentityCoordinator(
            eoa = account, dev = dev, k = k,
            readKey = { keyRead },
            readIdentity = {
                val f = identityScript.firstOrNull() ?: { _: RegistrationReadback.Expected? -> ChainIdentityRead.Absent }
                if (identityScript.size > 1) identityScript.removeAt(0)
                f(lastExpected)
            },
            legacyKeyPresent = { legacy },
            generate = {
                if (failOnGenerate) throw AssertionError("a key was generated")
                generated++
                val g = injectedKey?.let { NativePgpKeyGen.Generated(it.privateArmor, it.publicArmor, it.identity.fingerprint) } ?: NativePgpKeyGen.generate(account, random)
                g
            },
            chooseRoute = { if (routeUnreadable) RouteChoice.Unreadable else routeId?.let { RouteChoice.Ok(it) } ?: RouteChoice.None },
            eoaKey = { accountKey.copyOf() },
            bases = listOf("https://beamio.test"),
            poster = ChatRouteSubmit.Poster { _, json, _ ->
                posts += JSONObject(json)
                postAnswer()
            },
            sleep = { true },
            pollDelaysMs = longArrayOf(1, 1, 1),
            nowMs = { 1_700_000_000_000L },
            flightEnter = { flightFree },
            flightExit = { },
            log = { logs += it },
            emit = { events += it.state; statuses += it },
            lockState = { lock() },
            mode = mode,
        )

        /** The identity of the key that ended pending (or active). */
        fun pendingIdentity(): PgpIdentity? = dev.pending.identity()
        fun activeIdentity(): PgpIdentity? = dev.active.identity()
    }

    // ---- the happy path ------------------------------------------------------------------------------------------------------------------

    @Test
    fun aConfirmedNoRecordGeneratesRegistersReadsBackActivatesAndMirrors() {
        val w = World()
        // The chain shows our key once the submission was made (we learn the identity from the pending key as soon as it exists).
        w.chainHoldsOurKeyAfterPosts(1) { w.pendingIdentity() ?: w.activeIdentity() }
        val r = w.coordinator().run()
        assertEquals("registered", r.code)
        assertEquals("one key generated", 1, w.generated)
        assertEquals("one submission", 1, w.posts.size)
        assertTrue("active holds the key", w.dev.active.state() is NativePgpVault.State.Ready)
        assertTrue("pending is gone", w.dev.pending.state() is NativePgpVault.State.NoKey)
        assertNull("the registering marker is gone", w.dev.registeringMark())
        // K is mirrored with the same key.
        val kItem = w.k.read(account, PgpMigrationPolicy.WORKSPACE)!!
        assertEquals(w.activeIdentity()!!.subkeyKeyId, kItem.getString("keyId"))
        assertEquals("a status of its own for each step: registering with its reason, then registered", listOf("registering", "registered"), w.events)
        // The submitted body is the existing eight-field shape and carries no plaintext private key.
        val body = w.posts.single()
        assertEquals(account, body.getString("wallet"))
        assertEquals(route, body.getString("routeKeyID"))
        assertFalse("no private key in the body", body.toString().contains("PRIVATE KEY"))
        assertTrue(w.logs.any { it.contains(FIRST_IDENTITY_APPROVAL) })
    }

    @Test
    fun theGenerationApprovalIsARecordAndTheGlobalFlagStaysFalse() {
        assertEquals("confirmed-no-record", FIRST_IDENTITY_APPROVAL)
        assertFalse(PgpMigrationPolicy.OPENPGP_APPROVED)
    }

    // ---- the three chain reads at S1 -----------------------------------------------------------------------------------------------------

    @Test
    fun anUnreadableChainNeverGeneratesNorTouchesAnything() {
        val w = World().also { it.keyRead = RegisteredKeyRead.Unknown; it.failOnGenerate = true }
        val r = w.coordinator().run()
        assertEquals("retry_later:chain_unreadable", r.code)
        assertTrue(w.dev.pending.state() is NativePgpVault.State.NoKey)
        assertTrue(w.files.map.isEmpty())
        assertTrue(w.posts.isEmpty())
        assertEquals(listOf("retry_later"), w.events)
    }

    @Test
    fun aRegisteredChainIsTheApprovedRecoveryNotAGeneration() {
        val w = World()
        w.keyRead = registeredOf(RecKeys.generate(account, random), account)
        w.failOnGenerate = true
        val r = w.coordinator().run()
        assertTrue(r is FirstIdentityCoordinator.Result.Recovery)
        assertTrue(w.files.map.isEmpty())
        assertTrue(w.posts.isEmpty())
    }

    @Test
    fun aKeyAnOlderBuildLeftInTheSdkStoreIsNeverReplacedByAGeneratedOne() {
        for (legacy in listOf(true, null)) {
            val w = World().also { it.legacy = legacy; it.failOnGenerate = true }
            val r = w.coordinator().run()
            assertEquals(if (legacy == true) "retry_later:legacy_key_present" else "retry_later:legacy_unreadable", r.code)
            assertTrue(w.files.map.isEmpty())
        }
    }

    @Test
    fun noRouteCandidateMeansNoGeneration() {
        val w = World().also { it.routeId = null; it.failOnGenerate = true }
        assertEquals("retry_later:no_route", w.coordinator().run().code)
        assertTrue(w.files.map.isEmpty())
    }

    // ---- the account that has only an old K ------------------------------------------------------------------------------------------------

    private fun seedOldK(w: World): RecPgp {
        val old = RecKeys.generate(account, random)
        assertTrue(w.k.write(account, PgpMigrationPolicy.WORKSPACE, old.identity.subkeyKeyId, old.publicArmor, old.privateArmor, 1L))
        return old
    }

    @Test
    fun aKOnlyAccountWithAConfirmedNoRecordDiscardsTheOldKeyAndRegistersANewOne() {
        val w = World()
        val old = seedOldK(w)
        w.chainHoldsOurKeyAfterPosts(1) { w.pendingIdentity() ?: w.activeIdentity() }
        assertEquals("registered", w.coordinator().run().code)
        val kItem = w.k.read(account, PgpMigrationPolicy.WORKSPACE)!!
        assertNotEquals("the old key is not adopted", old.identity.subkeyKeyId, kItem.getString("keyId"))
        assertNotEquals(old.privateArmor, kItem.getString("privateKeyArmor"))
        assertEquals(w.activeIdentity()!!.subkeyKeyId, kItem.getString("keyId"))
    }

    @Test
    fun aKOnlyAccountWhoseChainIsRegisteredOrUnreadableKeepsItsK() {
        for (read in listOf(registeredOf(RecKeys.generate(account, random), account), RegisteredKeyRead.Unknown)) {
            val w = World()
            val old = seedOldK(w)
            w.keyRead = read
            w.failOnGenerate = true
            w.coordinator().run()
            assertEquals(old.identity.subkeyKeyId, w.k.read(account, PgpMigrationPolicy.WORKSPACE)!!.getString("keyId"))
        }
    }

    @Test
    fun aKDiscardThatFailsStopsBeforeGenerating() {
        val w = World()
        val old = seedOldK(w)
        val stuck = object : AccountPgpKBackend {
            override fun get(name: String) = w.kBackend.get(name)
            override fun put(name: String, value: String) = w.kBackend.put(name, value)
            override fun names() = w.kBackend.names()
            override fun remove(name: String) = false
        }
        w.failOnGenerate = true
        val c = FirstIdentityCoordinator(
            eoa = account, dev = w.dev, k = AccountPgpK(stuck), readKey = { RegisteredKeyRead.Absent }, readIdentity = { ChainIdentityRead.Absent },
            legacyKeyPresent = { false }, generate = { throw AssertionError("generated") }, chooseRoute = { RouteChoice.Ok(route) }, eoaKey = { accountKey.copyOf() },
            bases = listOf("https://beamio.test"), poster = ChatRouteSubmit.Poster { _, _, _ -> throw AssertionError("posted") },
        )
        assertEquals("retry_later:k_discard_failed", c.run().code)
        assertEquals(old.identity.subkeyKeyId, w.k.read(account, PgpMigrationPolicy.WORKSPACE)!!.getString("keyId"))
    }

    // ---- S3: the read before the submission ----------------------------------------------------------------------------------------------

    @Test
    fun aPendingKeyWithItsMetadataResumesAndIsNeverRegenerated() {
        val w = World()
        val pending = RecKeys.generate(account, random)
        assertEquals(NativePgpVault.Put.OK, w.dev.pending.put(account, pending.privateArmor, ""))
        w.dev.writePendingMeta(PendingMeta("idem-1", 0L, "first"))
        w.failOnGenerate = true
        w.chainHoldsOurKeyAfterPosts(1) { pending.identity }
        assertEquals("registered", w.coordinator().run().code)
        assertEquals(0, w.generated)
        assertEquals(pending.identity.subkeyKeyId, w.activeIdentity()!!.subkeyKeyId)
        assertEquals("idem-1", w.dev.completedIdem())
    }

    @Test
    fun ifTheChainAlreadyHoldsOurKeyNothingIsSubmittedAgain() {
        val w = World()
        val pending = RecKeys.generate(account, random)
        w.dev.pending.put(account, pending.privateArmor, "")
        w.dev.writePendingMeta(PendingMeta("idem-2", 0L, "first"))
        w.identityScript = mutableListOf({ _ -> ChainIdentityRead.Present(ChainIdentityView(pending.identity.fingerprint, pending.identity.subkeyKeyId, route)) })
        assertEquals("registered", w.coordinator().run().code)
        assertTrue("no second submission", w.posts.isEmpty())
        assertEquals(pending.identity.subkeyKeyId, w.activeIdentity()!!.subkeyKeyId)
    }

    @Test
    fun anotherKeyOnTheChainIsAConflictNothingIsSubmittedAndTheChainKeyIsNotOverwritten() {
        val w = World()
        val pending = RecKeys.generate(account, random)
        val other = RecKeys.generate(account, random)
        w.dev.pending.put(account, pending.privateArmor, "")
        w.dev.writePendingMeta(PendingMeta("idem-3", 0L, "first"))
        w.identityScript = mutableListOf({ _ -> ChainIdentityRead.Present(ChainIdentityView(other.identity.fingerprint, other.identity.subkeyKeyId, route)) })
        val r = w.coordinator().run()
        assertEquals("conflict", r.code)
        assertTrue(w.posts.isEmpty())
        assertTrue("the never-registered pending key is erased", w.dev.pending.state() is NativePgpVault.State.NoKey)
        assertTrue("no active key", w.dev.active.state() is NativePgpVault.State.NoKey)
        assertTrue(w.k.existsFor(account, PgpMigrationPolicy.WORKSPACE).not())
    }

    @Test
    fun anUnreadableChainBeforeTheSubmissionStopsAndKeepsThePendingKey() {
        val w = World()
        val pending = RecKeys.generate(account, random)
        w.dev.pending.put(account, pending.privateArmor, "")
        w.dev.writePendingMeta(PendingMeta("idem-4", 0L, "first"))
        w.identityScript = mutableListOf({ _ -> ChainIdentityRead.Unknown })
        assertEquals("retry_later:chain_unreadable", w.coordinator().run().code)
        assertTrue(w.posts.isEmpty())
        assertTrue(w.dev.pending.state() is NativePgpVault.State.Ready)
    }

    // ---- S4/S5: the submission and the readback ------------------------------------------------------------------------------------------

    @Test
    fun aReadbackThatDoesNotShowTheKeyInTheWindowIsRetryLaterAndTheNextRunResignsTheSameKey() {
        val w = World()
        w.identityScript = mutableListOf({ _ -> ChainIdentityRead.Absent })
        val first = w.coordinator().run()
        assertEquals("retry_later:not_confirmed_in_window", first.code)
        assertEquals(1, w.posts.size)
        val pendingBefore = w.pendingIdentity()!!
        assertTrue("pending and the marker stay", w.dev.pending.state() is NativePgpVault.State.Ready && w.dev.registeringMark() != null)
        // The next run: the same pending key, a fresh signature (new nonce); this time the chain shows it.
        w.failOnGenerate = true
        w.chainHoldsOurKeyAfterPosts(2) { pendingBefore }
        assertEquals("registered", w.coordinator().run().code)
        assertEquals(2, w.posts.size)
        assertNotEquals("a new nonce for the new signature", w.posts[0].getString("nonce"), w.posts[1].getString("nonce"))
        assertEquals("the same key", w.posts[0].getString("keyID"), w.posts[1].getString("keyID"))
        assertEquals(pendingBefore.subkeyKeyId, w.activeIdentity()!!.subkeyKeyId)
        assertEquals("one generation in all", 1, w.generated)
    }

    @Test
    fun aTransportFailureIsRetryLaterAndAFourXxIsFailedNeverAnImmediateRetry() {
        val a = World().also { it.postAnswer = { ChatRouteSubmit.Transport.Unreachable } }
        assertEquals("retry_later:network_unavailable", a.coordinator().run().code)
        assertTrue("the pending key is kept", a.dev.pending.state() is NativePgpVault.State.Ready)
        val b = World().also { it.postAnswer = { ChatRouteSubmit.Transport.Answer(400, "{\"error\":\"x\"}") } }
        val r = b.coordinator().run()
        assertEquals("failed:chain_refused", r.code)
        assertEquals("a 4xx is not resent", 1, b.posts.size)
        assertEquals(listOf("registering", "failed"), b.events)
    }

    @Test
    fun aConflictAfterTheSubmissionIsNotResentAndTheActiveSlotStaysEmpty() {
        val w = World()
        val other = RecKeys.generate(account, random)
        // Absent before the submission, another key after it.
        w.identityScript = mutableListOf(
            { _ -> ChainIdentityRead.Absent },
            { _ -> ChainIdentityRead.Present(ChainIdentityView(other.identity.fingerprint, other.identity.subkeyKeyId, route)) },
        )
        assertEquals("conflict", w.coordinator().run().code)
        assertEquals(1, w.posts.size)
        assertTrue(w.dev.active.state() is NativePgpVault.State.NoKey)
        assertTrue(w.dev.pending.state() is NativePgpVault.State.NoKey)
    }

    @Test
    fun aKeyOnTheChainWithoutTheRouteIsNotYetComplete() {
        val w = World()
        w.identityScript = mutableListOf({ _ ->
            val id = w.pendingIdentity()
            if (id == null) ChainIdentityRead.Absent else ChainIdentityRead.Present(ChainIdentityView(id.fingerprint, id.subkeyKeyId, null))
        })
        assertEquals("retry_later:not_confirmed_in_window", w.coordinator().run().code)
        assertTrue(w.dev.active.state() is NativePgpVault.State.NoKey)
    }

    // ---- single flight and interruption --------------------------------------------------------------------------------------------------

    @Test
    fun aSecondCallerForTheSameAccountIsBusyAndSubmitsNothing() {
        val w = World()
        val pending = RecKeys.generate(account, random)
        w.dev.pending.put(account, pending.privateArmor, "")
        w.dev.writePendingMeta(PendingMeta("idem-5", 0L, "first"))
        w.flightFree = false
        assertEquals("retry_later:busy", w.coordinator().run().code)
        assertTrue(w.posts.isEmpty())
    }

    @Test
    fun theRealFlightAdmitsOneAccountAtATimeAndIsReleasedAfterwards() {
        IdentityRegisterFlight.resetForTests()
        assertTrue(IdentityRegisterFlight.tryEnter(account))
        assertFalse("the same account in another case is the same account", IdentityRegisterFlight.tryEnter(account.uppercase().replace("0X", "0x")))
        assertTrue("another account is free", IdentityRegisterFlight.tryEnter("0x" + "cd".repeat(20)))
        IdentityRegisterFlight.exit(account)
        assertTrue(IdentityRegisterFlight.tryEnter(account))
        IdentityRegisterFlight.resetForTests()
        val busy = IdentityRegisterFlight.runExclusive(account, { "busy" }, { IdentityRegisterFlight.runExclusive(account, { "inner busy" }, { "inner ran" }) })
        assertEquals("inner busy", busy)
        assertEquals("released after the body", "ran", IdentityRegisterFlight.runExclusive(account, { "busy" }, { "ran" }))
    }

    @Test
    fun anInterruptedActivationIsFinishedWithoutAnotherSubmission() {
        val w = World()
        val key = RecKeys.generate(account, random)
        // The active key is written, the cleanup is not: the pending key, its metadata and the marker are still there.
        assertEquals(NativePgpVault.Put.OK, w.dev.active.put(account, key.privateArmor, ""))
        assertEquals(NativePgpVault.Put.OK, w.dev.pending.put(account, key.privateArmor, ""))
        w.dev.writePendingMeta(PendingMeta("idem-6", 0L, "first"))
        w.dev.markRegistering(null)
        w.failOnGenerate = true
        assertEquals("registered", w.coordinator().run().code)
        assertTrue(w.posts.isEmpty())
        assertTrue(w.dev.pending.state() is NativePgpVault.State.NoKey)
        assertNull(w.dev.registeringMark())
        assertEquals(key.identity.subkeyKeyId, w.k.read(account, PgpMigrationPolicy.WORKSPACE)!!.getString("keyId"))
    }

    @Test
    fun aKMirrorThatFailsKeepsThePendingKeyAndOnlyTheMirrorIsRetried() {
        val w = World()
        val key = RecKeys.generate(account, random)
        w.dev.pending.put(account, key.privateArmor, "")
        w.dev.writePendingMeta(PendingMeta("idem-7", 0L, "first"))
        w.chainHoldsOurKeyAfterPosts(0) { key.identity }
        val failingK = object : AccountPgpKBackend {
            override fun get(name: String): String? = null
            override fun put(name: String, value: String) = false
            override fun names(): Set<String> = emptySet()
            override fun remove(name: String) = true
        }
        val c = FirstIdentityCoordinator(
            eoa = account, dev = w.dev, k = AccountPgpK(failingK), readKey = { RegisteredKeyRead.Absent },
            readIdentity = { ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, route)) },
            legacyKeyPresent = { false }, generate = { throw AssertionError("generated") }, chooseRoute = { RouteChoice.Ok(route) }, eoaKey = { accountKey.copyOf() },
            bases = listOf("https://beamio.test"), poster = ChatRouteSubmit.Poster { _, _, _ -> throw AssertionError("posted") },
        )
        assertEquals("retry_later:k_mirror_failed", c.run().code)
        assertTrue("the active key is written", w.dev.active.state() is NativePgpVault.State.Ready)
        assertTrue("the pending key is kept for the mirror retry", w.dev.pending.state() is NativePgpVault.State.Ready)
        // The next run with a working K finishes it without a second submission.
        w.chainHoldsOurKeyAfterPosts(0) { key.identity }
        assertEquals("registered", w.coordinator().run().code)
        assertTrue(w.posts.isEmpty())
    }

    // ---- an active key (a restored or older account): only its registration is reconciled -------------------------------------------------

    private fun worldWithActive(): Pair<World, RecPgp> {
        val w = World()
        val key = RecKeys.generate(account, random)
        assertEquals(NativePgpVault.Put.OK, w.dev.active.put(account, key.privateArmor, ""))
        w.failOnGenerate = true
        return w to key
    }

    private fun snapshot(w: World): Triple<Map<String, List<Byte>>, Map<String, String>, Int> =
        Triple(w.files.map.mapValues { it.value.toList() }, w.kBackend.items.toMap(), w.posts.size)

    @Test
    fun anActiveKeyWithItsRouteOnTheChainSubmitsNothingAndChangesNothing() {
        val (w, key) = worldWithActive()
        w.identityScript = mutableListOf({ _ -> ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, route)) })
        val before = snapshot(w)
        assertEquals("registered", w.coordinator().run().code)
        assertEquals(before, snapshot(w))
        assertEquals(0, w.generated)
    }

    @Test
    fun aFalseRouteOnlineFlagIsNotAnInputSoNothingIsRegisteredAgain() {
        // routeOnline is set only by a registered node wallet (setUserOnlineOnMe) and the node no longer writes it: false is normal. The view the
        // coordinator reads has no such field, so key and route on the chain mean done, whatever the flag says.
        val fields = ChainIdentityView::class.java.declaredFields.map { it.name.lowercase() }
        assertTrue("no online field in the chain view: $fields", fields.none { it.contains("online") })
        val (w, key) = worldWithActive()
        w.identityScript = mutableListOf({ _ -> ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, route)) })
        w.coordinator().run()
        assertTrue("no submission for a false online flag", w.posts.isEmpty())
        val src = File("src/main/java/network/conet/chat/nativekey/FirstIdentityCoordinator.kt").readText()
        assertFalse("the coordinator reads no online flag", Regex("""[^\w]routeOnline\s*[=(:]""").containsMatchIn(src.lines().filter { !it.trim().startsWith("*") && !it.trim().startsWith("//") }.joinToString("\n")))
    }

    @Test
    fun anActiveKeyWithoutARouteOnTheChainSubmitsThatKeyOnceReadsBackAndGeneratesNothing() {
        val (w, key) = worldWithActive()
        w.chainHoldsOurKeyAfterPosts(1) { key.identity }
        // Before the submission the chain has the key but no route (the script's first answer), after it the route is there.
        w.identityScript = mutableListOf(
            { _ -> ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, null)) },
            { _ -> if (w.posts.isNotEmpty()) ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, route)) else ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, null)) },
        )
        val r = w.coordinator().run()
        assertEquals("registered", r.code)
        assertEquals("exactly one registration", 1, w.posts.size)
        assertEquals("the same key", key.identity.subkeyKeyId, w.posts.single().getString("keyID"))
        assertEquals(route, w.posts.single().getString("routeKeyID"))
        assertEquals(0, w.generated)
        assertTrue("no pending key was made", w.dev.pending.state() is NativePgpVault.State.NoKey)
        assertTrue("no K was written", w.kBackend.items.isEmpty())
        assertEquals(listOf("registering", "registered"), w.events)
        val src = File("src/main/java/network/conet/chat/nativekey/FirstIdentityCoordinator.kt").readText()
        assertFalse("no addUser from the coordinator", src.contains("addUser") || src.contains("AccountRegister"))
    }

    @Test
    fun anActiveKeyThatTheChainDoesNotHoldIsRegisteredAsItIsAndNeverReplaced() {
        val (w, key) = worldWithActive()
        w.identityScript = mutableListOf(
            { _ -> ChainIdentityRead.Absent },
            { _ -> if (w.posts.isNotEmpty()) ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, route)) else ChainIdentityRead.Absent },
        )
        assertEquals("registered", w.coordinator().run().code)
        assertEquals(1, w.posts.size)
        assertEquals(key.identity.subkeyKeyId, w.activeIdentity()!!.subkeyKeyId)
        assertEquals(0, w.generated)
    }

    @Test
    fun anActiveKeyAgainstAnotherRegisteredKeyIsAConflictAndWritesNothing() {
        val (w, _) = worldWithActive()
        val other = RecKeys.generate(account, random)
        w.identityScript = mutableListOf({ _ -> ChainIdentityRead.Present(ChainIdentityView(other.identity.fingerprint, other.identity.subkeyKeyId, route)) })
        val before = snapshot(w)
        assertEquals("conflict", w.coordinator().run().code)
        assertEquals(before, snapshot(w))
    }

    @Test
    fun anActiveKeyOnAnUnreadableChainOrABusyFlightSubmitsNothing() {
        val (w, _) = worldWithActive()
        w.identityScript = mutableListOf({ _ -> ChainIdentityRead.Unknown })
        assertEquals("retry_later:chain_unreadable", w.coordinator().run().code)
        val (b, key) = worldWithActive()
        b.identityScript = mutableListOf({ _ -> ChainIdentityRead.Absent })
        b.flightFree = false
        assertEquals("retry_later:busy", b.coordinator().run().code)
        assertTrue(b.posts.isEmpty())
        assertTrue(w.posts.isEmpty())
        assertNotEquals(null, key)
    }

    @Test
    fun aSecondRunAfterTheRouteIsOnTheChainSubmitsNothingMore() {
        val (w, key) = worldWithActive()
        w.identityScript = mutableListOf(
            { _ -> ChainIdentityRead.Absent },
            { _ -> if (w.posts.isNotEmpty()) ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, route)) else ChainIdentityRead.Absent },
        )
        assertEquals("registered", w.coordinator().run().code)
        assertEquals(1, w.posts.size)
        assertEquals("registered", w.coordinator().run().code)
        assertEquals("idempotent: the same key is not submitted twice", 1, w.posts.size)
    }

    @Test
    fun aLockedOrUnreadableSlotIsRetryNeverGenerate() {
        val w = World()
        // A pending record whose marker is missing is a locked slot.
        w.dev.pending.put(account, RecKeys.generate(account, random).privateArmor, "")
        w.files.map.remove(NativePgpVault.markName(account, NativePgpVault.Slot.PENDING))
        w.failOnGenerate = true
        assertEquals("retry_later:pending_locked", w.coordinator().run().code)
    }

    @Test
    fun aRouteCheckThatFailsOrFindsNoRecordedNodeGeneratesAndSubmitsNothing() {
        val a = World().also { it.routeUnreadable = true; it.failOnGenerate = true }
        assertEquals("retry_later:route_check_failed", a.coordinator().run().code)
        assertTrue(a.files.map.isEmpty() && a.posts.isEmpty())
        val b = World().also { it.routeId = null; it.failOnGenerate = true }
        assertEquals("retry_later:no_route", b.coordinator().run().code)
        // An active key whose route is missing: the check fails, so nothing is submitted.
        val (c, key) = worldWithActive()
        c.routeUnreadable = true
        c.identityScript = mutableListOf({ _ -> ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, null)) })
        assertEquals("retry_later:route_check_failed", c.coordinator().run().code)
        assertTrue(c.posts.isEmpty())
    }

    // ---- what the coordinator sends to the page -----------------------------------------------------------------

    @Test
    fun aFailedChainReadIsRetryLaterWithAReasonAndNeverAGeneration() {
        val w = World().also { it.keyRead = RegisteredKeyRead.Unknown; it.failOnGenerate = true }
        assertEquals("retry_later:chain_unreadable", w.coordinator().run().code)
        val s = w.statuses.single()
        assertEquals("retry_later", s.state)
        assertEquals("read_unavailable", s.reason)
        assertEquals(1, s.attempt)
        assertEquals(60_000L, s.retryAfterMs)
        assertEquals(0, w.generated)
    }

    @Test
    fun aReadbackThatNeverShowsTheKeyIsRetryLaterTwiceThenIdentityPendingAndTheKeyIsKept() {
        val w = World()
        w.identityScript = mutableListOf({ _ -> ChainIdentityRead.Absent })
        repeat(3) { w.coordinator().run() }
        assertEquals(
            listOf("registering:no_record_confirmed", "retry_later:readback_timeout", "registering:-", "retry_later:readback_timeout", "registering:-", "identity_pending:readback_timeout"),
            w.statuses.map { it.state + ":" + (it.reason ?: "-") },
        )
        assertEquals(listOf(null, 1, null, 2, null, 3), w.statuses.map { it.attempt })
        assertEquals("the same key all along: one generation, three submissions", 1, w.generated)
        assertEquals(3, w.posts.size)
        assertNull("identity_pending carries no retry delay", w.statuses.last().retryAfterMs)
    }

    @Test
    fun aConflictAndARefusalAreFailedWithTheirReasonAndAMaterialStopSendsNothing() {
        val c = World()
        val other = RecKeys.generate(account, random)
        c.identityScript = mutableListOf(
            { _ -> ChainIdentityRead.Absent },
            { _ -> ChainIdentityRead.Present(ChainIdentityView(other.identity.fingerprint, other.identity.subkeyKeyId, route)) },
        )
        c.coordinator().run()
        assertEquals("failed:conflict_other_key", c.statuses.last().let { it.state + ":" + it.reason })
        val r = World().also { it.postAnswer = { ChatRouteSubmit.Transport.Answer(400, "{}") } }
        r.coordinator().run()
        assertEquals("failed:submit_4xx", r.statuses.last().let { it.state + ":" + it.reason })
        for (lock in listOf(LockState.LOCKED, LockState.UNKNOWN)) {
            val l = World().also { it.lock = { lock }; it.failOnGenerate = true }
            l.coordinator().run()
            assertTrue("a material stop is a gate matter, no status event ($lock)", l.statuses.isEmpty())
        }
        val busy = World().also { it.flightFree = false }
        val pending = RecKeys.generate(account, random)
        busy.dev.pending.put(account, pending.privateArmor, "")
        busy.dev.writePendingMeta(PendingMeta("idem-b", 0L, "first"))
        busy.coordinator().run()
        assertTrue("another registration in flight: silent", busy.statuses.isEmpty())
    }

    // ---- the passcode lock: generate, decide, submit and activate each need the account unlocked -----------------------------------------------

    @Test
    fun aLockedOrUnknownAccountGeneratesWritesAndSubmitsNothing() {
        for ((state, code) in listOf(LockState.LOCKED to "retry_later:passcode_not_provided", LockState.UNKNOWN to "retry_later:not_ready")) {
            val w = World().also { it.lock = { state }; it.failOnGenerate = true }
            val old = RecKeys.generate(account, random)
            w.k.write(account, PgpMigrationPolicy.WORKSPACE, old.identity.subkeyKeyId, old.publicArmor, old.privateArmor, 1L)
            val before = snapshot(w)
            assertEquals(code, w.coordinator().run().code)
            assertEquals("zero writes, zero submissions, the old K is not discarded", before, snapshot(w))
        }
    }

    /** Runs [setup]'s world with a lock that turns on at the n-th question; every write and submission after that moment is a failure. */
    private fun lockSweep(setup: (World) -> Unit, label: String, expectedAsks: Int) {
        // How many times the coordinator asks while unlocked, to know the points.
        val probe = World().also(setup)
        var asked = 0
        probe.lock = { asked++; LockState.UNLOCKED }
        probe.coordinator().run()
        assertEquals("$label: the lock points are exactly these (a removed check shows here)", expectedAsks, asked)
        var locked = 0
        for (n in 1..asked) {
            val w = World().also(setup)
            var calls = 0
            var frozen: Triple<Map<String, List<Byte>>, Map<String, String>, Int>? = null
            w.lock = {
                calls++
                if (calls >= n) {
                    if (frozen == null) frozen = snapshot(w)
                    LockState.LOCKED
                } else {
                    LockState.UNLOCKED
                }
            }
            val r = w.coordinator().run()
            assertTrue("$label n=$n: a lock stops the run (${r.code})", r.code == "retry_later:passcode_not_provided")
            assertEquals("$label n=$n: nothing was written or submitted after the lock", frozen, snapshot(w))
            locked++
        }
        assertEquals(asked, locked)
    }

    @Test
    fun aLockAtAnyPointOfTheFirstIdentityStopsEverythingAfterIt() {
        lockSweep({ w -> w.chainHoldsOurKeyAfterPosts(1) { w.pendingIdentity() ?: w.activeIdentity() } }, "new account", expectedAsks = 5)
    }

    @Test
    fun aLockAtAnyPointOfAResumedPendingKeyStopsEverythingAfterIt() {
        lockSweep({ w ->
            val pending = RecKeys.generate(account, random)
            w.dev.pending.put(account, pending.privateArmor, "")
            w.dev.writePendingMeta(PendingMeta("idem-lock", 0L, "first"))
            w.chainHoldsOurKeyAfterPosts(1) { pending.identity }
        }, "resume", expectedAsks = 4)
    }

    @Test
    fun aLockAtAnyPointOfAnActiveKeyRouteFillStopsEverythingAfterIt() {
        lockSweep({ w ->
            val key = RecKeys.generate(account, random)
            w.dev.active.put(account, key.privateArmor, "")
            w.failOnGenerate = true
            w.identityScript = mutableListOf(
                { _ -> ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, null)) },
                { _ -> if (w.posts.isNotEmpty()) ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, route)) else ChainIdentityRead.Present(ChainIdentityView(key.identity.fingerprint, key.identity.subkeyKeyId, null)) },
            )
        }, "active", expectedAsks = 2)
    }

    // ---- the one place that generates -----------------------------------------------------------------------------------------------------

    @Test
    fun aKeyIsGeneratedInOnePlaceOnly() {
        val callers = File("src/main/java/network/conet/chat").walkTopDown().filter { it.name.endsWith(".kt") }
            .filter { it.readText().contains("NativePgpKeyGen.generate(") }.map { it.name }.toSortedSet()
        // VoiceEphemeral makes a throwaway per-call voice key (never an account identity, never stored or registered); it predates this rule.
        assertEquals("only the coordinator generates an account key", setOf("FirstIdentityCoordinator.kt", "VoiceEphemeral.kt"), callers)
        val coordinator = File("src/main/java/network/conet/chat/nativekey/FirstIdentityCoordinator.kt").readText()
        // The generation sits after the three checks (chain registered, legacy key, route) in the same function.
        val gen = coordinator.indexOf("val generated = generate()")
        for (guard in listOf("is RegisteredKeyRead.Present -> return Result.Recovery", "legacyKeyPresent()", "is RouteChoice.None -> return Result.RetryLater(\"no_route\")")) {
            assertTrue("$guard comes before the generation", coordinator.indexOf(guard) in 0 until gen)
        }
        assertFalse("the creation does not generate", File("src/main/java/network/conet/chat/nativekey/NativeAccountCreate.kt").readText().contains("generate("))
    }

    // ---- the default build: reconcile an active key only -------------------------------------------

    private fun assertUntouched(w: World, before: Map<String, ByteArray>) {
        assertEquals("zero generations", 0, w.generated)
        assertTrue("zero submissions", w.posts.isEmpty())
        assertEquals("no file written, erased or replaced", before.keys, w.files.map.keys)
        for ((name, bytes) in before) assertTrue("unchanged: $name", bytes.contentEquals(w.files.map[name]!!))
        assertTrue("no status event", w.events.isEmpty())
    }

    @Test
    fun theDefaultModeWithNoActiveKeyGeneratesSubmitsAndDiscardsNothing() {
        // The confirmed-no-record case, which in the full mode generates and registers.
        val w = World().also { it.failOnGenerate = true }
        val r = w.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run()
        assertEquals("not_applicable", r.code)
        assertUntouched(w, emptyMap())
        // The same world in the full mode does generate, so the test is not vacuous.
        val full = World()
        full.chainHoldsOurKeyAfterPosts(1) { full.pendingIdentity() ?: full.activeIdentity() }
        assertEquals("registered", full.coordinator().run().code)
        assertEquals(1, full.generated)
    }

    @Test
    fun theDefaultModeNeverDiscardsAKOnlyKey() {
        val w = World().also { it.failOnGenerate = true }
        val old = RecKeys.generate(account, random)
        assertTrue(w.k.write(account, PgpMigrationPolicy.WORKSPACE, old.identity.subkeyKeyId, old.publicArmor, old.privateArmor, 1L))
        val before = HashMap(w.files.map)
        assertEquals("not_applicable", w.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run().code)
        assertTrue("the K-only key is still there", w.k.existsFor(account, PgpMigrationPolicy.WORKSPACE))
        assertEquals(old.identity.subkeyKeyId, w.k.read(account, PgpMigrationPolicy.WORKSPACE)!!.getString("keyId"))
        assertUntouched(w, before)
    }

    @Test
    fun theDefaultModeNeitherResumesNorErasesAPendingKey() {
        val w = World().also { it.failOnGenerate = true }
        val pending = RecKeys.generate(account, random)
        assertEquals(NativePgpVault.Put.OK, w.dev.pending.put(account, pending.privateArmor, ""))
        w.dev.writePendingMeta(PendingMeta("idem-1", 0L, "first"))
        w.chainHoldsOurKeyAfterPosts(0) { pending.identity }
        val before = HashMap(w.files.map)
        assertEquals("not_applicable", w.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run().code)
        assertUntouched(w, before)
        // An orphan pending key (no metadata) is not erased either.
        val o = World().also { it.failOnGenerate = true }
        assertEquals(NativePgpVault.Put.OK, o.dev.pending.put(account, RecKeys.generate(account, random).privateArmor, ""))
        val ob = HashMap(o.files.map)
        assertEquals("not_applicable", o.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run().code)
        assertUntouched(o, ob)
    }

    @Test
    fun theDefaultModeStillReconcilesAnActiveKeyWithTheSameKey() {
        // An active key whose route is missing on the chain: the same key is submitted once; nothing is generated.
        val w = World().also { it.failOnGenerate = true }
        val key = RecKeys.generate(account, random)
        assertEquals(NativePgpVault.Put.OK, w.dev.active.put(account, key.privateArmor, ""))
        w.chainHoldsOurKeyAfterPosts(1) { key.identity }
        val r = w.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run()
        assertEquals("registered", r.code)
        assertEquals("one submission of the same key", 1, w.posts.size)
        assertEquals(0, w.generated)
        assertEquals("the active key is the one it was", key.identity, w.activeIdentity())
        // Already registered with a route: nothing is submitted.
        val done = World().also { it.failOnGenerate = true }
        assertEquals(NativePgpVault.Put.OK, done.dev.active.put(account, key.privateArmor, ""))
        done.chainHoldsOurKeyAfterPosts(0) { key.identity }
        assertEquals("registered", done.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run().code)
        assertTrue(done.posts.isEmpty())
        // Another key on the chain is a conflict and nothing is written.
        val other = RecKeys.generate(account, random)
        val c = World().also { it.failOnGenerate = true }
        assertEquals(NativePgpVault.Put.OK, c.dev.active.put(account, key.privateArmor, ""))
        c.chainHoldsOurKeyAfterPosts(0) { other.identity }
        val cb = HashMap(c.files.map)
        assertEquals("conflict", c.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run().code)
        assertTrue(c.posts.isEmpty())
        assertEquals(cb.keys, c.files.map.keys)
    }

    @Test
    fun theDefaultModeDoesNotFinishAnInterruptedActivation() {
        // The full mode finishes an S6 that stopped half way (the active key written, the pending key and marker left). The default mode leaves it.
        val w = World().also { it.failOnGenerate = true }
        val key = RecKeys.generate(account, random)
        assertEquals(NativePgpVault.Put.OK, w.dev.pending.put(account, key.privateArmor, ""))
        assertEquals(NativePgpVault.Put.OK, w.dev.active.put(account, key.privateArmor, ""))
        w.dev.writePendingMeta(PendingMeta("idem-9", 0L, "first"))
        w.chainHoldsOurKeyAfterPosts(0) { key.identity }
        w.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run()
        assertTrue("the pending key is not cleaned up by the default mode", w.dev.pending.state() is NativePgpVault.State.Ready)
        assertNull("no completion record is written", w.dev.completedIdem())
    }

    @Test
    fun theModeIsAConstructorChoiceWhoseDefaultIsTheFullMachineAndTheProductionPathPicksIt() {
        assertEquals(FirstIdentityCoordinator.Mode.FULL, FirstIdentityCoordinator.Mode.values().first())
        val src = java.io.File("src/main/java/network/conet/chat/nativekey/FirstIdentityCoordinator.kt").readText()
        // RECONCILE_ONLY returns before the pending state is read: no generation, discard or pending write is reachable from it.
        val head = src.substringAfter("private fun runLocked(): Result {").substringBefore("val pendingState = dev.pending.state()")
        assertTrue(head.contains("if (mode == Mode.RECONCILE_ONLY) return runReconcileOnly()"))
        val only = src.substringAfter("private fun runReconcileOnly(): Result {").substringBefore("private fun activeIdentityFromSnapshot")
        assertTrue(only.contains("reconcileActive("))
        assertTrue(only.contains("Result.NotApplicable()"))
        assertFalse("the default mode never reads the pending slot", only.contains("dev.pending"))
    }

    // ---- the default build reconciles from the public snapshot: no decrypt on a valid entry, one read otherwise --------------------------------

    private fun activeWorld(failOnGenerate: Boolean = true): Pair<World, RecPgp> {
        val w = World().also { it.failOnGenerate = failOnGenerate }
        val key = RecKeys.generate(account, random)
        assertEquals(NativePgpVault.Put.OK, w.dev.active.put(account, key.privateArmor, ""))
        return w to key
    }

    @Test
    fun aValidSnapshotEntryReconcilesWithNoDecrypt() {
        val (w, key) = activeWorld()
        PublicIdentitySnapshot.refresh(w.dev.active)
        w.chainHoldsOurKeyAfterPosts(0) { key.identity }
        w.wrap.opens = 0
        val r = w.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run()
        assertEquals("registered", r.code)
        assertEquals("a valid entry: no decrypt at all", 0, w.wrap.opens)
        assertTrue(w.posts.isEmpty())
        assertEquals(0, w.generated)
    }

    @Test
    fun noEntryIsOneReadAndItFillsTheSnapshot() {
        val (w, key) = activeWorld()
        w.chainHoldsOurKeyAfterPosts(0) { key.identity }
        w.wrap.opens = 0
        val r = w.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run()
        assertEquals("registered", r.code)
        assertEquals("one read for state and identity together (it was two)", 1, w.wrap.opens)
        assertTrue("the read filled the snapshot", PublicIdentitySnapshot.lookup(account, w.dev.active.fileSignature()) is PublicIdentitySnapshot.Lookup.Hit)
        // the second run is free
        w.wrap.opens = 0
        assertEquals("registered", w.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run().code)
        assertEquals(0, w.wrap.opens)
    }

    @Test
    fun aChangedRecordIsNeverServedFromTheSnapshot() {
        // The snapshot holds key A. The active record is then replaced by key B by code that never calls invalidate (an outside replacement): the
        // entry is still in the map, with the old file signature, so only the signature check can refuse it. The run reads B.
        for (chainHolds in listOf("new", "old")) {
            val (w, a) = activeWorld()
            // B's world is built first: a put drops the (global, per account) snapshot entry, so it must not come after the refresh below.
            val other = World()
            val b = RecKeys.generate(account, random)
            assertEquals(NativePgpVault.Put.OK, other.dev.active.put(account, b.privateArmor, ""))
            PublicIdentitySnapshot.refresh(w.dev.active)
            assertTrue("control: the entry is there and valid", PublicIdentitySnapshot.lookup(account, w.dev.active.fileSignature()) is PublicIdentitySnapshot.Lookup.Hit)
            // the outside replacement of the record and its marker, as another process would do
            w.files.map[NativePgpVault.recName(account)] = other.files.map[NativePgpVault.recName(account)]!!
            w.files.map[NativePgpVault.markName(account)] = other.files.map[NativePgpVault.markName(account)]!!
            // the sealed record is B's under B's wrap key: the world's wrap opens only its own, so B is read through B's wrap
            val dev = PgpRestoreDevice("d", account, other.wrap, w.files)
            w.chainHoldsOurKeyAfterPosts(0) { if (chainHolds == "new") b.identity else a.identity }
            other.wrap.opens = 0
            val c = FirstIdentityCoordinator(
                eoa = account, dev = dev, k = w.k,
                readKey = { w.keyRead },
                readIdentity = { ChainIdentityRead.Present(ChainIdentityView(
                    (if (chainHolds == "new") b.identity else a.identity).fingerprint, (if (chainHolds == "new") b.identity else a.identity).subkeyKeyId, route)) },
                legacyKeyPresent = { false },
                generate = { throw AssertionError("a key was generated") },
                chooseRoute = { RouteChoice.Ok(route) },
                eoaKey = { accountKey.copyOf() },
                bases = listOf("https://beamio.test"),
                poster = ChatRouteSubmit.Poster { _, _, _ -> throw AssertionError("posted") },
                sleep = { true }, pollDelaysMs = longArrayOf(1),
                flightEnter = { true }, flightExit = { },
                mode = FirstIdentityCoordinator.Mode.RECONCILE_ONLY,
            )
            val r = c.run()
            assertEquals("chain holds $chainHolds", if (chainHolds == "new") "registered" else "conflict", r.code)
            assertEquals("the stale entry was refused: one read of the new record", 1, other.wrap.opens)
        }
    }

    @Test
    fun aSnapshotEntryThatIsNotUsableFallsBackToTheRead() {
        // READY without a key id
        val (w, key) = activeWorld()
        PublicIdentitySnapshot.store(account, NativePgpVault.Read(NativePgpVault.State.Ready("FP"), null, null, w.dev.active.fileSignature()!!))
        w.chainHoldsOurKeyAfterPosts(0) { key.identity }
        w.wrap.opens = 0
        assertEquals("registered", w.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run().code)
        assertEquals("not usable: one read", 1, w.wrap.opens)
        // an entry that does not say READY (a locked record)
        val l = World().also { it.failOnGenerate = true }
        val lk = RecKeys.generate(account, random)
        assertEquals(NativePgpVault.Put.OK, l.dev.active.put(account, lk.privateArmor, ""))
        l.files.map.remove(NativePgpVault.markName(account))
        PublicIdentitySnapshot.refresh(l.dev.active)
        assertEquals("not_applicable", l.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run().code)
        assertTrue(l.posts.isEmpty())
    }

    @Test
    fun theThreeReconcileResultsAreTheSameFromTheSnapshot() {
        // registered with a route: nothing submitted
        val (a, ka) = activeWorld()
        PublicIdentitySnapshot.refresh(a.dev.active)
        a.chainHoldsOurKeyAfterPosts(0) { ka.identity }
        assertEquals("registered", a.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run().code)
        assertTrue(a.posts.isEmpty())
        // another key on the chain: conflict, nothing written
        PublicIdentitySnapshot.resetForTests()
        val (c, kc) = activeWorld()
        PublicIdentitySnapshot.refresh(c.dev.active)
        val other = RecKeys.generate(account, random)
        c.chainHoldsOurKeyAfterPosts(0) { other.identity }
        val before = HashMap(c.files.map)
        assertEquals("conflict", c.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run().code)
        assertTrue(c.posts.isEmpty())
        assertEquals(before.keys, c.files.map.keys)
        assertEquals(kc.identity, c.activeIdentity())
        // no registration on the chain: the same key is submitted once, nothing generated
        PublicIdentitySnapshot.resetForTests()
        val (s, ks) = activeWorld()
        PublicIdentitySnapshot.refresh(s.dev.active)
        s.chainHoldsOurKeyAfterPosts(1) { ks.identity }
        assertEquals("registered", s.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run().code)
        assertEquals("one submission of the same key", 1, s.posts.size)
        assertEquals(0, s.generated)
        assertEquals(ks.identity, s.activeIdentity())
    }

    @Test
    fun theFullModeDoesNotTakeTheSnapshotPath() {
        val (w, key) = activeWorld()
        PublicIdentitySnapshot.refresh(w.dev.active)
        w.chainHoldsOurKeyAfterPosts(0) { key.identity }
        w.wrap.opens = 0
        assertEquals("registered", w.coordinator(FirstIdentityCoordinator.Mode.FULL).run().code)
        assertTrue("the full machine reads the slot itself: ${w.wrap.opens}", w.wrap.opens >= 1)
        val src = java.io.File("src/main/java/network/conet/chat/nativekey/FirstIdentityCoordinator.kt").readText()
        assertEquals("the snapshot is read in one place", 1, Regex("""activeIdentityFromSnapshot\(\)\?\.let""").findAll(src).count())
        val runLocked = src.substringAfter("private fun runLocked(): Result {").substringBefore("val pendingState")
        assertTrue(runLocked.contains("if (mode == Mode.RECONCILE_ONLY) return runReconcileOnly()"))
        val only = src.substringAfter("private fun runReconcileOnly(): Result {").substringBefore("private fun activeIdentityFromSnapshot")
        assertTrue(only.contains("dev.active.readOnce(wantArmor = false)"))
        assertFalse(only.contains("dev.active.state()") || only.contains("dev.active.identity()"))
    }

    // ---- a record whose stored fingerprint disagrees with its key is never reconciled, first or later ----------------

    private fun unknownHit(w: World): PublicIdentitySnapshot.Facts {
        val l = PublicIdentitySnapshot.lookup(account, w.dev.active.fileSignature())
        assertTrue("an entry is there: $l", l is PublicIdentitySnapshot.Lookup.Hit)
        val f = (l as PublicIdentitySnapshot.Lookup.Hit).facts
        assertEquals("UNKNOWN, never READY", PublicIdentitySnapshot.Kind.UNKNOWN, f.kind)
        assertNull(f.keyId)
        assertNull(f.fingerprint)
        assertNull(f.publicArmor)
        return f
    }

    @Test
    fun aRecordWhoseFingerprintDisagreesWithItsKeyIsRefusedEveryTimeAndNeverStoredAsReady() {
        val w = World().also { it.failOnGenerate = true }
        val key = RecKeys.generate(account, random)
        writeMismatchedPgpRecord(w.wrap, w.files, account, key.privateArmor, "00".repeat(20))
        // the chain shows the key's own identity and a route: were the check skipped, the run would end registered
        w.chainHoldsOurKeyAfterPosts(0) { key.identity }
        for (run in 1..3) {
            w.wrap.opens = 0
            val r = w.coordinator(FirstIdentityCoordinator.Mode.RECONCILE_ONLY).run()
            assertEquals("run $run", "retry_later:active_unreadable", r.code)
            assertTrue("run $run read the record again: the reconcile never takes an UNKNOWN entry (${w.wrap.opens})", w.wrap.opens >= 1)
            unknownHit(w)
        }
        assertTrue(w.posts.isEmpty())
        assertEquals(0, w.generated)
    }

    @Test
    fun aMismatchedRecordReplacesAnEarlierReadyEntryWithUnknown() {
        val (w, key) = activeWorld()
        PublicIdentitySnapshot.refresh(w.dev.active)
        assertEquals(PublicIdentitySnapshot.Kind.READY, (PublicIdentitySnapshot.lookup(account, w.dev.active.fileSignature()) as PublicIdentitySnapshot.Lookup.Hit).facts.kind)
        writeMismatchedPgpRecord(w.wrap, w.files, account, key.privateArmor, "11".repeat(20))
        val read = w.dev.active.readOnce(wantArmor = false)
        assertEquals(PublicIdentitySnapshot.Kind.UNKNOWN, PublicIdentitySnapshot.store(account, read))
        unknownHit(w)
        assertEquals("refresh says unknown, not READY", PublicIdentitySnapshot.Kind.UNKNOWN, PublicIdentitySnapshot.refresh(w.dev.active))
    }

    @Test
    fun aMismatchedRecordIsReadOnceInTheTtlAndAgainAfterIt() {
        val w = World().also { it.failOnGenerate = true }
        val key = RecKeys.generate(account, random)
        writeMismatchedPgpRecord(w.wrap, w.files, account, key.privateArmor, "22".repeat(20))
        var now = 50_000L
        PublicIdentitySnapshot.nowMs = { now }
        w.wrap.opens = 0
        assertEquals("the first read", account, VaultWarmUp.refreshIdentity(account) { w.dev.active })
        assertEquals(1, w.wrap.opens)
        // every page retry inside the time is a hit of the UNKNOWN entry: no decrypt
        repeat(5) {
            now += 900
            assertNull(VaultWarmUp.refreshIdentity(account) { w.dev.active })
        }
        assertEquals("one decrypt in the time", 1, w.wrap.opens)
        // after the time the record is read and compared again, and is still unknown
        now += PublicIdentitySnapshot.UNKNOWN_TTL_MS
        assertEquals(account, VaultWarmUp.refreshIdentity(account) { w.dev.active })
        assertEquals("one more read after the time", 2, w.wrap.opens)
        unknownHit(w)
    }

    @Test
    fun identityPublicAnswersAMismatchedRecordAsUnknownWithNoneOfTheThreeItems() {
        val w = World().also { it.failOnGenerate = true }
        val key = RecKeys.generate(account, random)
        writeMismatchedPgpRecord(w.wrap, w.files, account, key.privateArmor, "33".repeat(20))
        PublicIdentitySnapshot.refresh(w.dev.active)
        val src = SnapshotIdentitySource(
            eoaOf = { account },
            factsOf = { (PublicIdentitySnapshot.lookup(account, w.dev.active.fileSignature()) as? PublicIdentitySnapshot.Lookup.Hit)?.facts },
            routeArmorOf = { "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nroute\n-----END PGP PUBLIC KEY BLOCK-----" },
            kPresentOf = { null },
        )
        val reply = IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId") }, 1, src)
        assertTrue("an answer, not a refusal", reply.ok)
        val r = reply.result!!
        assertFalse("not ready", r.getBoolean("pgpReady"))
        assertFalse("unknown, not a confirmed no-key: pgpReadyKnown is false", r.getBoolean("pgpReadyKnown"))
        for (name in listOf("pgpKeyID", "pgpPublicKeyArmored", "ownRouteArmoredPublicKey")) assertFalse(name, r.has(name))
    }

    @Test
    fun aConsistentRecordIsStoredAsBefore() {
        val (w, _) = activeWorld()
        val read = w.dev.active.readOnce(wantArmor = false)
        assertEquals(PublicIdentitySnapshot.Kind.READY, PublicIdentitySnapshot.store(account, read))
        assertEquals(PublicIdentitySnapshot.Kind.READY, PublicIdentitySnapshot.refresh(w.dev.active))
        // a key that cannot be parsed has no identity to compare: stored as before (READY without a key id; the reconcile does not use it)
        val noId = NativePgpVault.Read(NativePgpVault.State.Ready("FP"), null, null, w.dev.active.fileSignature()!!)
        assertEquals(PublicIdentitySnapshot.Kind.READY, PublicIdentitySnapshot.store(account, noId))
    }
}

/**
 * Writes an active PGP record whose stored fingerprint is [fakeFp] while the sealed key is [privateArmor]'s: the shape only an outside rewrite can make
 * (a normal write stores the key's own fingerprint). The marker is the record's digest, so every other check passes.
 */
internal fun writeMismatchedPgpRecord(wrap: NativeTestWrap, files: NativeTestFiles, account: String, privateArmor: String, fakeFp: String) {
    val plain = org.json.JSONObject().put("v", 1).put("fp", fakeFp).put("priv", privateArmor).put("pass", "").toString().toByteArray(Charsets.UTF_8)
    val sealed = wrap.seal(NativePgpVault.aad(account), plain)
    val rec = org.json.JSONObject().put("record", NativePgpVault.RECORD_VERSION).put("eoa", account).put("fingerprint", fakeFp)
        .put("sealed", network.conet.chat.ConetChatCryptoUtil.toHex(sealed)).toString().toByteArray(Charsets.UTF_8)
    files.map[NativePgpVault.recName(account)] = rec
    files.map[NativePgpVault.markName(account)] =
        network.conet.chat.ConetChatCryptoUtil.toHex(java.security.MessageDigest.getInstance("SHA-256").digest(rec)).toByteArray(Charsets.US_ASCII)
}
