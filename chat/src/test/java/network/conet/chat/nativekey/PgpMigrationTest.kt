package network.conet.chat.nativekey

import network.conet.chat.nativekey.PgpMigrationKeys.ACCOUNT
import network.conet.chat.nativekey.PgpMigrationKeys.WORKSPACE
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * Behaviour the vectors do not state directly: the production gate, the interruption and resume bytes, the covering rule,
 * the bridge order, the event shape, unregister (§25.52C.3, §25.52D.12), the failed state (§25.52D.4), the page source and its
 * zero-fill (§25.52D.3), the checkpoint visibility (§25.52C.4), and the source scans (no logging, no clearing of L, no key
 * generation, no WebSocket).
 */
class PgpMigrationTest {
    private val a = PgpMigrationKeys.a
    private val b = PgpMigrationKeys.b
    private val legacyA = legacyRecord(ACCOUNT, a.priv, a.pub)

    @Test
    fun theProductionGateIsClosed() {
        assertFalse(PgpMigrationPolicy.OPENPGP_APPROVED)
        assertFalse(NativeMigrationCrypto().approved())
    }

    @Test
    fun theProductionPathAnswersVerifyUnavailableAndWritesNothing() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val engine = PgpMigrationEngine(
            eoa = ACCOUNT,
            legacy = FixedLegacy(legacyA),
            primary = null,
            staged = SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE),
            marker = SealedMarkerStore(wrap, files, ACCOUNT, WORKSPACE),
            lastCode = FileLastCodeStore(files, ACCOUNT, WORKSPACE),
            chain = FixedChain(ChainAnswer.Found(a.fp)),
            crypto = NativeMigrationCrypto(),
            recovery = FixedRecovery(p = false, chain = false),
        )
        assertEquals(MigrationCode.VERIFY_UNAVAILABLE, engine.run().code)
        assertNull(files.read(stagedFileName()))
        assertNull(files.read(markerFileName()))
        assertEquals("failed", engine.state())
    }

    @Test
    fun publicFingerprintRefusesAPrivateBlockAndReadsAPublicOne() {
        val crypto = NativeMigrationCrypto(approvedFlag = true)
        assertNull(crypto.publicFingerprint(a.priv))
        assertEquals(a.fp, crypto.publicFingerprint(a.pub))
    }

    @Test
    fun anInterruptedRunLeavesTheStoredBytesAndTheSameResultFollows() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val faults = MigrationFaults(interrupt = "afterN")
        try {
            migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp), faults).run(checkpointFor(faults))
            fail("the run must be interrupted after N")
        } catch (_: PgpMigrationInterrupted) {
            // expected: no result, no marker
        }
        val afterInterrupt = files.read(stagedFileName())
        assertTrue("N is written before the interruption", afterInterrupt != null)
        assertNull(files.read(markerFileName()))

        val resumed = migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).run()
        assertEquals(MigrationCode.OK, resumed.code)
        assertEquals(a.fp, resumed.fp)
        assertArrayEquals("the resume does not rewrite N", afterInterrupt, files.read(stagedFileName()))

        val marker = files.read(markerFileName())
        val again = migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).run()
        assertEquals(MigrationCode.ALREADY_VERIFIED, again.code)
        assertArrayEquals("a repeat does not rewrite M", marker, files.read(markerFileName()))
        assertArrayEquals("nor N", afterInterrupt, files.read(stagedFileName()))
    }

    @Test
    fun aStagedRecordForAnotherKeyIsNeverOverwrittenOrDeleted() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE).write(StagedItem(ACCOUNT, b.fp, b.priv))
        val before = files.read(stagedFileName())
        val result = migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).run()
        assertEquals(MigrationCode.FINGERPRINT_MISMATCH, result.code)
        assertArrayEquals(before, files.read(stagedFileName()))
        assertNull(files.read(markerFileName()))
    }

    @Test
    fun withoutLegacyTheChainIsTheReferenceAndADifferentRegistrationIsAMismatch() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE).write(StagedItem(ACCOUNT, a.fp, a.priv))
        val before = files.read(stagedFileName())
        val result = migrationEngine(files, wrap, null, ChainAnswer.Absent).run()
        assertEquals(MigrationCode.FINGERPRINT_MISMATCH, result.code)
        assertArrayEquals(before, files.read(stagedFileName()))
    }

    @Test
    fun theStateGoesNoneThenPendingThenVerified() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        assertEquals("none", migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).state())
        SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE).write(StagedItem(ACCOUNT, a.fp, a.priv))
        assertEquals("pending", migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).state())
        assertEquals(MigrationCode.OK, migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).run().code)
        assertEquals("verified", migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).state())
    }

    @Test
    fun aFailedRunIsRecordedAndStateFailedUntilARunSucceeds() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val failing = MigrationFaults(challenge = true)
        val result = migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp), failing).run()
        assertEquals(MigrationCode.CHALLENGE_FAILED, result.code)
        assertEquals("challenge_failed", files.read(lastCodeFileName())?.let { String(it, Charsets.UTF_8) }?.let {
            JSONObject(it).getString("code")
        })
        assertEquals("failed", migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).state())

        assertEquals(MigrationCode.OK, migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).run().code)
        assertEquals("verified", migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).state())
    }

    @Test
    fun anInterruptedRunRecordsNoLastCodeSoTheStateStaysPending() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val faults = MigrationFaults(interrupt = "afterN")
        try {
            migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp), faults).run(checkpointFor(faults))
            fail("the run must be interrupted")
        } catch (_: PgpMigrationInterrupted) {
            // expected
        }
        assertNull("no last code after an interruption", files.read(lastCodeFileName()))
        assertEquals("pending", migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).state())
    }

    @Test
    fun aPrimarySourceWithAnotherKeyThanLegacyIsAMismatchAndWritesNothing() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val primary = legacyRecord(ACCOUNT, b.priv, b.pub)
        val result = migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp), primary = primary).run()
        assertEquals(MigrationCode.FINGERPRINT_MISMATCH, result.code)
        assertNull(files.read(stagedFileName()))
        assertNull(files.read(markerFileName()))
    }

    @Test
    fun thePrimarySourceIsUsedBeforeLegacyWhenBothAgree() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        // The primary copy differs from L only by a trailing newline, so the staged bytes show which one was used.
        val primaryText = a.priv + "\n"
        val primary = legacyRecord(ACCOUNT, primaryText, a.pub)
        val result = migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp), primary = primary).run()
        assertEquals(MigrationCode.OK, result.code)
        assertEquals(primaryText, SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE).read()?.privateArmor)
    }

    @Test
    fun aPrimarySourceAboveTheSizeLimitIsLegacyUnreadable() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val big = ByteArray(LegacyPgpSource.MAX_BYTES + 1) { 'x'.code.toByte() }
        val primary = LegacyRecord(ACCOUNT, big, a.pub.toByteArray(Charsets.UTF_8))
        val result = migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp), primary = primary).run()
        assertEquals(MigrationCode.LEGACY_UNREADABLE, result.code)
        assertNull(files.read(stagedFileName()))
    }

    @Test
    fun theSourceArraysAreZeroFilledAfterTheRunWhateverItsResult() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        val source = LegacyPgpSource(a.priv.toByteArray(Charsets.UTF_8), a.pub.toByteArray(Charsets.UTF_8), keyId = "")
        val priv = source.privateArmor
        val pub = source.publicArmor
        val result = source.useAs(ACCOUNT) { record ->
            migrationEngine(files, wrap, null, ChainAnswer.Unavailable, primary = record).run()
        }
        assertEquals(MigrationCode.CHAIN_UNAVAILABLE, result.code)
        assertTrue("the private armor is wiped", priv.all { it == 0.toByte() })
        assertTrue("the public armor is wiped", pub.all { it == 0.toByte() })
    }

    @Test
    fun unregisterRemovesTheLastCodeAndRefusalKeepsIt() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE).write(StagedItem(ACCOUNT, a.fp, a.priv))
        SealedMarkerStore(wrap, files, ACCOUNT, WORKSPACE).write(MarkerItem(a.fp, "legacyPwa", 1L))
        FileLastCodeStore(files, ACCOUNT, WORKSPACE).write("fingerprint_mismatch")
        val refused = migrationEngine(files, wrap, null, ChainAnswer.Absent, recovery = FixedRecovery(p = false, chain = false))
            .unregister()
        assertEquals(MigrationCode.UNREGISTER_REFUSED, refused.code)
        assertTrue("the last code stays on refusal", files.read(lastCodeFileName()) != null)

        val done = migrationEngine(files, wrap, legacyA, ChainAnswer.Absent).unregister()
        assertEquals(MigrationCode.OK, done.code)
        assertNull(files.read(lastCodeFileName()))
        assertNull(files.read(stagedFileName()))
        assertNull(files.read(markerFileName()))
    }

    @Test
    fun unregisterRemovesTheMarkerBeforeTheStagedRecord() {
        val wrap = NativeTestWrap()
        val files = NativeTestFiles()
        SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE).write(StagedItem(ACCOUNT, a.fp, a.priv))
        SealedMarkerStore(wrap, files, ACCOUNT, WORKSPACE).write(MarkerItem(a.fp, "legacyPwa", 1L))
        var markerAtCheckpoint: Boolean? = null
        var stagedAtCheckpoint: Boolean? = null
        val result = migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp)).unregister { stage ->
            if (stage == Stage.AFTER_MARKER_DELETED) {
                markerAtCheckpoint = files.read(markerFileName()) != null
                stagedAtCheckpoint = files.read(stagedFileName()) != null
            }
        }
        assertEquals(MigrationCode.OK, result.code)
        assertEquals("M is already gone when the checkpoint runs", false, markerAtCheckpoint)
        assertEquals("N still stands at that checkpoint", true, stagedAtCheckpoint)
        assertNull(files.read(stagedFileName()))
        assertNull(files.read(markerFileName()))
    }

    @Test
    fun theBridgeRefusesKeyFieldsUnderEveryGate() {
        for (gate in NoKeyGate.Gate.values()) {
            val body = JSONObject().put("type", "pgpMigrate").put("reqId", "r1").put("pgpPassphrase", "")
            val ack = PgpMigrationBridge.ackFor(body, gate, locked = false, running = false)
            assertTrue("refused under $gate", ack is PgpMigrationBridge.Ack.Refused)
            ack as PgpMigrationBridge.Ack.Refused
            assertEquals("key_over_bridge_refused", ack.code)
            assertEquals(listOf("pgpPassphrase"), ack.fields)
        }
    }

    @Test
    fun theBridgeRejectsUnknownFieldsAndAMissingReqId() {
        val unknown = JSONObject().put("type", "pgpMigrate").put("reqId", "r1").put("note", "x")
        val ack = PgpMigrationBridge.ackFor(unknown, NoKeyGate.Gate.G2, locked = false, running = false) as PgpMigrationBridge.Ack.Refused
        assertEquals("bad_request", ack.code)
        assertEquals(listOf("note"), ack.fields)
        val noReqId = JSONObject().put("type", "pgpMigrate")
        val refused = PgpMigrationBridge.ackFor(noReqId, NoKeyGate.Gate.G2, locked = false, running = false)
        assertEquals("bad_request", (refused as PgpMigrationBridge.Ack.Refused).code)
    }

    @Test
    fun theBridgeOrderIsGateThenLockThenRunning() {
        val body = JSONObject().put("type", "pgpMigrate").put("reqId", "r1")
        assertEquals("no_key", (PgpMigrationBridge.ackFor(body, NoKeyGate.Gate.G0, false, false) as PgpMigrationBridge.Ack.Refused).code)
        assertEquals("not_ready", (PgpMigrationBridge.ackFor(body, NoKeyGate.Gate.G1, false, false) as PgpMigrationBridge.Ack.Refused).code)
        assertEquals("locked", (PgpMigrationBridge.ackFor(body, NoKeyGate.Gate.G2, true, false) as PgpMigrationBridge.Ack.Refused).code)
        assertTrue(PgpMigrationBridge.ackFor(body, NoKeyGate.Gate.G2, false, true) is PgpMigrationBridge.Ack.Busy)
        assertTrue(PgpMigrationBridge.ackFor(body, NoKeyGate.Gate.G2, false, false) is PgpMigrationBridge.Ack.Accepted)
    }

    @Test
    fun theEventCarriesOnlyTheCodeAndTheFirstSixteenCharacters() {
        val event = PgpMigrationBridge.eventFor("r1", MigrationResult(MigrationCode.OK, a.fp))
        val keys = event.keys().asSequence().map { it.toString() }.toSet()
        assertEquals(setOf("type", "reqId", "code", "fp"), keys)
        assertEquals("pgpMigrateResult", event.getString("type"))
        assertEquals("ok", event.getString("code"))
        assertEquals(a.fp.take(16), event.getString("fp"))
        assertFalse(event.toString().contains("PRIVATE KEY"))

        val none = PgpMigrationBridge.eventFor("r1", MigrationResult(MigrationCode.NONE))
        assertTrue(none.isNull("fp"))
    }

    @Test
    fun theCheckpointIsNotPartOfThePublicEntry() {
        val text = File("src/main/java/network/conet/chat/nativekey/PgpMigration.kt").readText()
        val start = text.indexOf("object BeamioPgpMigrationImport")
        assertTrue("the public object exists", start >= 0)
        val publicEntry = text.substring(start)
        assertFalse("the public entry takes no checkpoint", publicEntry.contains("checkpoint"))
        assertTrue(text.contains("workspace: String = PgpMigrationPolicy.WORKSPACE,\n        source: LegacyPgpSource? = null,"))
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertFalse("the bridge never passes a checkpoint", module.contains("checkpoint"))
        assertFalse("the bridge never names a stage", module.contains("Stage."))
        assertFalse("the bridge never passes a page source", module.contains("LegacyPgpSource"))
    }

    @Test
    fun logoutKeepsTheLegacyCopyAndUnregistersFirst() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertFalse("logout must not clear the whole PGP store, which holds L", module.contains("BeamioChatPgpStore.clear(ctx)"))
        assertTrue(module.contains("BeamioChatPgpStore.clearKeepingLegacy(ctx)"))
        assertTrue(module.contains("BeamioPgpMigrationImport.unregister(ctx, eoa)"))
        val store = File("src/main/java/network/conet/chat/BeamioChatPgpStore.kt").readText()
        val start = store.indexOf("fun clearKeepingLegacy(")
        assertTrue("clearKeepingLegacy exists", start >= 0)
        val body = store.substring(start, store.indexOf("\n    }", start))
        assertTrue("L is excluded from the removal", body.contains("it != KEY_PRIVATE"))
    }

    @Test
    fun theMigrationSourcesNeverLogClearOrGenerate() {
        val banned = listOf(
            "Log.",
            "println",
            "NativePgpKeyGen",
            "clearLegacyPrivateArmor",
            "removeRecord",
            "setLocalSigner",
            "writeLocal",
            "WebSocket",
        )
        for (path in listOf(
            "src/main/java/network/conet/chat/nativekey/PgpMigration.kt",
            "src/main/java/network/conet/chat/nativekey/PgpMigrationBridge.kt",
        )) {
            val text = File(path).readText()
            for (word in banned) assertFalse("$path must not contain $word", text.contains(word))
        }
    }

    @Test
    fun theLegacyCopyReadPathNeverWritesOrClears() {
        val text = File("src/main/java/network/conet/chat/BeamioChatPgpStore.kt").readText()
        val start = text.indexOf("fun legacyCopy(")
        assertTrue("legacyCopy exists", start >= 0)
        val body = text.substring(start, text.indexOf("\n    }", start))
        assertFalse(body.contains("edit()"))
        assertFalse(body.contains("commit()"))
        assertFalse(body.contains(".remove("))
    }
}
