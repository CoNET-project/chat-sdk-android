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
 * the bridge order, the event shape, and the source scans (no logging, no clearing of L, no key generation, no WebSocket).
 */
class PgpMigrationTest {
    private val a = PgpMigrationKeys.a
    private val b = PgpMigrationKeys.b
    private val legacyA = LegacyRecord(ACCOUNT, a.priv, a.pub)

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
            staged = SealedStagedStore(wrap, files, ACCOUNT, WORKSPACE),
            marker = SealedMarkerStore(wrap, files, ACCOUNT, WORKSPACE),
            chain = FixedChain(ChainAnswer.Found(a.fp)),
            crypto = NativeMigrationCrypto(),
        )
        assertEquals(MigrationCode.VERIFY_UNAVAILABLE, engine.run().code)
        assertNull(files.read(stagedFileName()))
        assertNull(files.read(markerFileName()))
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
        try {
            migrationEngine(files, wrap, legacyA, ChainAnswer.Found(a.fp), MigrationFaults(interruptAfterN = true)).run()
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
