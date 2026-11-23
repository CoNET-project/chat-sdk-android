package network.conet.chat.nativekey

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The decision order of the first identity and the replacement (spec, 2026-11-20; the first matching rule decides):
 *  1 no native confirmation → native_confirmation_missing;  2 same idempotency key already confirmed → idempotent, with no CAS re-read;
 *  3 a pending key under another key → pending_exists;  4 same identity on the chain → already_registered_same_key (noop, no write);
 *  5 the state the user saw changed (first identity over a registration, replacement version mismatch) → cas_conflict;  6 read-back failures keep their codes.
 */
class PgpDecisionOrderTest {
    private val acceptance = JSONObject(File("../spec/pgp-restore-acceptance-vectors.v1.json").readText(Charsets.UTF_8))
    private val account = acceptance.getJSONObject("syntheticAccount").getString("address").lowercase()
    private val password = JSONObject(File("../spec/pgp-backup-compat-vectors.v1.json").readText(Charsets.UTF_8))
        .getJSONArray("positives").getJSONObject(0).getString("passwordString")

    private fun identityOf(name: String) = PgpIdentity(
        acceptance.getJSONObject("identities").getJSONObject(name).getString("fingerprint"),
        acceptance.getJSONObject("identities").getJSONObject(name).getString("subkeyKeyID"),
    )

    private fun armorOf(name: String): String = acceptance.getJSONObject("syntheticKeys").getJSONObject(name).getString("privateArmor")

    private class Chain(var id: PgpIdentity? = null) : PgpRestoreChain {
        var writes = 0
        override fun chainReadable(): Boolean = true
        override fun backupReadable(): Boolean = true
        override fun version(): Long = writes.toLong()
        override fun identity(): PgpIdentity? = id
        override fun backupText(): String = ""
        override fun write(identity: PgpIdentity, backupText: String) {
            id = identity
            writes++
        }
    }

    private fun machine(chain: PgpRestoreChain, files: NativeTestFiles, generated: MutableList<String>) = PgpRestoreMachine(
        chain = chain,
        wallet = object : PgpRestoreWallet {
            override fun ready(): Boolean = true
            override fun passwordString(): String? = password
        },
        keys = object : PgpRestoreKeys {
            override fun newKey(deviceId: String): PgpNewKey {
                generated += deviceId
                return PgpNewKey(armorOf("P4"), identityOf("P4"))
            }
        },
        ivFor = { ByteArray(12) { 1 } },
        devices = mapOf("A" to PgpRestoreDevice("A", account, NativeTestWrap(), files)),
    )

    /** A first identity offered and confirmed once (a pending key exists under idem-1). */
    private fun confirmedOnce(chain: Chain, generated: MutableList<String>): PgpRestoreMachine {
        val m = machine(chain, NativeTestFiles(), generated)
        m.restore("A"); m.tapEntry("A")
        assertEquals("ok", m.keygen("A", "idem-1", nativeConfirmed = true).result)
        return m
    }

    @Test
    fun rule1NoNativeConfirmationIsRefused() {
        val m = machine(Chain(), NativeTestFiles(), mutableListOf())
        m.restore("A"); m.tapEntry("A")
        assertEquals("native_confirmation_missing", m.keygen("A", "idem-1", nativeConfirmed = false).code)
    }

    /** Step 1 before step 2: a repeat with the same key but no native confirmation is refused, not idempotent. */
    @Test
    fun rule1PrecedesRule2ForARepeatWithoutNativeConfirmation() {
        val generated = mutableListOf<String>()
        val m = confirmedOnce(Chain(), generated)
        assertEquals("native_confirmation_missing", m.keygen("A", "idem-1", nativeConfirmed = false).code)
    }

    /** Step 1 for registerDirect: without native confirmation, the same identity is refused as native_confirmation_missing (not a noop). */
    @Test
    fun rule1RegisterDirectWithoutNativeConfirmationIsRefusedEvenForTheSameIdentity() {
        val chain = Chain(identityOf("P3"))
        val m = machine(chain, NativeTestFiles(), mutableListOf())
        val step = m.registerDirect(identityOf("P3"), "backup", 0L, nativeConfirmed = false)
        assertEquals("native_confirmation_missing", step.code)
        assertEquals(0, chain.writes)
    }

    @Test
    fun rule2RepeatOfTheSameKeyIsIdempotentEvenIfTheChainChangedSinceTheConfirmation() {
        val chain = Chain()
        val generated = mutableListOf<String>()
        val m = confirmedOnce(chain, generated)
        chain.id = identityOf("P3") // another client registered after the confirmation
        val again = m.keygen("A", "idem-1", nativeConfirmed = true)
        assertEquals("idempotent", again.code)
        assertEquals("no CAS re-read decided the repeat: no second key", 1, generated.size)
    }

    @Test
    fun rule3ADifferentKeyWhileAPendingKeyExistsIsPendingExists() {
        val generated = mutableListOf<String>()
        val m = confirmedOnce(Chain(), generated)
        assertEquals("pending_exists", m.keygen("A", "idem-2", nativeConfirmed = true).code)
        assertEquals("no second key is generated", 1, generated.size)
    }

    /** registerDirect has no pending_exists step (spec 2026-11-20): a pending key does not refuse a registration whose checks pass. */
    @Test
    fun registerDirectDoesNotRefuseForAPendingKey() {
        val generated = mutableListOf<String>()
        val chain = Chain()
        val m = confirmedOnce(chain, generated)
        val step = m.registerDirect(identityOf("P3"), "backup", 0L, nativeConfirmed = true)
        assertEquals("ok", step.result)
        assertEquals(1, chain.writes)
    }

    /** Step 1 for keygen: a missing native confirmation is native_confirmation_missing (frozen vector M-04); the source check is confirmation_not_native. */
    @Test
    fun keygenWithoutNativeConfirmationIsNativeConfirmationMissing() {
        val m = machine(Chain(), NativeTestFiles(), mutableListOf())
        m.restore("A"); m.tapEntry("A")
        assertEquals("native_confirmation_missing", m.keygen("A", "idem-1", nativeConfirmed = false).code)
    }

    /** Step 4 for keygen: an identity already restored on this device (the active slot holds a key) is already_exists, before the CAS read. */
    @Test
    fun keygenOnADeviceThatAlreadyHoldsTheIdentityIsAlreadyExists() {
        val files = NativeTestFiles()
        val generated = mutableListOf<String>()
        val m = machine(Chain(), files, generated)
        m.restore("A"); m.tapEntry("A")
        assertEquals(NativePgpVault.Put.OK, m.devices.getValue("A").active.put(account, armorOf("P3"), ""))
        assertEquals("already_exists", m.keygen("A", "idem-1", nativeConfirmed = true).code)
        assertTrue("no key is generated", generated.isEmpty())
    }

    @Test
    fun rule4TheSameIdentityOnTheChainIsANoopAndWritesNothing() {
        val chain = Chain(identityOf("P3"))
        val m = machine(chain, NativeTestFiles(), mutableListOf())
        val first = m.registerDirect(identityOf("P3"), "backup", 1L, nativeConfirmed = true)
        assertEquals("noop", first.result)
        assertEquals("already_registered_same_key", first.code)
        assertEquals(0, chain.writes)
        assertEquals("noop", m.registerDirect(identityOf("P3"), "backup", 1L, nativeConfirmed = true).result)
    }

    @Test
    fun rule5AReplacementWithAStaleVersionIsCasConflict() {
        val chain = Chain(identityOf("P3")) // version 0 as the chain reports; a stale expected version differs
        val m = machine(chain, NativeTestFiles(), mutableListOf())
        assertEquals("cas_conflict", m.registerDirect(identityOf("P4"), "backup", 5L, nativeConfirmed = true).code)
        assertEquals(0, chain.writes)
    }

    /**  (5): an active key on the device refuses a direct registration as cas_conflict, writes nothing, and discards the pending key. */
    @Test
    fun registerDirectOverAnActiveKeyIsCasConflictAndDiscardsThePendingKey() {
        val chain = Chain()
        val generated = mutableListOf<String>()
        val m = confirmedOnce(chain, generated)
        assertEquals(NativePgpVault.Put.OK, m.devices.getValue("A").active.put(account, armorOf("P3"), ""))
        val step = m.registerDirect(identityOf("P4"), "backup", 0L, nativeConfirmed = true)
        assertEquals("cas_conflict", step.code)
        assertEquals("nothing is written", 0, chain.writes)
        assertTrue("registerDirect generated no pending key, so none is discarded", m.devices.getValue("A").pending.state() is NativePgpVault.State.Ready)
    }

    /** a cas_conflict of another request leaves a pending key under another idempotency key in place. */
    @Test
    fun aPendingKeyOfAnotherIdempotencyKeySurvivesACasConflict() {
        val chain = Chain()
        val generated = mutableListOf<String>()
        val m = confirmedOnce(chain, generated) // pending under idem-1
        assertEquals(NativePgpVault.Put.OK, m.devices.getValue("A").active.put(account, armorOf("P3"), ""))
        assertEquals("cas_conflict", m.registerDirect(identityOf("P4"), "backup", 0L, nativeConfirmed = true).code)
        val pending = m.devices.getValue("A").pendingMeta()
        assertTrue("the pending key under idem-1 is still there", m.devices.getValue("A").pending.state() is NativePgpVault.State.Ready)
        assertEquals("idem-1", pending?.idemKey)
    }

    /** a cas_conflict after this request generated its pending key discards that key (and only that one). */
    @Test
    fun aPendingKeyGeneratedByThisRequestIsDiscardedOnACasConflict() {
        val chain = Chain()
        val generated = mutableListOf<String>()
        val m = confirmedOnce(chain, generated) // generated under idem-1
        chain.id = identityOf("P3") // another client registers before the commit
        assertEquals("cas_conflict", m.commit("A").code)
        assertEquals("the key this request generated is discarded", NativePgpVault.State.NoKey, m.devices.getValue("A").pending.state())
        assertEquals("no pending metadata is left", null, m.devices.getValue("A").pendingMeta())
    }

    /** a cas_conflict before any key is generated has no side effect on the device. */
    @Test
    fun aCasConflictBeforeGenerationHasNoSideEffect() {
        val chain = Chain()
        val generated = mutableListOf<String>()
        val m = machine(chain, NativeTestFiles(), generated)
        m.restore("A"); m.tapEntry("A")
        chain.id = identityOf("P3")
        assertEquals("cas_conflict", m.keygen("A", "idem-1", nativeConfirmed = true).code)
        assertEquals("no pending key", NativePgpVault.State.NoKey, m.devices.getValue("A").pending.state())
        assertTrue("no key is generated", generated.isEmpty())
        assertEquals("no active key", NativePgpVault.State.NoKey, m.devices.getValue("A").active.state())
    }

    /** Review: a failed erase of the pending metadata is not reported as a discard, and the answer is not cas_conflict. */
    @Test
    fun aFailedEraseOfThePendingMetadataIsNotReportedAsADiscard() {
        val chain = Chain()
        val files = NativeTestFiles()
        val generated = mutableListOf<String>()
        val m = machine(chain, files, generated)
        m.restore("A"); m.tapEntry("A")
        assertEquals("ok", m.keygen("A", "idem-1", nativeConfirmed = true).result)
        files.silentDeleteFailure = NativePgpVault.pendingMetaName(account)
        chain.id = identityOf("P3") // the chain moved: the commit would discard this request's key
        val step = m.commit("A")
        assertEquals("retry_write", step.code)
        assertEquals("nothing is reported as discarded", 0, m.counters.pendingDiscarded)
        assertTrue("the pending key is kept for a retry", m.devices.getValue("A").pending.state() is NativePgpVault.State.Ready)
    }

    /** the discard path writes no key material to the log. The machine has no logging call at all. */
    @Test
    fun theRestoreMachineLogsNoKeyMaterial() {
        val src = File("src/main/java/network/conet/chat/nativekey/PgpRestoreMachine.kt").readText(Charsets.UTF_8)
        assertFalse("no android Log in the restore machine", src.contains("Log."))
        assertFalse("no println in the restore machine", src.contains("println("))
    }

    @Test
    fun rule5AFirstIdentityOverARegistrationIsCasConflict() {
        val chain = Chain()
        val generated = mutableListOf<String>()
        val m = machine(chain, NativeTestFiles(), generated)
        m.restore("A"); m.tapEntry("A")
        chain.id = identityOf("P3")
        assertEquals("cas_conflict", m.keygen("A", "idem-1", nativeConfirmed = true).code)
        assertTrue("no key is generated", generated.isEmpty())
    }
}
