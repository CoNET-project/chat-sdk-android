package network.conet.chat.nativekey

import network.conet.chat.identity.CredFields
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** `identityPublic` reports the real state of the native PGP vault as `pgpReady`: true for a usable key, false for no key, false with `pgpReadyKnown` false for unknown. */
class IdentityPublicPgpStateTest {
    private val eoa = "0x" + "ab".repeat(20)

    private fun source(state: IdentityPublic.PgpState?, keyId: String? = null) = object : IdentityPublic.Source {
        override fun eoa(): String? = eoa
        override fun pgp(): IdentityPublic.PgpRecord = IdentityPublic.PgpRecord.NotRead
        override fun pgpState(): IdentityPublic.PgpState? = state
        override fun pgpKeyId(): String? = keyId
    }

    private fun result(state: IdentityPublic.PgpState?, keyId: String? = null): JSONObject {
        val reply = IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId") }, 1, source(state, keyId))
        assertTrue(reply.ok)
        return reply.result!!
    }

    @Test
    fun aUsableVaultKeyIsReadyOnlyWithAllThreePublicParts() {
        // the key id alone is not enough; the key's public armor and the route's public armor must be there too.
        val own = RecKeys.generate(eoa)
        val route = RecKeys.generate("route").publicArmor
        val full = object : IdentityPublic.Source {
            override fun eoa(): String? = eoa
            override fun pgp(): IdentityPublic.PgpRecord = IdentityPublic.PgpRecord.NotRead
            override fun pgpState(): IdentityPublic.PgpState? = IdentityPublic.PgpState.READY
            override fun pgpKeyId(): String? = "0123456789ABCDEF"
            override fun pgpPublicArmor(): String? = own.publicArmor
            override fun ownRouteArmor(): String? = route
        }
        val r = IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId") }, 1, full).result!!
        assertTrue(r.getBoolean("pgpReady"))
        assertEquals("0123456789ABCDEF", r.getString("pgpKeyID"))
        assertFalse(r.has("pgpReadyKnown"))
        assertEquals(eoa, r.getString("eoa"))
        // The key id alone: not ready (the page would otherwise get an incomplete answer and retry).
        val partial = result(IdentityPublic.PgpState.READY, "0123456789ABCDEF")
        assertFalse(partial.getBoolean("pgpReady"))
        assertFalse(partial.has("pgpKeyID"))
    }

    @Test
    fun noVaultKeyIsNotReadyAndKnown() {
        val r = result(IdentityPublic.PgpState.NOT_READY)
        assertFalse(r.getBoolean("pgpReady"))
        assertFalse("known: the field is only there when it is not", r.has("pgpReadyKnown"))
        assertFalse(r.has("pgpKeyID"))
    }

    @Test
    fun anUnreadableOrLockedVaultIsNotReadyAndSaysItIsUnknown() {
        val r = result(IdentityPublic.PgpState.UNKNOWN, "0123456789ABCDEF")
        assertFalse(r.getBoolean("pgpReady"))
        assertFalse("pgpReadyKnown", r.getBoolean("pgpReadyKnown"))
        assertFalse("no key id for a state that is not ready", r.has("pgpKeyID"))
    }

    @Test
    fun aSourceWithoutTheStateKeepsTheOlderAnswer() {
        val r = result(null)
        assertFalse(r.getBoolean("pgpReady"))
        assertFalse(r.has("pgpReadyKnown"))
    }

    @Test
    fun theAnswerCarriesNoKeyField() {
        for (state in IdentityPublic.PgpState.values()) {
            val payload = IdentityPublic.ackPayload(1, IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId") }, 1, source(state, "0123456789ABCDEF")))
            val names = payload.getJSONObject("result").keys().asSequence().toSet()
            assertTrue(names.none { it in CredFields.NAMES })
            assertTrue(names.all { it in setOf("eoa", "accountKey", "pgpReady", "pgpReadyKnown", "pgpKeyID") })
        }
    }

    @Test
    fun theProductionSourceReadsTheSnapshotAndNeverOpensTheRecord() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        val src = module.substringAfter("private fun identityPublicSource(").substringBefore("private fun provisionIdentity")
        assertTrue("the production source is the snapshot source", src.contains("SnapshotIdentitySource("))
        assertTrue("the facts come from the snapshot", src.contains("publicIdentityFacts(app)"))
        for (open in listOf(".state()", ".identity()", ".armorForMove()", ".readOnce(", ".unlock(")) {
            assertFalse("no $open on the command's thread", src.contains(open))
        }
        val source = File("src/main/java/network/conet/chat/nativekey/SnapshotIdentitySource.kt").readText()
        for (open in listOf(".state()", ".identity()", ".armorForMove()", ".readOnce(", ".unlock(", "NativeWallet")) {
            assertFalse("no $open in the source class", source.contains(open))
        }
        val lookup = module.substringAfter("private fun publicIdentityFacts(").substringBefore("private fun provisionIdentity")
        assertTrue(lookup.contains("PublicIdentitySnapshot.lookup(eoa, vault.fileSignature())"))
        assertTrue("a miss asks for one refresh", lookup.contains("VaultWarmUp.warmIdentity(app, eoa)"))
        for (open in listOf(".state()", ".identity()", ".armorForMove()", ".readOnce(", ".refresh(")) {
            assertFalse("no $open in the lookup", lookup.contains(open))
        }
    }

    // ---- no valid snapshot entry: not_ready, never the older record path --------------------------------------------

    private val publicArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ...\n-----END PGP PUBLIC KEY BLOCK-----"
    private val routeArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZroute...\n-----END PGP PUBLIC KEY BLOCK-----"

    private fun facts(kind: PublicIdentitySnapshot.Kind, keyId: String? = "0123456789ABCDEF", armor: String? = publicArmor): PublicIdentitySnapshot.Facts =
        PublicIdentitySnapshot.Facts(eoa, kind, keyId, "FP", armor, "sig", 0L)

    private fun productionSource(f: PublicIdentitySnapshot.Facts?, asked: IntArray = IntArray(1), route: String? = routeArmor) =
        SnapshotIdentitySource(eoaOf = { eoa }, factsOf = { asked[0]++; f }, routeArmorOf = { route }, kPresentOf = { null })

    private fun answer(src: IdentityPublic.Source) = IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId") }, 1, src)

    @Test
    fun theProductionSourceWithNoValidEntryAnswersNotReadyAndNeverPgpReadyFalse() {
        val reply = answer(productionSource(null))
        assertFalse("not an ok answer", reply.ok)
        assertEquals(IdentityPublic.NOT_READY, reply.error)
        assertNull("no result at all, so no pgpReady:false that reads as a confirmed no-key", reply.result)
        val payload = IdentityPublic.ackPayload(1, reply)
        assertFalse(payload.getBoolean("ok"))
        assertEquals("not_ready", payload.getString("error"))
        assertFalse(payload.has("result"))
        assertFalse("no reason in the answer", payload.has("reason"))
    }

    @Test
    fun theProductionSourceAnswersFromEveryKindOfEntry() {
        val ready = answer(productionSource(facts(PublicIdentitySnapshot.Kind.READY))).result!!
        assertTrue(ready.getBoolean("pgpReady"))
        assertEquals("0123456789ABCDEF", ready.getString("pgpKeyID"))
        assertEquals(publicArmor, ready.getString("pgpPublicKeyArmored"))
        assertEquals(routeArmor, ready.getString("ownRouteArmoredPublicKey"))
        assertFalse(ready.has("pgpReadyKnown"))
        // The three-item rule: a ready entry with the key's armor or the route missing is not ready, with none of the three.
        for (r in listOf(
            answer(productionSource(facts(PublicIdentitySnapshot.Kind.READY, armor = null))).result!!,
            answer(productionSource(facts(PublicIdentitySnapshot.Kind.READY), route = null)).result!!,
            answer(productionSource(facts(PublicIdentitySnapshot.Kind.READY, keyId = null))).result!!,
        )) {
            assertFalse(r.getBoolean("pgpReady"))
            for (n in listOf("pgpKeyID", "pgpPublicKeyArmored", "ownRouteArmoredPublicKey")) assertFalse(r.has(n))
        }
        val noKey = answer(productionSource(facts(PublicIdentitySnapshot.Kind.NO_KEY, null))).result!!
        assertFalse(noKey.getBoolean("pgpReady"))
        assertFalse("a confirmed no-key is known", noKey.has("pgpReadyKnown"))
        val unknown = answer(productionSource(facts(PublicIdentitySnapshot.Kind.UNKNOWN, null))).result!!
        assertFalse(unknown.getBoolean("pgpReady"))
        assertFalse(unknown.getBoolean("pgpReadyKnown"))
    }

    @Test
    fun theFactsAreReadOnceForACallAndOnlyAfterTheInputChecks() {
        val asked = IntArray(1)
        val src = productionSource(facts(PublicIdentitySnapshot.Kind.NO_KEY, null), asked)
        answer(src)
        assertEquals("one read for the whole answer", 1, asked[0])
        // A refused or malformed input never reads the snapshot (and so never asks for a refresh).
        val a2 = IntArray(1)
        assertEquals(IdentityPublic.KEY_REFUSED, IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId", "mnemonic") }, 1, productionSource(null, a2)).error)
        assertEquals(IdentityPublic.BAD_REQUEST, IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId", "x") }, 1, productionSource(null, a2)).error)
        assertEquals(0, a2[0])
        // And not before the gate: G0 and G1 never ask.
        assertEquals(IdentityPublic.NO_KEY, IdentityPublic.answer(NoKeyGate.Gate.G0, { listOf("type", "reqId") }, 1, productionSource(null, a2)).error)
        assertEquals(IdentityPublic.NOT_READY, IdentityPublic.answer(NoKeyGate.Gate.G1, { listOf("type", "reqId") }, 1, productionSource(facts(PublicIdentitySnapshot.Kind.READY), a2)).error)
        assertEquals(0, a2[0])
    }

    @Test
    fun noSnapshotIsNotReadyAfterTheInputChecksAndTheStateIsNotAsked() {
        var asked = 0
        val src = object : IdentityPublic.Source {
            override fun eoa(): String? = eoa
            override fun pgp(): IdentityPublic.PgpRecord = IdentityPublic.PgpRecord.NotRead
            override fun pgpAvailable(): Boolean = false
            override fun pgpState(): IdentityPublic.PgpState? { asked++; return IdentityPublic.PgpState.READY }
        }
        val reply = IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId") }, 1, src)
        assertFalse(reply.ok)
        assertEquals(IdentityPublic.NOT_READY, reply.error)
        assertEquals("the state is not asked when there is nothing to read", 0, asked)
        // The input is judged first: a refused field or an unknown field is that error, not not_ready.
        assertEquals(IdentityPublic.KEY_REFUSED, IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId", "mnemonic") }, 1, src).error)
        assertEquals(IdentityPublic.BAD_REQUEST, IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId", "x") }, 1, src).error)
        assertEquals(IdentityPublic.BAD_REQUEST, IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId") }, null, src).error)
    }
}
