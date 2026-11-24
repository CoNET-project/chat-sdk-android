package network.conet.chat.nativekey

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * The readback of a registration: the comparator (identity of the normalized public armor, and the route), the bounded poll, the submission's
 * states (match, absent, conflict, unknown), and the identityPublic answer with its public armors.
 */
class RegistrationReadbackTest {
    private val random = SecureRandom()
    private val account = "0x" + "ab".repeat(20)
    private val own = RecKeys.generate(account, random)
    private val other = RecKeys.generate(account, random)
    private val route = "ABCDEF0123456789"
    private val expected = RegistrationReadback.Expected(own.identity.fingerprint, own.identity.subkeyKeyId, route)

    private fun present(id: PgpIdentity, routeId: String? = route) = ChainIdentityRead.Present(ChainIdentityView(id.fingerprint, id.subkeyKeyId, routeId))

    // ---- the comparator --------------------------------------------------------------------------------------------------------------------

    @Test
    fun theVerdictComparesKeyIdentityAndRoute() {
        assertEquals(ChainState.MATCH, RegistrationReadback.verdict(expected, present(own.identity)))
        assertEquals("case does not matter", ChainState.MATCH, RegistrationReadback.verdict(expected, present(PgpIdentity(own.identity.fingerprint.lowercase(), own.identity.subkeyKeyId.lowercase()), route.lowercase())))
        assertEquals(ChainState.CONFLICT, RegistrationReadback.verdict(expected, present(other.identity)))
        assertEquals("the same master with another subkey is another key", ChainState.CONFLICT, RegistrationReadback.verdict(expected, present(PgpIdentity(own.identity.fingerprint, other.identity.subkeyKeyId))))
        assertEquals("our key, no route yet: not complete", ChainState.ABSENT, RegistrationReadback.verdict(expected, present(own.identity, null)))
        assertEquals("our key, another route: not complete", ChainState.ABSENT, RegistrationReadback.verdict(expected, present(own.identity, "0000000000000000")))
        assertEquals(ChainState.ABSENT, RegistrationReadback.verdict(expected, ChainIdentityRead.Absent))
        assertEquals(ChainState.UNKNOWN, RegistrationReadback.verdict(expected, ChainIdentityRead.Unknown))
    }

    @Test
    fun theProductionReadTurnsTheTwoReadsIntoOneView() {
        val key = registeredOf(own, account)
        val ok = ProductionIdentityRead.read(account, { key }, { network.conet.chat.BeamioOwnRouteCheck.ChainRoute.Ok(route, "armor") })
        val view = (ok as ChainIdentityRead.Present).view
        assertEquals(own.identity.fingerprint, view.fingerprint)
        assertEquals(route, view.routeKeyId)
        val noRoute = ProductionIdentityRead.read(account, { key }, { network.conet.chat.BeamioOwnRouteCheck.ChainRoute.Empty })
        assertNull((noRoute as ChainIdentityRead.Present).view.routeKeyId)
        assertTrue("a route read that fails is unknown, never absent", ProductionIdentityRead.read(account, { key }, { network.conet.chat.BeamioOwnRouteCheck.ChainRoute.Error("x") }) is ChainIdentityRead.Unknown)
        assertTrue(ProductionIdentityRead.read(account, { RegisteredKeyRead.Unknown }, { throw AssertionError("route read") }) is ChainIdentityRead.Unknown)
        assertTrue(ProductionIdentityRead.read(account, { RegisteredKeyRead.Absent }, { throw AssertionError("route read") }) is ChainIdentityRead.Absent)
    }

    // ---- the poll ----------------------------------------------------------------------------------------------------------------------------

    @Test
    fun theWindowIsNinetySecondsAndEndsOnAMatchOrAConflictEarly() {
        assertEquals(90_000L, RegistrationReadback.POLL_DELAYS_MS.sum())
        var reads = 0
        val slept = mutableListOf<Long>()
        val state = RegistrationReadback.poll(expected, { reads++; if (reads < 3) ChainIdentityRead.Absent else present(own.identity) }, { slept += it; true })
        assertEquals(ChainState.MATCH, state)
        assertEquals(3, reads)
        assertEquals(listOf(2_000L, 4_000L), slept)
        assertEquals(ChainState.CONFLICT, RegistrationReadback.poll(expected, { present(other.identity) }, { throw AssertionError("slept") }))
    }

    @Test
    fun aWindowThatNeverAnswersIsUnknownAndOneThatAnsweredEmptyIsAbsent() {
        assertEquals(ChainState.UNKNOWN, RegistrationReadback.poll(expected, { ChainIdentityRead.Unknown }, { true }, longArrayOf(1, 1)))
        assertEquals(ChainState.ABSENT, RegistrationReadback.poll(expected, { ChainIdentityRead.Absent }, { true }, longArrayOf(1, 1)))
        var n = 0
        assertEquals("one answer among failures is absent", ChainState.ABSENT, RegistrationReadback.poll(expected, { if (n++ == 1) ChainIdentityRead.Absent else ChainIdentityRead.Unknown }, { true }, longArrayOf(1, 1)))
        assertEquals("stopped by the caller", ChainState.UNKNOWN, RegistrationReadback.poll(expected, { ChainIdentityRead.Unknown }, { false }))
    }

    // ---- the submission uses the states ----------------------------------------------------------------------------------------------------

    private fun submit(status: Int, body: String, state: (Boolean) -> ChainState): ChatRouteSubmit.Outcome {
        val check = object : ChatRouteSubmit.ChainCheck {
            override fun registered(): Boolean? = null
            override fun state(afterAccepted: Boolean): ChainState = state(afterAccepted)
        }
        return ChatRouteSubmit.submit(
            bases = listOf("https://x.test"),
            bodyFor = { "{}" },
            poster = ChatRouteSubmit.Poster { _, _, _ -> ChatRouteSubmit.Transport.Answer(status, body) },
            chain = check,
            backoffMs = { 0 },
            pause = { },
        )
    }

    @Test
    fun anAcceptedAnswerIsSubmittedOnlyWhenThePollMatchesAndTheOthersAreNamed() {
        val ok = "{\"ok\":true}"
        assertTrue(submit(200, ok) { ChainState.MATCH } is ChatRouteSubmit.Outcome.Submitted)
        assertTrue(submit(200, ok) { ChainState.ABSENT } is ChatRouteSubmit.Outcome.UnverifiedSubmit)
        assertTrue(submit(200, ok) { ChainState.CONFLICT } is ChatRouteSubmit.Outcome.Conflict)
        assertTrue(submit(200, ok) { ChainState.UNKNOWN } is ChatRouteSubmit.Outcome.NetworkUnavailable)
        // The poll is asked for after an accepted answer, a single read otherwise.
        val asked = mutableListOf<Boolean>()
        submit(200, ok) { asked += it; ChainState.MATCH }
        assertEquals(listOf(true), asked)
    }

    @Test
    fun aFiveHundredReadsOnceAndAConflictIsNeverResent() {
        var sent = 0
        val outcome = ChatRouteSubmit.submit(
            bases = listOf("https://x.test"), bodyFor = { "{}" },
            poster = ChatRouteSubmit.Poster { _, _, _ -> sent++; ChatRouteSubmit.Transport.Answer(500, "") },
            chain = ChatRouteSubmit.ChainCheck { null }.let { base ->
                object : ChatRouteSubmit.ChainCheck {
                    override fun registered(): Boolean? = null
                    override fun state(afterAccepted: Boolean) = ChainState.CONFLICT
                }
            },
            backoffMs = { 0 }, pause = { },
        )
        assertTrue(outcome is ChatRouteSubmit.Outcome.Conflict)
        assertEquals(1, sent)
        assertTrue(submit(409, "") { ChainState.MATCH } is ChatRouteSubmit.Outcome.Submitted)
        assertTrue(submit(409, "") { ChainState.CONFLICT } is ChatRouteSubmit.Outcome.Conflict)
        assertTrue(submit(409, "") { ChainState.ABSENT } is ChatRouteSubmit.Outcome.Refused)
    }

    @Test
    fun theOlderBooleanCheckStillMapsToTheStates() {
        assertEquals(ChainState.MATCH, ChatRouteSubmit.ChainCheck { true }.state(true))
        assertEquals(ChainState.ABSENT, ChatRouteSubmit.ChainCheck { false }.state(true))
        assertEquals(ChainState.UNKNOWN, ChatRouteSubmit.ChainCheck { null }.state(false))
    }

    @Test
    fun thePageCommandAndTheCoordinatorShareTheFlightAndTheReadbackIsWired() {
        val module = File("src/main/java/network/conet/chat/BeamioConetChatModule.kt").readText()
        assertTrue(module.contains("IdentityRegisterFlight.tryEnter(eoa)"))
        assertTrue(module.contains("RegistrationReadback.check(expected"))
        assertTrue(module.contains("registration_conflict"))
        val coordinator = File("src/main/java/network/conet/chat/nativekey/FirstIdentityCoordinator.kt").readText()
        assertTrue(coordinator.contains("flightEnter: (String) -> Boolean = IdentityRegisterFlight::tryEnter"))
    }

    // ---- identityPublic with the public armors -----------------------------------------------------------------------------------------

    private fun source(state: IdentityPublic.PgpState?, pub: String?, routeArmor: String?) = object : IdentityPublic.Source {
        override fun eoa(): String? = account
        override fun pgp(): IdentityPublic.PgpRecord = IdentityPublic.PgpRecord.NotRead
        override fun pgpState() = state
        override fun pgpKeyId(): String? = own.identity.subkeyKeyId
        override fun pgpPublicArmor(): String? = pub
        override fun ownRouteArmor(): String? = routeArmor
    }

    private fun answer(src: IdentityPublic.Source): JSONObject =
        IdentityPublic.answer(NoKeyGate.Gate.G2, { listOf("type", "reqId") }, 1, src).result!!

    @Test
    fun aReadyVaultGivesThePublicKeyAndTheRouteAndNeverAPrivateKey() {
        val route = RecKeys.generate("route", random).publicArmor
        val r = answer(source(IdentityPublic.PgpState.READY, own.publicArmor, route))
        assertTrue(r.getBoolean("pgpReady"))
        assertEquals(own.identity.subkeyKeyId, r.getString("pgpKeyID"))
        assertEquals(own.publicArmor, r.getString("pgpPublicKeyArmored"))
        assertEquals(route, r.getString("ownRouteArmoredPublicKey"))
        assertFalse(r.toString().contains("PRIVATE KEY"))
    }

    @Test
    fun aPrivateArmorOrNoRouteOrANonReadyStateAddsNoArmorField() {
        val none = answer(source(IdentityPublic.PgpState.READY, own.publicArmor, null))
        assertFalse("no route read back yet: not ready, and none of the three fields", none.getBoolean("pgpReady"))
        assertFalse(none.has("pgpPublicKeyArmored") || none.has("ownRouteArmoredPublicKey") || none.has("pgpKeyID"))
        val priv = answer(source(IdentityPublic.PgpState.READY, own.privateArmor, own.privateArmor))
        assertFalse("a private armor is never let through", priv.has("pgpPublicKeyArmored") || priv.has("ownRouteArmoredPublicKey"))
        for (state in listOf(IdentityPublic.PgpState.NOT_READY, IdentityPublic.PgpState.UNKNOWN)) {
            val r = answer(source(state, own.publicArmor, own.publicArmor))
            assertFalse(r.getBoolean("pgpReady"))
            assertFalse(r.has("pgpPublicKeyArmored") || r.has("ownRouteArmoredPublicKey") || r.has("pgpKeyID"))
        }
    }

    // ---- N-14, N-15: identityPublic needs all three, and the route armor is the read-back one --------------------------------------------------

    @Test
    fun pgpReadyIsTrueOnlyWithTheKeyIdThePublicArmorAndTheRouteArmor() {
        val route = RecKeys.generate("route", random).publicArmor
        fun src(keyId: String?, pub: String?, rt: String?) = object : IdentityPublic.Source {
            override fun eoa(): String? = account
            override fun pgp(): IdentityPublic.PgpRecord = IdentityPublic.PgpRecord.NotRead
            override fun pgpState() = IdentityPublic.PgpState.READY
            override fun pgpKeyId(): String? = keyId
            override fun pgpPublicArmor(): String? = pub
            override fun ownRouteArmor(): String? = rt
        }
        val full = answer(src(own.identity.subkeyKeyId, own.publicArmor, route))
        assertTrue(full.getBoolean("pgpReady"))
        assertEquals(setOf("eoa", "accountKey", "pgpReady", "pgpKeyID", "pgpPublicKeyArmored", "ownRouteArmoredPublicKey"), full.keys().asSequence().toSet())
        for ((label, s) in listOf(
            "no key id" to src(null, own.publicArmor, route),
            "an empty key id" to src("", own.publicArmor, route),
            "no public armor" to src(own.identity.subkeyKeyId, null, route),
            "no route armor" to src(own.identity.subkeyKeyId, own.publicArmor, null),
            "an empty route placeholder" to src(own.identity.subkeyKeyId, own.publicArmor, ""),
            "a route that is not public armor" to src(own.identity.subkeyKeyId, own.publicArmor, "placeholder"),
        )) {
            val r = answer(s)
            assertFalse("$label: not ready", r.getBoolean("pgpReady"))
            assertFalse("$label: none of the three fields", r.has("pgpKeyID") || r.has("pgpPublicKeyArmored") || r.has("ownRouteArmoredPublicKey"))
        }
    }

    @Test
    fun theRouteArmorIsTheRosterKeyOfTheRouteTheRegistrationWasReadBackOn() {
        FirstIdentityRegistered.resetForTests()
        val nodeA = RecKeys.generate("a", random).publicArmor
        val nodeB = RecKeys.generate("b", random).publicArmor
        val roster = listOf("AAAA1111AAAA1111" to nodeA, "BBBB2222BBBB2222" to nodeB)
        assertNull("nothing recorded yet", FirstIdentityRegistered.routeArmor(account, roster))
        FirstIdentityRegistered.record(account, "bbbb2222bbbb2222")
        assertEquals(nodeB, FirstIdentityRegistered.routeArmor(account, roster))
        assertNull("a route that is not in the roster gives none, never a placeholder", FirstIdentityRegistered.routeArmor(account, listOf("CCCC" to nodeA)))
        assertNull("a roster entry that is not public armor gives none", FirstIdentityRegistered.routeArmor(account, listOf("BBBB2222BBBB2222" to "")))
        assertNull("another account has none", FirstIdentityRegistered.routeArmor("0x" + "cd".repeat(20), roster))
        // The coordinator records the route only when the readback matched (the registration paths and the already-complete path).
        val src = File("src/main/java/network/conet/chat/nativekey/FirstIdentityCoordinator.kt").readText()
        assertEquals(4, Regex("FirstIdentityRegistered\\.record\\(account, ").findAll(src).count())
    }
}
