package network.conet.chat.nativekey

import network.conet.chat.BeamioOwnRouteCheck
import java.util.concurrent.ConcurrentHashMap

/** What the chain says about one registration, compared with what this device submitted. */
internal enum class ChainState {
    /** The chain holds this device's key (same fingerprint and subkey id) on the expected route. */
    MATCH,

    /** Nothing, or this device's key without the route yet: not complete, keep reading. */
    ABSENT,

    /** The chain holds another key for the account: never overwritten from here. */
    CONFLICT,

    /** The chain cannot answer right now (never "absent"). */
    UNKNOWN,
}

/** The identity the chain holds for an account: the key's fingerprint and subkey id, and the route key id. Public values only. */
internal class ChainIdentityView(val fingerprint: String, val subkeyKeyId: String, val routeKeyId: String?)

internal sealed class ChainIdentityRead {
    object Unknown : ChainIdentityRead()
    object Absent : ChainIdentityRead()
    class Present(val view: ChainIdentityView) : ChainIdentityRead()
}

/**
 * The readback of a registration: the comparison and the bounded poll. The comparison uses the normalized public armor's identity
 * (the same rule as [RegisteredArmor]), never the raw stored text, and compares the route too.
 */
internal object RegistrationReadback {
    class Expected(val fingerprint: String, val subkeyKeyId: String, val routeKeyId: String)

    /** Waits between readbacks after an accepted submission: 2+4+8+16+30+30 = 90 s (the project default; after it the state is retry_later). */
    val POLL_DELAYS_MS: LongArray = longArrayOf(2_000, 4_000, 8_000, 16_000, 30_000, 30_000)

    fun verdict(expected: Expected, read: ChainIdentityRead): ChainState = when (read) {
        is ChainIdentityRead.Unknown -> ChainState.UNKNOWN
        is ChainIdentityRead.Absent -> ChainState.ABSENT
        is ChainIdentityRead.Present -> {
            val v = read.view
            when {
                !v.fingerprint.equals(expected.fingerprint, ignoreCase = true) || !v.subkeyKeyId.equals(expected.subkeyKeyId, ignoreCase = true) ->
                    ChainState.CONFLICT
                expected.routeKeyId.isNotBlank() && v.routeKeyId?.equals(expected.routeKeyId, ignoreCase = true) != true -> ChainState.ABSENT
                else -> ChainState.MATCH
            }
        }
    }

    /**
     * Reads until MATCH or CONFLICT, sleeping [delaysMs] between reads; [sleep] returns false to stop. After the window, UNKNOWN when no read ever
     * answered, otherwise ABSENT (the chain answered but the registration is not there yet).
     */
    fun poll(
        expected: Expected,
        read: () -> ChainIdentityRead,
        sleep: (Long) -> Boolean,
        delaysMs: LongArray = POLL_DELAYS_MS,
    ): ChainState {
        var answered = false
        var i = 0
        while (true) {
            val state = verdict(expected, read())
            if (state == ChainState.MATCH || state == ChainState.CONFLICT) return state
            if (state == ChainState.ABSENT) answered = true
            if (i >= delaysMs.size) return if (answered) ChainState.ABSENT else ChainState.UNKNOWN
            if (!sleep(delaysMs[i++])) return if (answered) ChainState.ABSENT else ChainState.UNKNOWN
        }
    }

    /** The check the submission uses: a bounded poll after an accepted answer, one read otherwise. */
    fun check(
        expected: Expected,
        read: () -> ChainIdentityRead,
        sleep: (Long) -> Boolean = { Thread.sleep(it); true },
        delaysMs: LongArray = POLL_DELAYS_MS,
    ): ChatRouteSubmit.ChainCheck = object : ChatRouteSubmit.ChainCheck {
        override fun registered(): Boolean? = when (state(false)) {
            ChainState.MATCH -> true
            ChainState.ABSENT -> false
            else -> null
        }

        override fun state(afterAccepted: Boolean): ChainState =
            if (afterAccepted) poll(expected, read, sleep, delaysMs) else verdict(expected, read())
    }
}

/** The production chain read of an account's identity: both endpoints at one block for the key, and the route key id of the same account. */
internal object ProductionIdentityRead {
    fun read(
        eoa: String,
        keyRead: (String) -> RegisteredKeyRead = { a ->
            AddressPgpChain.readAgreed(a) { ep -> AddressPgpRead.HttpRpc(ep.url, ep.timeoutMs) }.registeredKey()
        },
        routeRead: (String) -> BeamioOwnRouteCheck.ChainRoute = { a ->
            BeamioOwnRouteCheck.readChainRoute(AddressPgpConfig.default.endpoints[0].url, a)
        },
    ): ChainIdentityRead = when (val k = keyRead(eoa)) {
        is RegisteredKeyRead.Unknown -> ChainIdentityRead.Unknown
        is RegisteredKeyRead.Absent -> ChainIdentityRead.Absent
        is RegisteredKeyRead.Present -> when (val r = routeRead(eoa)) {
            is BeamioOwnRouteCheck.ChainRoute.Error -> ChainIdentityRead.Unknown
            is BeamioOwnRouteCheck.ChainRoute.Empty -> ChainIdentityRead.Present(ChainIdentityView(k.key.fingerprint, k.key.subkeyKeyId, null))
            is BeamioOwnRouteCheck.ChainRoute.Ok -> ChainIdentityRead.Present(ChainIdentityView(k.key.fingerprint, k.key.subkeyKeyId, r.routeKeyId))
        }
    }
}

/**
 * One registration at a time per account: the first-identity coordinator and the page's `chatRouteRegister` share it. A second caller for the same
 * account is refused (busy), never queued, so one account never has two submissions in flight.
 */
internal object IdentityRegisterFlight {
    private val inFlight: MutableSet<String> = ConcurrentHashMap.newKeySet()

    fun tryEnter(eoa: String): Boolean = inFlight.add(eoa.lowercase())

    fun exit(eoa: String) {
        inFlight.remove(eoa.lowercase())
    }

    inline fun <T> runExclusive(eoa: String, busy: () -> T, body: () -> T): T {
        if (!tryEnter(eoa)) return busy()
        try {
            return body()
        } finally {
            exit(eoa)
        }
    }

    internal fun resetForTests() {
        inFlight.clear()
    }
}
