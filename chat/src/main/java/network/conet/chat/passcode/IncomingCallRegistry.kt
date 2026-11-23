package network.conet.chat.passcode

import network.conet.chat.nativekey.NativeSessionState

/**
 * The current incoming call, as the native side knows it (addenda 13 §4.2 and 14 §二). The shell registers it with [bind] when the call is
 * answered and removes it with [unbind] when the call ends. The SDK also clears it itself when the session ends (E-24), through
 * [onSessionEnded], which advances the account's generation in the same critical section.
 *
 * These are native in-process calls. They are not bridge commands and are not in any command allowlist, so a page cannot register or clear a call.
 * Only one call is current at a time.
 */
internal class IncomingCallRegistry(
    private val generation: SessionGeneration,
    private val session: PasscodeSessionSource = NoPasscodeSession,
) {
    private class Entry(val callId: String, val eoa: String, val gen0: Long)

    private var current: Entry? = null

    /** What [check] found for a request that names (or does not name) a call. */
    sealed class CallCheck {
        /** No call is registered and the request names none: an ordinary unlock. */
        object NoPendingCall : CallCheck()

        /** A call is registered and the request names none: the unlock runs, and the call ends as cancelled. */
        object CancelsCall : CallCheck()

        /** The named call is the registered one and the accounts agree. [gen0] is the generation captured at bind. */
        class Proceed(val gen0: Long) : CallCheck()

        /** The named call is not the registered one, or none is registered. The call itself is not affected. */
        object CallMismatch : CallCheck()

        /** The registered account, the request's account and the current account do not all agree. */
        object AccountMismatch : CallCheck()
    }

    /** Registers [callId] for [eoa] and captures the generation of that account. Returns false when either value is malformed. */
    @Synchronized
    fun incomingCallBind(callId: String, eoa: String): Boolean {
        if (!PasscodeUnlockEntry.isCallId(callId) || !PasscodeUnlockEntry.isEoa(eoa)) return false
        val account = eoa.lowercase()
        current = Entry(callId, account, generation.current(account))
        return true
    }

    /** Removes the registration when [callId] is the registered call. Any other value leaves the registration as it is. */
    @Synchronized
    fun incomingCallUnbind(callId: String) {
        if (current?.callId == callId) current = null
    }

    /**
     * The session of [account] ends for [reason] (lock of an unlocked account, logout, or switch away from the account). The generation advances,
     * and the registration is cleared in the same step, so no later request sees the old call.
     */
    @Synchronized
    fun onSessionEnded(account: String, reason: SessionGeneration.Reason): Long {
        val next = generation.advance(account, reason)
        current = null
        return next
    }

    /**
     * Judges a request against the registration. Runs before any passcode check. A request names at most one [callId]; null means it names none.
     * Order: the account first, then the callId. The request eoa, the registered eoa and the current account must all be equal;
     * any difference is account_mismatch, even when the callId is also wrong. Only then is the callId compared.
     */
    @Synchronized
    fun check(callId: String?, eoa: String, currentAccount: String): CallCheck {
        val cur = current
        if (callId == null) return if (cur == null) CallCheck.NoPendingCall else CallCheck.CancelsCall
        // Account first (notice v2): the request eoa must equal the current account, even when no call is registered.
        val requested = eoa.lowercase()
        if (requested != currentAccount.lowercase()) return CallCheck.AccountMismatch
        if (cur == null) return CallCheck.CallMismatch
        if (cur.eoa != requested) return CallCheck.AccountMismatch
        if (cur.callId != callId) return CallCheck.CallMismatch
        return CallCheck.Proceed(cur.gen0)
    }

    /**
     * The decision the shell takes before signing. The non-unlock conditions come first (the call is still registered, the
     * callId matches, the current account is the registered eoa, the generation is unchanged); any failure is [DENY]. Then the one SDK reading: an
     * unreadable native reading is [DENY] (a storage or keystore fault is never hidden); a native session that is not loaded is [NEEDS_UNLOCK]; a
     * loaded one is [ALLOW]. The passcode and the UI lock are not read here: the UI owns them. The readings come from the SDK's own
     * source ([session]), never from the caller. The shell does not compare generations itself.
     */
    @Synchronized
    fun incomingCallAuthorizeAnswer(callId: String, currentAccount: String): String {
        val cur = current ?: return DENY
        if (cur.callId != callId) return DENY
        if (cur.eoa != currentAccount.lowercase()) return DENY
        if (generation.current(cur.eoa) != cur.gen0) return DENY
        val native = runCatching { session.nativeUnlocked(cur.eoa) }.getOrNull() ?: return DENY
        return if (native) ALLOW else NEEDS_UNLOCK
    }

    companion object {
        const val ALLOW = "allow"
        const val DENY = "deny"
        const val NEEDS_UNLOCK = "needs_unlock"
    }
}

/**
 * The SDK's own reading for the authorize decision: whether the native session is loaded for the account (true or false), or null when unreadable
 * (null is deny). The passcode and the UI lock are not part of it (the UI owns them).
 */
internal interface PasscodeSessionSource {
    fun nativeUnlocked(account: String): Boolean?
}

/** No source at all: every reading is unreadable, so every authorization is deny. Used by tests that need the fail-closed default. */
internal object NoPasscodeSession : PasscodeSessionSource {
    override fun nativeUnlocked(account: String): Boolean? = null
}

/** The native session as the SDK reads it: the keystore-backed session state of the account. */
internal object NativeSessionSource : PasscodeSessionSource {
    override fun nativeUnlocked(account: String): Boolean? = NativeSessionState.isReadyFor(account)
}

/** The process-wide incoming-call registry the shell's native calls use. The bridge does not reach it. */
internal object IncomingCalls {
    val registry: IncomingCallRegistry = IncomingCallRegistry(SessionGeneration(), NativeSessionSource)
}
