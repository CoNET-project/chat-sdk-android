package network.conet.chat.nativekey

import network.conet.chat.BeamioChatPgpStore

/**
 * The shipped-record candidate of the recovery: the account's own PGP private key that an older build left in the SDK's own store
 * (`beamio_chat_pgp_v1`), read inside the SDK. It is only a candidate: nothing here reads the chain, checks an identity or signs. The recovery gate
 * ([RecoveryChallengeGate]) decides whether it is the registered key, and only then is anything written. The old file is read, never changed.
 *
 *  - no record, a record of another account, or something that is not a private key block: [Candidate.None] (the chain backup is tried next);
 *  - a private key block of this account (or of an owner that was never stored): [Candidate.Present].
 */
internal object LegacyArmorRestore {
    sealed class Candidate {
        object None : Candidate()

        /** The armor stays inside the native layer; the gate decides whether it may be written. */
        class Present(val armor: String) : Candidate()
    }

    fun candidate(eoa: String, copy: BeamioChatPgpStore.LegacyCopy?): Candidate {
        if (copy == null) return Candidate.None
        // A record of another account is not this account's key. An owner that was never stored is judged by the gate's identity check.
        if (copy.eoa.isNotEmpty() && !copy.eoa.equals(eoa, ignoreCase = true)) return Candidate.None
        if (!copy.privateArmor.contains("BEGIN PGP PRIVATE KEY")) return Candidate.None
        return Candidate.Present(copy.privateArmor)
    }
}
