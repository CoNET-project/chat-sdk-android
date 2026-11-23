package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The pwaWalletSync cipher sync (step (2)). Pure: the caller gives the envelope, the passcode (or
 * none) and a stage function for the two-state store; this function decides and writes nothing else.
 *
 * - Format first: an envelope that is not v3 or does not match its parameters is verify_failed, and nothing is decrypted or written.
 * - With a passcode: the envelope is opened first (a wrong passcode or a failed GCM tag is unlock_failed; another address is verify_failed); none
 *   of these writes. The passcode is used in memory only, never logged.
 * - The write: the stage writes a new version and reads it back; the pointer moves only at commit. A failed stage or commit is a write failure and
 *   the current set is not switched; the older sets stay.
 * - Without a passcode the answer is ok with decrypted=false; with one, decrypted=true. The answer carries stored, readback and decrypted in the
 *   result, beside the code (the position of stored/readback/decrypted is confirmed by the interface; write_failed's position is not fixed here).
 */
internal object PwaSyncCipher {

    /** The outcome: ok with decrypted, or a failure code (the envelope error of the ack). */
    sealed class Outcome {
        /** [phrase] is set only when the passcode opened the envelope and the set was written; the caller derives the key and zeroes nothing else. */
        class Ok(val decrypted: Boolean, val phrase: String? = null) : Outcome()
        class Fail(val code: String, val reason: String? = null) : Outcome()
    }

    /** The plain staging of the phrase branch: a ready staged write (the pointer not yet moved), or the answer code. */
    sealed class PlainStart {
        class Ready(val staged: MnemonicSetStore.Staged) : PlainStart()
        class Fail(val code: String, val reason: String? = null) : PlainStart()
        /** The account has a saved v3 set: the plaintext is not written and the answer is `unchanged`. */
        object Unchanged : PlainStart()
    }

    /** Stages the phrase of [eoa] in [store] before the vault write: a different phrase for the same EOA is bad_request, a write failure is write_failed. */
    fun startPlain(store: MnemonicSetStore, eoa: String, phrase: String): PlainStart =
        when (val st = store.stagePlain(eoa, phrase)) {
            is MnemonicSetStore.Stage.Ready -> PlainStart.Ready(st.staged)
            is MnemonicSetStore.Stage.Refused -> PlainStart.Fail(NativeSyncAck.BAD_REQUEST)
            is MnemonicSetStore.Stage.V3Present -> PlainStart.Unchanged
            is MnemonicSetStore.Stage.Unverifiable -> PlainStart.Fail(NativeSyncAck.BAD_REQUEST)
            is MnemonicSetStore.Stage.Failed -> PlainStart.Fail(NativeSyncAck.WRITE_FAILED, failedReason(st.reason))
        }

    /** The write-failure reason of a failed stage: a read-back mismatch is an unknown state; any other write error is a plain write failure. */
    internal fun failedReason(stageReason: String): String =
        if (stageReason == "readback_mismatch") NativeSyncAck.INTERNAL_STATE else NativeSyncAck.STORAGE_WRITE

    /** The envelope of the request's `cipher` object, or null when a field is missing. */
    fun envelopeOf(c: JSONObject?): MnemonicCipherV3.Envelope? {
        if (c == null) return null
        return try {
            MnemonicCipherV3.Envelope(
                c.getInt("v"), c.getString("mode"), c.getString("eoa"), c.getString("kdf"),
                c.getString("salt"), c.getString("iv"), c.getString("alg"), c.getString("ct"),
            )
        } catch (_: Exception) {
            null
        }
    }

    /** The cipher sync decision and write (see the class comment). [passcode] is null when none was sent. */
    fun run(env: MnemonicCipherV3.Envelope?, passcode: String?, stage: (MnemonicCipherV3.Envelope, Boolean) -> MnemonicSetStore.Stage): Outcome {
        if (env == null || !MnemonicCipherV3.formatOk(env)) return Outcome.Fail(NativeSyncAck.VERIFY_FAILED)
        var decrypted = false
        var phrase: String? = null
        if (passcode != null) {
            val opened = MnemonicCipherV3.open(env, passcode)
            when (opened.code) {
                MnemonicCipherV3.CODE_OK -> {
                    decrypted = true
                    phrase = opened.phrase
                }
                MnemonicCipherV3.CODE_UNLOCK_FAILED -> return Outcome.Fail(NativeSyncAck.UNLOCK_FAILED)
                else -> return Outcome.Fail(NativeSyncAck.VERIFY_FAILED)
            }
        }
        // The second argument tells the store whether the envelope was verified: a passcode opened it and the derived address matched the envelope's.
        return when (val st = stage(env, decrypted)) {
            is MnemonicSetStore.Stage.Ready -> {
                when (st.staged.commitOutcome()) {
                    MnemonicSetStore.Commit.OK -> Outcome.Ok(decrypted, phrase)
                    MnemonicSetStore.Commit.READBACK_MISMATCH -> {
                        st.staged.abort()
                        Outcome.Fail(NativeSyncAck.WRITE_FAILED, NativeSyncAck.INTERNAL_STATE)
                    }
                    MnemonicSetStore.Commit.WRITE_FAILED -> {
                        st.staged.abort()
                        Outcome.Fail(NativeSyncAck.WRITE_FAILED, NativeSyncAck.STORAGE_WRITE)
                    }
                }
            }
            is MnemonicSetStore.Stage.Refused -> Outcome.Fail(NativeSyncAck.VERIFY_FAILED)
            is MnemonicSetStore.Stage.V3Present -> Outcome.Fail(NativeSyncAck.VERIFY_FAILED)
            // M6 v3.3: unverifiable bytes that differ from every saved v3 version of the account: bad_request, nothing written.
            is MnemonicSetStore.Stage.Unverifiable -> Outcome.Fail(NativeSyncAck.BAD_REQUEST)
            is MnemonicSetStore.Stage.Failed -> Outcome.Fail(NativeSyncAck.WRITE_FAILED, failedReason(st.reason))
        }
    }
}
