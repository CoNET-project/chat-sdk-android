package network.conet.chat.nativekey

/**
 * The Keystore part of `init` for a vault account: unlock the key, hand it to the signer, and mark the session ready unless the
 * account is key-only. It runs on the init worker, off the main thread, so it must answer in every case: an exception here used to leave `init` with no
 * answer at all (the page waited for its 180 s timeout).
 *
 * The outcome is what the caller answers:
 *  - [Outcome.UNREADABLE]: the key could not be unlocked, or an Exception was thrown (a keystore or storage fault). Unknown, retryable: `not_ready`
 *    (`unreadable`), never `no_key`. The signer is cleared and the session is not marked ready.
 *  - [Outcome.KEY_ONLY]: a readable key with no phrase is not an account: the signer holds the key as before, the session is NOT marked ready, and init
 *    goes on (the gate stays G1).
 *  - [Outcome.SESSION_READY]: the session is marked ready for the account.
 * The key copy is zeroed in every case. An Error (out of memory and the like) gets the same cleanup (signer cleared, key zeroed, session not marked
 * ready) and is rethrown: it is never turned into an answer, and the process does not carry on with a state it may have corrupted.
 */
internal object InitUnlock {
    enum class Outcome { SESSION_READY, KEY_ONLY, UNREADABLE }

    /** The signer is cleared whatever failed; a fault of the clearing itself (or an Error while clearing) must not replace the failure being handled. */
    private fun cleanup(clearSigner: () -> Unit) {
        try {
            clearSigner()
        } catch (_: Throwable) {
        }
    }

    fun run(
        vault: NativeWalletVault,
        setSigner: (ByteArray) -> Unit,
        clearSigner: () -> Unit,
        markReady: () -> Unit,
    ): Outcome {
        var key: ByteArray? = null
        return try {
            key = vault.unlock()
            if (key == null) {
                clearSigner()
                return Outcome.UNREADABLE
            }
            setSigner(key)
            key.fill(0)
            key = null
            if (vault.keyOnlyChecked()) {
                Outcome.KEY_ONLY
            } else {
                markReady()
                Outcome.SESSION_READY
            }
        } catch (_: Exception) {
            // A fault after the signer was set must not leave a signer for a session that is not ready: cleared, and the answer is retryable.
            cleanup(clearSigner)
            Outcome.UNREADABLE
        } catch (e: Throwable) {
            // An Error (OutOfMemoryError, StackOverflowError, ...) gets the same cleanup, so the process cannot go on with a signer for a session that
            // is not ready, and is then rethrown: it is not swallowed into an answer, and the process is not kept running on a state it may have corrupted
            // (the Android convention; the uncaught-exception handler decides). The key copy is zeroed in `finally` below.
            cleanup(clearSigner)
            throw e
        } finally {
            key?.fill(0)
        }
    }
}
