package network.conet.chat.nativekey

import java.io.IOException

/**
 * The replay of the stored inbox at `init` (finishInit, deferAck pages). Each stored message is decrypted with the account's PGP key: a Keystore
 * operation, seconds on a hardware-backed keystore. It used to run on the main thread (finishInit does), where it held the UI for 3.5 s on the S25.
 * It now runs on [execute] (the module's io pool), and only the handling of a decrypted line goes back to the main thread, as before (the decrypt
 * callback posts to it).
 *
 * Every stored message not already pending is forgotten by the dedupe first (so the replay is not dropped as a repeat) and then decrypted. If the same
 * message reaches the module from the listen meanwhile, [SeenArmor.markSeen] lets exactly one of the two through.
 */
internal object InboxReplay {
    /** Schedules the replay on [execute] and returns at once. An unreadable inbox is unknown, not empty: nothing is replayed (retried at the next init). */
    fun <E> start(
        execute: (Runnable) -> Unit,
        load: () -> List<E>,
        hashOf: (E) -> String,
        isPending: (String) -> Boolean,
        forget: (String) -> Unit,
        decrypt: (E) -> Unit,
        log: (String) -> Unit,
    ) {
        execute(Runnable {
            val all = try {
                load()
            } catch (_: IOException) {
                log("inbox unreadable; not replayed")
                return@Runnable
            }
            val stored = all.filter { !isPending(hashOf(it)) }
            if (stored.isEmpty()) return@Runnable
            log("inbox replay count=${stored.size}")
            for (e in stored) {
                forget(hashOf(e))
                decrypt(e)
            }
        })
    }
}
