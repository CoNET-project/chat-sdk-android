package network.conet.chat.nativekey

/**
 * The inbound dedupe: the armor hashes already seen, bounded to the last 512. [markSeen] is true only for the first caller of a hash, whichever thread
 * it is on, so a message that reaches the module twice at once (the listen and the inbox replay, now on different threads) is handled once.
 * [forget] lets a hash through again (the replay of a stored message; a pending ack that expired).
 */
internal class SeenArmor(private val limit: Int = 512) {
    private val seen = object : LinkedHashMap<String, Boolean>(256, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>?): Boolean = size > limit
    }

    fun markSeen(hash: String): Boolean = synchronized(seen) {
        if (seen.containsKey(hash)) false else {
            seen[hash] = true
            true
        }
    }

    fun forget(hash: String) {
        synchronized(seen) { seen.remove(hash) }
    }

    fun clear() {
        synchronized(seen) { seen.clear() }
    }
}
