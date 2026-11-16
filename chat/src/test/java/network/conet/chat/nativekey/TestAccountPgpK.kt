package network.conet.chat.nativekey

import java.io.IOException

/** An in-memory K store for the creation tests: the same contract as the device store, with no encryption. */
internal fun memoryAccountPgpK(): AccountPgpK = AccountPgpK(MemoryAccountPgpKBackend())

internal class MemoryAccountPgpKBackend : AccountPgpKBackend {
    val items = mutableMapOf<String, String>()
    override fun get(name: String): String? = items[name]
    override fun put(name: String, value: String): Boolean {
        items[name] = value
        return true
    }
    override fun names(): Set<String> = items.keys.toSet()
    override fun remove(name: String): Boolean {
        items.remove(name)
        return true
    }
}
