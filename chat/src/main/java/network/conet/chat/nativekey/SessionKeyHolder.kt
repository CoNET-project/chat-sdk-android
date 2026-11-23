package network.conet.chat.nativekey

import network.conet.chat.nativekey.MnemonicSetStore
import java.util.Arrays

/**
 * The in-session key of a passcode-protected (v3) account (design: design-in-session-passcode-v3). The key is derived in memory
 * from the passphrase the PWA sent with pwaWalletSync and is held only in this process: it is never written, never logged, and it is cleared on a
 * reset or when another account becomes ready. A cold start begins empty. Each put copies the key; the caller zeroes its own copy.
 */
internal object SessionKeyHolder {
    private val lock = Any()
    private var eoa: String? = null
    private var key: ByteArray? = null

    /** Stores a copy of [privateKey] for [account] (lower case), replacing any other account's key. */
    fun put(account: String, privateKey: ByteArray) {
        synchronized(lock) {
            key?.let { Arrays.fill(it, 0.toByte()) }
            eoa = account.lowercase()
            key = privateKey.copyOf()
        }
    }

    /** A fresh copy of the key of [account] (case-insensitive), or null when none is held for it. The caller zeroes the copy. */
    fun keyFor(account: String): ByteArray? = synchronized(lock) {
        if (eoa == null || key == null || eoa != account.lowercase()) null else key!!.copyOf()
    }

    /** Clears the held key (zeroed). */
    fun clear() {
        synchronized(lock) {
            key?.let { Arrays.fill(it, 0.toByte()) }
            key = null
            eoa = null
        }
    }
}
