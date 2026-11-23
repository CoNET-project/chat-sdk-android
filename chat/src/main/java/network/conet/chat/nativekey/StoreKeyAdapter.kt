package network.conet.chat.nativekey

/**
 * The read-only key source of the two-state store (order 2026-11-22, step 1): signing, NativeSessionState, PGP decryption and the no-page
 * listen can take the account key from the current set. A plain set derives its key from the stored phrase, in memory only; the caller zeroes
 * the key. A v3 set needs the passcode that came with the sync, to be opened in memory for the session; that path is not here yet, so a v3
 * set gives no key and the vault path stays the fallback. Absent, unknown, and a phrase that does not derive the set's EOA give no key.
 */
internal object StoreKeyAdapter {

    /**
     * A fresh copy of the in-session key of the current v3 set, or null. It is used only when the held key derives the set's account
     * (design in-session v3). The caller zeroes the copy.
     */
    fun sessionKey(current: MnemonicSetStore.Current): ByteArray? {
        val found = current as? MnemonicSetStore.Current.Found ?: return null
        if (found.kind != MnemonicSetStore.Kind.V3) return null
        val key = SessionKeyHolder.keyFor(found.eoa) ?: return null
        val derived = WalletAddress.fromPrivateKey(key)?.lowercase()
        if (derived == null || derived != found.eoa.lowercase()) {
            key.fill(0)
            return null
        }
        return key
    }

    /** A fresh copy of the account key of the current plain set, or null (the caller zeroes it). */
    fun plainKey(current: MnemonicSetStore.Current): ByteArray? {
        val found = current as? MnemonicSetStore.Current.Found ?: return null
        if (found.kind != MnemonicSetStore.Kind.PLAIN) return null
        val key = MnemonicDerivation.deriveKey(found.value) ?: return null
        val derived = WalletAddress.fromPrivateKey(key)?.lowercase()
        if (derived == null || derived != found.eoa.lowercase()) {
            key.fill(0)
            return null
        }
        return key
    }
}

/**
 * The init decision for the store-only session (NOTE-, option A): when the vault has no key
 * (NoKey) and the store's current set is a plain set of the init account, the session is ready for that account and the signer takes its key;
 * init still answers no_key. A v3 set never makes the session ready here (it waits for the sync passphrase, step (2)). A Ready vault keeps its
 * own path (the storeMayAnswer rule), and a different account never adopts.
 */
internal object StoreSessionAdoption {

    /** The account and key to adopt, or null when the store does not make the session ready. The caller zeroes [key]. */
    class Adopt(val eoa: String, val key: ByteArray)

    fun plainAdoption(vaultState: network.conet.chat.nativekey.NativeWalletVault.State?, current: MnemonicSetStore.Current, initEoa: String): Adopt? {
        if (vaultState !is network.conet.chat.nativekey.NativeWalletVault.State.NoKey) return null
        if (!NativeMessageSigner.storeMayAnswer(current)) return null
        val found = current as? MnemonicSetStore.Current.Found ?: return null
        if (found.kind != MnemonicSetStore.Kind.PLAIN) return null
        if (!found.eoa.equals(initEoa, ignoreCase = true)) return null
        val key = StoreKeyAdapter.plainKey(current) ?: return null
        return Adopt(found.eoa.lowercase(), key)
    }
}
