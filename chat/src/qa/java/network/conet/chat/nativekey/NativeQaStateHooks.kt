package network.conet.chat.nativekey

import android.content.Context

/**
 * QA-only state maker (2026-11-17: the QA hooks live only in the QA / debug product, never in the formal release AAR; the release symbol check
 * is in the handoff). It is compiled only with `-PchatQaHooks=true` (src/qa/java), and only the shell's native QA page calls it.
 *
 * [makeKeyOnlyAccount] builds the state "window after, only a private key B": the record of B is written from a SYNTHETIC phrase, with no phrase
 * record (MNEM), no pending marker and no intent. It refuses when any account is already present (the vault's own import refuses an existing
 * record). The key is derived and used inside the vault write; it is not returned, logged or exported.
 */
object NativeQaStateHooks {
    /** The outcome name of the import (the vault's Import enum), or `not_applicable` when the phrase does not derive a key. */
    fun makeKeyOnlyAccount(context: Context, syntheticPhrase: String): String {
        val key = MnemonicDerivation.deriveKey(syntheticPhrase) ?: return "not_applicable"
        try {
            val eoa = WalletAddress.fromPrivateKey(key) ?: return "not_applicable"
            val vault = NativeWallet.vault(context.applicationContext)
            return vault.importKey(eoa, key).name
        } finally {
            key.fill(0)
        }
    }
}
