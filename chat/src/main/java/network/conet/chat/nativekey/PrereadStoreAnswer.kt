package network.conet.chat.nativekey

import org.json.JSONObject

/**
 * The nativeMnemonicPreread answer (the empty-store fallback, 2026-11-22).
 *
 * 1. A current set in the store is returned as it is: `ok` with the mnemonic (plain) or the cipher (v3, never the plaintext). A current set whose
 *    EOA differs from a Ready vault account is still returned; the mismatch is reported as the diagnostic code `store_vault_eoa_mismatch`, and the
 *    vault is not changed.
 * 2. An empty store (Absent) falls back to the old vault, read only (the vault is not removed or overwritten, and stays the read-only fallback):
 *    NoKey → confirmed_missing; Ready with a verified phrase → `ok` with the mnemonic; Ready without one, Locked (any reason), an unreadable vault,
 *    or a read that throws → read_error (retryable, nothing changed).
 * 3. An undetermined store (Unknown) → read_error.
 *
 * Pure: the vault is given as [VaultSource]; the module reads the vault, this function only maps.
 */
internal object PrereadStoreAnswer {

    /** The read-only view of the old vault for the fallback. [Ready.phrase] is null when the vault holds no verified phrase. */
    sealed class VaultSource {
        object NoKey : VaultSource()
        /**
         * [eoa] is the vault's Ready account. [phraseRead] is called only when the answer needs the phrase (an empty store), never for a current set.
         * [keyOnlyRead] tells a key-only vault (the key record is read, no phrase item at all) from a phrase that cannot be read or verified
         * only the former is confirmed missing on an empty store.
         */
        class Ready(
            val eoa: String,
            private val phraseRead: () -> String?,
            private val keyOnlyRead: () -> Boolean = { false },
        ) : VaultSource() {
            fun phrase(): String? = phraseRead()
            fun keyOnly(): Boolean = keyOnlyRead()
        }
        object Unreadable : VaultSource()
    }

    /** A diagnostic code (not an answer code) for the store and vault mismatch; the answer is the store's. */
    const val DIAG_STORE_VAULT_EOA_MISMATCH = "store_vault_eoa_mismatch"

    /** The answer and an optional diagnostic code. */
    class Result(val answer: JSONObject, val diag: String?)

    /** The answer for [current], with the vault fallback for an empty store (see the class comment). */
    fun answerWithVault(current: MnemonicSetStore.Current, vaultRead: () -> VaultSource): Result {
        // A vault read that throws is an unreadable vault (read_error for an empty store), never an escaping error.
        val vault: () -> VaultSource = { try { vaultRead() } catch (_: Exception) { VaultSource.Unreadable } }
        return answerWithVaultSource(current, vault)
    }

    private fun answerWithVaultSource(current: MnemonicSetStore.Current, vault: () -> VaultSource): Result = when (current) {
        is MnemonicSetStore.Current.Found -> {
            val diag = (vault() as? VaultSource.Ready)?.takeIf { !it.eoa.equals(current.eoa, ignoreCase = true) }
                ?.let { DIAG_STORE_VAULT_EOA_MISMATCH }
            Result(answer(current), diag)
        }
        is MnemonicSetStore.Current.Absent -> Result(
            when (val v = vault()) {
                is VaultSource.NoKey -> JSONObject().put("code", "confirmed_missing")
                is VaultSource.Ready -> v.phrase()?.let { JSONObject().put("code", "ok").put("mnemonic", it).put("eoa", v.eoa.lowercase()) }
                    ?: if (v.keyOnly()) JSONObject().put("code", "confirmed_missing") else JSONObject().put("code", "read_error")
                is VaultSource.Unreadable -> JSONObject().put("code", "read_error")
            },
            null,
        )
        is MnemonicSetStore.Current.Unknown -> Result(JSONObject().put("code", "read_error"), null)
    }

    /** The answer for the store's current set alone (no vault): an empty store is confirmed_missing. */
    fun answer(current: MnemonicSetStore.Current): JSONObject = when (current) {
        is MnemonicSetStore.Current.Absent -> JSONObject().put("code", "confirmed_missing")
        is MnemonicSetStore.Current.Found -> when (current.kind) {
            // Supplement 32 (NP-14): the plain ok carries the set's EOA; the cipher reply is unchanged (no eoa).
            MnemonicSetStore.Kind.PLAIN -> JSONObject().put("code", "ok").put("mnemonic", current.value).put("eoa", current.eoa.lowercase())
            MnemonicSetStore.Kind.V3 -> try {
                JSONObject().put("code", "ok").put("cipher", JSONObject(current.value))
            } catch (_: org.json.JSONException) {
                // A damaged set file is a read failure, never a confirmed absence and never a crash.
                JSONObject().put("code", "read_error")
            }
        }
        is MnemonicSetStore.Current.Unknown -> JSONObject().put("code", "read_error")
    }
}
