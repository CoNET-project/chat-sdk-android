package network.conet.chat.nativekey

import android.content.Context
import org.json.JSONObject

/**
 * `pageCopyState(eoa)` (§25.52PY.15 第 15 项, §25.52PY.17; r3rz). The state of the page wallet copy of [eoa] (§25.52W.4): `absent`, `unreadable`, or
 * `readable(eoaMatchesKeychain)`. It returns only the state: no secret, no content. Native application layer only; not a bridge command.
 */
internal object PageCopyState {
    sealed class Result {
        /** No page copy for the account (§25.52PY.15 第 14 项 (b): migrating). */
        object Absent : Result()

        /** The copy cannot be read: fail closed. */
        object Unreadable : Result()

        /** The copy is readable. [eoaMatchesKeychain] is true only when the EOA decoded from the copy, [eoa] and the keychain EOA are equal (PY.17 第 1 项). */
        data class Readable(val eoaMatchesKeychain: Boolean) : Result()
    }

    /**
     * The state of the copy in [store] for [eoa]. [keychainEoa] is the EOA of the native keychain state (null when the keychain holds none). The
     * EOA decoded from the copy is the address of the key in its profile that holds `privateKeyArmor` (PY.17 第 1 項 (a)); no decoded EOA means no match.
     */
    fun of(eoa: String, store: SealedPageRecordStore, keychainEoa: String?): Result {
        // Any failure to open the copy is fail closed (PY.17): never an exception to the caller, and never absent.
        val record: JSONObject? = try {
            store.read()
        } catch (_: Exception) {
            return Result.Unreadable
        }
        if (record == null) return Result.Absent
        val decoded = decodedEoa(record)
        val input = eoa.lowercase()
        val matches = decoded != null && decoded == input && keychainEoa != null && keychainEoa.lowercase() == input
        return Result.Readable(matches)
    }

    /** The address of the one key the copy holds, or null when it holds none, or more than one, or the key does not derive a profile of its own. */
    internal fun decodedEoa(record: JSONObject): String? {
        val profiles = record.optJSONArray("profiles") ?: return null
        val held = (0 until profiles.length()).mapNotNull { i ->
            val p = profiles.optJSONObject(i) ?: return@mapNotNull null
            val armor = p.optString("privateKeyArmor", "")
            if (armor.isEmpty()) null else p.optString("keyID", "").lowercase() to armor
        }
        if (held.size != 1) return null
        val (keyId, armor) = held[0]
        // The key bytes are zeroed after the derivation. The armor string is a JSON value of the record, which cannot be zeroed (a recorded risk).
        val hex = ShellRecordPolicy.normalizeLegacyKey(armor)?.removePrefix("0x") ?: return null
        val key = try {
            ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        } catch (_: NumberFormatException) {
            return null
        }
        try {
            val derived = WalletAddress.fromPrivateKey(key)?.lowercase() ?: return null
            return if (derived == keyId) derived else null
        } finally {
            key.fill(0)
        }
    }

    /** The device state of the copy of [eoa] (the default workspace, the native keychain state). */
    fun ofDevice(app: Context, eoa: String): Result {
        // A keychain or store that cannot be reached is fail closed: unreadable, not a match.
        val keychain = try {
            (NativeWallet.vault(app).state() as? NativeWalletVault.State.Ready)?.eoa
        } catch (_: Exception) {
            return Result.Unreadable
        }
        val store = try {
            BeamioShellRecordImport.storeFor(app, eoa)
        } catch (_: Exception) {
            return Result.Unreadable
        }
        return of(eoa, store, keychain)
    }
}
