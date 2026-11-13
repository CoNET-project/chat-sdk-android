package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Hardware layer of the native wallet key (spec r3b 25.17.5, device-key mode only). The key is
 * sealed with a non-exportable AES-GCM key: AndroidKeyStore on the device, an in-memory key in tests.
 */
interface KeyWrap {
    /** Returns `iv || ciphertext || tag`. Throws when the wrapping key is unavailable. */
    fun seal(aad: ByteArray, plain: ByteArray): ByteArray

    /** Returns the plaintext, or `null` when authentication fails or the wrapping key is gone. */
    fun open(aad: ByteArray, sealed: ByteArray): ByteArray?

    /** Removes the wrapping key. Records sealed under it can no longer be opened. */
    fun deleteKey()
}

/** Record and marker storage. [write] must be all-or-nothing (temp file and rename on the device). */
interface VaultFiles {
    fun read(name: String): ByteArray?
    fun write(name: String, bytes: ByteArray)
    fun delete(name: String)
}

/**
 * Native store for the account's EOA private key. Only native code writes it: a native import or a
 * legacy migration. The bridge never reaches it.
 *
 * Write order: record file, then read back from storage (unwrap, derive address, compare), then the
 * completion marker (SHA-256 of the record). A record without a matching marker was never confirmed
 * and is removed on the next [state] call. A record whose marker does not match is kept and locks the
 * vault, because deleting it could destroy the only copy.
 *
 * Nothing is overwritten: a second wallet is refused until [forget] runs. Plaintext keys are never
 * stored, logged or returned from [state]; [unlock] returns a fresh copy that the caller must zero.
 */
class NativeWalletVault(
    private val wrap: KeyWrap,
    private val files: VaultFiles,
) {
    sealed class State {
        /** No record: nothing to sign with. The user imports natively. */
        object NoKey : State()

        /** A record exists, passed readback, and belongs to [eoa]. */
        class Ready(val eoa: String) : State()

        /** A record exists but cannot be used. [reason] is a code, never key material. */
        class Locked(val reason: String) : State()
    }

    enum class Import(val code: String) {
        OK("ok"),
        ALREADY_PRESENT("already_present"),
        BAD_EOA("bad_eoa"),
        BAD_KEY("bad_key"),
        ADDRESS_MISMATCH("address_mismatch"),
        RECORD_EXISTS("record_exists"),
        STORE_FAILED("store_failed"),
        READBACK_FAILED("readback_failed"),
    }

    private class Opened(val eoa: String, val key: ByteArray)

    /** Reports the state. Also removes a record that never reached its completion marker. */
    @Synchronized
    fun state(): State {
        val rec = files.read(REC)
        val mark = files.read(MARK)
        if (rec == null) {
            if (mark != null) files.delete(MARK)
            return State.NoKey
        }
        if (mark == null) {
            files.delete(REC)
            return State.NoKey
        }
        if (!mark.contentEquals(digestHex(rec).toByteArray(Charsets.US_ASCII))) return State.Locked("marker_mismatch")
        val opened = openRecord(rec) ?: return State.Locked("unreadable")
        opened.key.fill(0)
        return State.Ready(opened.eoa)
    }

    /** A fresh copy of the key for a confirmed record. The caller must zero it after use. */
    @Synchronized
    fun unlock(): ByteArray? {
        val rec = files.read(REC) ?: return null
        val mark = files.read(MARK) ?: return null
        if (!mark.contentEquals(digestHex(rec).toByteArray(Charsets.US_ASCII))) return null
        return openRecord(rec)?.key
    }

    /**
     * Stores [key] for [eoa] after checks: canonical EOA, 32-byte valid scalar, derived address equal to
     * [eoa], no existing record, readback, marker. [key] is only read; the caller zeroes it.
     */
    @Synchronized
    fun importKey(eoa: String, key: ByteArray, source: String = SOURCE_NATIVE_IMPORT): Import {
        if (!isCanonicalEoa(eoa)) return Import.BAD_EOA
        if (source != SOURCE_NATIVE_IMPORT && source != SOURCE_NATIVE_CREATE && source != SOURCE_LEGACY) return Import.BAD_KEY
        if (key.size != 32) return Import.BAD_KEY
        val derived = WalletAddress.fromPrivateKey(key) ?: return Import.BAD_KEY
        if (derived != eoa) return Import.ADDRESS_MISMATCH
        when (val st = state()) {
            is State.Ready -> return if (st.eoa == eoa) Import.ALREADY_PRESENT else Import.RECORD_EXISTS
            is State.Locked -> return Import.RECORD_EXISTS
            State.NoKey -> Unit
        }
        val rec = try {
            encodeRecord(eoa, source, wrap.seal(aad(eoa), key))
        } catch (e: Exception) {
            return Import.STORE_FAILED
        }
        try {
            files.write(REC, rec)
        } catch (e: Exception) {
            cleanup()
            return Import.STORE_FAILED
        }
        val back = try {
            files.read(REC)?.let { openRecord(it) }
        } catch (e: Exception) {
            null
        }
        val confirmed = back != null && back.eoa == eoa && back.key.contentEquals(key)
        back?.key?.fill(0)
        if (!confirmed) {
            cleanup()
            return Import.READBACK_FAILED
        }
        try {
            files.write(MARK, digestHex(rec).toByteArray(Charsets.US_ASCII))
        } catch (e: Exception) {
            cleanup()
            return Import.STORE_FAILED
        }
        return Import.OK
    }

    /** Removes the record, the marker and the wrapping key. Used on logout or when the wallet is removed. */
    @Synchronized
    fun forget() {
        runCatching { files.delete(MARK) }
        runCatching { files.delete(REC) }
        runCatching { wrap.deleteKey() }
    }

    private fun cleanup() {
        runCatching { files.delete(MARK) }
        runCatching { files.delete(REC) }
    }

    private fun openRecord(rec: ByteArray): Opened? {
        return try {
            val o = JSONObject(String(rec, Charsets.UTF_8))
            if (o.optInt("record", 0) != RECORD_VERSION) return null
            val eoa = o.optString("eoa", "")
            if (!isCanonicalEoa(eoa)) return null
            val sealed = ConetChatCryptoUtil.hexToBytes(o.optString("sealed", "")) ?: return null
            val key = wrap.open(aad(eoa), sealed) ?: return null
            if (key.size != 32 || WalletAddress.fromPrivateKey(key) != eoa) {
                key.fill(0)
                return null
            }
            Opened(eoa, key)
        } catch (e: Exception) {
            null
        }
    }

    private fun encodeRecord(eoa: String, source: String, sealed: ByteArray): ByteArray =
        JSONObject()
            .put("record", RECORD_VERSION)
            .put("eoa", eoa)
            .put("source", source)
            .put("sealed", ConetChatCryptoUtil.toHex(sealed))
            .toString()
            .toByteArray(Charsets.UTF_8)

    companion object {
        const val REC = "wallet.v1.rec"
        const val MARK = "wallet.v1.ok"
        const val RECORD_VERSION = 1
        const val SOURCE_NATIVE_IMPORT = "native_import"
        const val SOURCE_NATIVE_CREATE = "native_create"
        const val SOURCE_LEGACY = "legacy_migration"

        /** Hardware-layer AAD (spec 25.17.5): binds the record to its EOA. */
        fun aad(eoa: String): ByteArray = "beamio-native-wallet-v1|h|$eoa".toByteArray(Charsets.UTF_8)

        fun isCanonicalEoa(s: String): Boolean = Regex("^0x[0-9a-f]{40}$").matches(s)

        private fun digestHex(bytes: ByteArray): String =
            ConetChatCryptoUtil.toHex(MessageDigest.getInstance("SHA-256").digest(bytes))
    }
}
