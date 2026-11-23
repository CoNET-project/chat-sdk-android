package network.conet.chat.passcode

import network.conet.chat.ConetChatCryptoUtil
import network.conet.chat.nativekey.VaultFiles
import java.io.IOException

/**
 * The native passcode record of one account (protocol sections 7 and 9): one file per account, named by the lower-case EOA, holding
 * the salt and the passcode-layer blob. A write is: write a new file beside the old one, read it back, open it with the same passcode and
 * compare, and only then replace the old file. The old bytes are never removed before the new ones are verified (protocol section 9).
 * Encoding (text, strict): "passcode-record v1\nsalt=<hex>\nblob=<hex>\n". Anything else is an invalid record, never a missing one.
 */
class PasscodeRecordStore(private val files: VaultFiles) {
    enum class Write { OK, WRITE_FAILED, READBACK_MISMATCH }

    /** Result of a read: [Absent] means no file; [Invalid] means a file that does not decode (unknown, never absent). */
    sealed class Read {
        object Absent : Read()
        object Invalid : Read()
        class Record(val salt: ByteArray, val blob: ByteArray) : Read()
    }

    fun read(eoa: String): Read {
        val bytes = try {
            files.read(nameOf(eoa))
        } catch (_: IOException) {
            return Read.Invalid
        } ?: return Read.Absent
        return decode(bytes)?.let { Read.Record(it.first, it.second) } ?: Read.Invalid
    }

    /**
     * Writes the account key [inner] under [passcode]: new salt, seal, write the new file beside the old, read back, open with [passcode] and
     * compare with [inner], then replace the old file. Returns [Write.OK] only after the replace.
     */
    fun writeVerified(eoa: String, passcode: String, inner: ByteArray): Write {
        PasscodeWriteState.begin(eoa)
        return try {
            writeVerifiedInner(eoa, passcode, inner)
        } finally {
            PasscodeWriteState.end(eoa)
        }
    }

    private fun writeVerifiedInner(eoa: String, passcode: String, inner: ByteArray): Write {
        val salt = PasscodeLayer.newSalt()
        val blob = PasscodeLayer.seal(passcode, salt, PasscodeLayer.aadForAccountKey(eoa), inner)
        val bytes = encode(salt, blob)
        val fresh = nameOf(eoa) + NEW_SUFFIX
        try {
            files.write(fresh, bytes)
        } catch (_: IOException) {
            bestEffortDelete(fresh)
            return Write.WRITE_FAILED
        }
        val readBack = try { files.read(fresh) } catch (_: IOException) { null }
        val decoded = readBack?.takeIf { it.contentEquals(bytes) }?.let { decode(it) }
        val opened = decoded?.let { PasscodeLayer.open(passcode, it.first, PasscodeLayer.aadForAccountKey(eoa), it.second) }
        if (opened == null || !opened.contentEquals(inner)) {
            bestEffortDelete(fresh)
            return Write.READBACK_MISMATCH
        }
        return try {
            files.write(nameOf(eoa), bytes)
            bestEffortDelete(fresh)
            Write.OK
        } catch (_: IOException) {
            Write.WRITE_FAILED
        }
    }

    /** Opens the stored account key with [passcode]. Null when the record is absent, invalid, or the passcode does not open it. */
    fun unlock(eoa: String, passcode: String): ByteArray? {
        val record = read(eoa) as? Read.Record ?: return null
        return PasscodeLayer.open(passcode, record.salt, PasscodeLayer.aadForAccountKey(eoa), record.blob)
    }

    private fun nameOf(eoa: String): String = eoa.lowercase()

    private fun bestEffortDelete(name: String) {
        try { files.delete(name) } catch (_: IOException) { /* a leftover fresh file is never read as a record */ }
    }

    private fun encode(salt: ByteArray, blob: ByteArray): ByteArray =
        "passcode-record v1\nsalt=${ConetChatCryptoUtil.toHex(salt)}\nblob=${ConetChatCryptoUtil.toHex(blob)}\n".toByteArray(Charsets.UTF_8)

    private fun decode(bytes: ByteArray): Pair<ByteArray, ByteArray>? {
        val lines = String(bytes, Charsets.UTF_8).split('\n')
        if (lines.size < 3 || lines[0] != "passcode-record v1") return null
        val salt = lines[1].takeIf { it.startsWith("salt=") }?.removePrefix("salt=")?.let { ConetChatCryptoUtil.hexToBytes(it) } ?: return null
        val blob = lines[2].takeIf { it.startsWith("blob=") }?.removePrefix("blob=")?.let { ConetChatCryptoUtil.hexToBytes(it) } ?: return null
        if (salt.size != PasscodeLayer.SALT_BYTES) return null
        return salt to blob
    }

    companion object {
        const val NEW_SUFFIX = ".new"

        /** The directory of the native passcode records (protocol section 8). Never backed up; excluded from account cleanup (AccountCleanupWiring). */
        const val DIRECTORY = "native_passcode_v1"

        fun directoryUnder(noBackupDir: java.io.File): java.io.File = java.io.File(noBackupDir, DIRECTORY)
    }
}
