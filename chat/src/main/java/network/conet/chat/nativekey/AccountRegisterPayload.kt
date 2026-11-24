package network.conet.chat.nativekey

import network.conet.chat.ConetChatCryptoUtil
import java.security.SecureRandom
import java.util.Base64

/**
 * The BeamioTag and recover registration payload of a new account. The page collects the BeamioTag and the user's password and asks the native
 * layer; the native layer signs with the account key and seals the recover records itself, in the same format the PWA's `createRecover` writes, and the
 * page forwards the result to `/api/addUser`. The phrase, the password, the account key and the plain recover code never leave this object except the
 * recover code the user must be shown once (the answer's `recoverCode`); nothing here logs any of them.
 *
 *  - `signMessage` is the EIP-191 signature of the wallet address string exactly as it is returned (lower case): the server's
 *    `checkSign(wallet, signMessage, wallet)` verifies the signature over the `wallet` string as sent, and the page forwards it unchanged.
 *  - `recover` holds two records: the recover code's (hash = keccak256 of the code) and the password's (hash = keccak256 of the BeamioTag), each
 *    `base64({stored, img})`; `stored` carries one Argon2id salt and the password's hash, and `img` is the phrase sealed under the record's own secret.
 *  - the recover code is 22 base58 characters: a form the existing native restore accepts (22 alphanumeric characters) and base58 can be read aloud.
 */
internal object AccountRegisterPayload {
    private val NAME_RE = Regex("^[a-zA-Z0-9_.]{3,26}$")
    private const val BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    const val CODE_LENGTH = 22
    private const val MAX_PASSWORD_BYTES = 1024

    class RecoverItem(val hash: String, val encrypto: String)

    sealed class Built {
        class Ok(
            val accountName: String,
            val wallet: String,
            val signMessage: String,
            val recover: List<RecoverItem>,
            val recoverCode: String,
        ) : Built()

        class Refused(val code: String) : Built()
    }

    /** The BeamioTag as the server takes it: trimmed, a leading `@` dropped; null when it is not 3 to 26 of `[a-zA-Z0-9_.]`. */
    fun normalizeName(raw: String): String? = raw.trim().removePrefix("@").takeIf { NAME_RE.matches(it) }

    /** EIP-55 checksum form of [address] (any case, `0x` and 40 hex digits). */
    fun checksum(address: String): String {
        val lower = address.lowercase().removePrefix("0x")
        val hash = ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256(lower.toByteArray(Charsets.US_ASCII)))
        val sb = StringBuilder("0x")
        for (i in lower.indices) sb.append(if (lower[i] in 'a'..'f' && hash[i] >= '8') lower[i].uppercaseChar() else lower[i])
        return sb.toString()
    }

    /** 22 uniformly random base58 characters (rejection sampling, no bias). */
    fun newRecoverCode(random: SecureRandom): String {
        val out = StringBuilder()
        val buf = ByteArray(1)
        while (out.length < CODE_LENGTH) {
            random.nextBytes(buf)
            val v = buf[0].toInt() and 0xFF
            if (v < 232) out.append(BASE58[v % 58]) // 232 = 58 * 4: no modulo bias
        }
        return out.toString()
    }

    private fun keccakOf(text: String): String =
        "0x" + ConetChatCryptoUtil.toHex(ConetChatCryptoUtil.keccak256(text.toByteArray(Charsets.UTF_8)))

    /**
     * Builds the payload. [password] and [phrase] are UTF-8 bytes; the caller zeroes them. The phrase must derive [eoaKey] (else `phrase_mismatch`).
     * [kdf] is a seam only so tests can use cheap parameters; production uses Argon2id with the PWA's parameters.
     */
    fun build(
        accountName: String,
        password: ByteArray,
        eoa: String,
        eoaKey: ByteArray,
        phrase: ByteArray,
        random: SecureRandom = SecureRandom(),
        kdf: (ByteArray, RecoveryRecord.Stored) -> ByteArray = { p, st -> RecoveryRecord.argon2idKey(p, st) },
    ): Built {
        val name = normalizeName(accountName) ?: return Built.Refused("bad_request")
        if (password.isEmpty() || password.size > MAX_PASSWORD_BYTES) return Built.Refused("bad_request")
        val phraseText = String(phrase, Charsets.UTF_8)
        val derived = MnemonicDerivation.deriveKey(phraseText) ?: return Built.Refused("phrase_mismatch")
        try {
            if (!derived.contentEquals(eoaKey)) return Built.Refused("phrase_mismatch")
        } finally {
            derived.fill(0)
        }
        val wallet = eoa.lowercase()
        val signMessage = Eip191Signer.sign(eoaKey, wallet.toByteArray(Charsets.UTF_8)) ?: return Built.Refused("sign_failed")
        val code = newRecoverCode(random)
        val codeBytes = code.toByteArray(Charsets.US_ASCII)
        val (stored, passwordKey) = RecoveryRecord.newStored(password, random, kdf)
        var codeKey: ByteArray? = null
        try {
            codeKey = kdf(codeBytes, stored)
            fun iv() = ByteArray(12).also { random.nextBytes(it) }
            val imgCode = RecoveryRecord.seal(codeKey, phrase, iv())
            val imgPassword = RecoveryRecord.seal(passwordKey, phrase, iv())
            val recover = listOf(
                RecoverItem(keccakOf(code), RecoveryRecord.record(stored, passwordKey, imgCode)),
                RecoverItem(keccakOf(name), RecoveryRecord.record(stored, passwordKey, imgPassword)),
            )
            return Built.Ok(name, wallet, signMessage, recover, code)
        } finally {
            codeKey?.fill(0)
            passwordKey.fill(0)
            codeBytes.fill(0)
        }
    }

    /** What the registry says about a BeamioTag before anything is signed. */
    sealed class Registry {
        /** The tag is free: build the payload. */
        object Free : Registry()

        /** The same account already owns the tag: nothing is submitted again (code already_registered). */
        object AlreadyRegistered : Registry()

        /** The tag belongs to another account. */
        object Taken : Registry()

        /** The registry cannot answer at one block (never "free"). */
        object Unreadable : Registry()
    }

    /**
     * The decision from the same-block read of the tag's owner ([owner]: lower-case address, or null for none; a failed read throws). The tag already owned by this account is `AlreadyRegistered` whether or not its recover record exists (the page then calls no addUser);
     * another account's tag is `Taken`; a failed read is `Unreadable`, never free.
     */
    fun decide(eoa: String, read: () -> String?): Registry {
        val owner = try { read() } catch (_: Exception) { return Registry.Unreadable }
        return when {
            owner == null -> Registry.Free
            owner.equals(eoa, ignoreCase = true) -> Registry.AlreadyRegistered
            else -> Registry.Taken
        }
    }
}
