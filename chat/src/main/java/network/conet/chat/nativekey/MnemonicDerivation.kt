package network.conet.chat.nativekey

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import java.math.BigInteger
import java.security.MessageDigest
import java.text.Normalizer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * BIP-39 phrase to the account-0 private key (spec §25.26.1 and §25.26.3, P-MNEMONIC).
 *
 * Rules, in order: remove leading and trailing ASCII whitespace (the one deliberate relaxation, §25.26.1);
 * lowercase; split on JavaScript `\s` (Unicode whitespace, so NBSP and the ideographic space split too); NFKD each
 * word; the word count is 12, 15, 18, 21 or 24; every word is in the English list; the checksum holds. No passphrase.
 * Path m/44'/60'/0'/0/0 (BIP-32). Only the 32-byte key is returned. The caller zeroes it. The phrase is never stored.
 *
 * Intermediate byte arrays are zeroed before return. JVM `String`s cannot be zeroed; the phrase text is held only
 * as long as the caller holds the input string (see the receipt for this limit).
 */
internal object MnemonicDerivation {
    private val CURVE = SECNamedCurves.getByName("secp256k1")
    private val N: BigInteger = CURVE.n
    private const val HARDENED = 0x80000000L
    private const val PBKDF2_ROUNDS = 2048

    /** m/44'/60'/0'/0/0 */
    private val PATH = longArrayOf(44L or HARDENED, 60L or HARDENED, HARDENED, 0L, 0L)
    private val COUNTS = setOf(12, 15, 18, 21, 24)
    private val ASCII_WS = charArrayOf(' ', '\t', '\n', '\r', '\u000B', '\u000C')

    /** JavaScript `\s`: the characters that split a phrase. */
    private val JS_WS: Set<Char> = buildSet {
        addAll(
            listOf(
                '\t', '\n', '\u000B', '\u000C', '\r', ' ', ' ', ' ',
                ' ', ' ', ' ', ' ', '　', '﻿',
            ),
        )
        for (c in ' '..' ') add(c)
    }

    /**
     * @return the 32-byte account-0 key, or null when the phrase is invalid. The caller zeroes the result.
     */
    fun deriveKey(raw: String): ByteArray? {
        val text = raw.trim { it in ASCII_WS }.lowercase()
        val words = words(text) ?: return null
        val idx = IntArray(words.size)
        for (i in words.indices) idx[i] = Bip39English.INDEX[words[i]] ?: return null
        if (!checksumOk(idx)) return null
        val password = words.joinToString(" ").toByteArray(Charsets.UTF_8)
        val seed = try {
            seedOf(password)
        } finally {
            password.fill(0)
        }
        return try {
            pathKey(seed)
        } finally {
            seed.fill(0)
        }
    }

    /**
     * The phrase in the form the vault stores (spec §25.52Y.42): the same word rule as [deriveKey] (trim, lower-case, NFKD per word,
     * single spaces). Null when the word count is not valid. The phrase is not checked against the checksum here; [deriveKey] does that.
     */
    fun canonicalPhrase(raw: String): String? {
        val text = raw.trim { it in ASCII_WS }.lowercase()
        val words = words(text) ?: return null
        return words.joinToString(" ")
    }

    /** Splits on JS whitespace, NFKD-normalises each word, and checks the word count. */
    private fun words(text: String): List<String>? {
        val out = ArrayList<String>()
        val cur = StringBuilder()
        for (ch in text) {
            if (ch in JS_WS) {
                if (cur.isNotEmpty()) {
                    out.add(Normalizer.normalize(cur, Normalizer.Form.NFKD))
                    cur.setLength(0)
                }
            } else {
                cur.append(ch)
            }
        }
        if (cur.isNotEmpty()) out.add(Normalizer.normalize(cur, Normalizer.Form.NFKD))
        return if (out.size in COUNTS) out else null
    }

    /** BIP-39 checksum: the first n/3 bits of SHA-256(entropy) must equal the trailing bits of the phrase. */
    private fun checksumOk(idx: IntArray): Boolean {
        val n = idx.size
        val total = n * 11
        val csBits = n / 3
        val entBits = total - csBits
        val bits = ByteArray((total + 7) / 8)
        try {
            for (i in idx.indices) {
                for (b in 0 until 11) {
                    // Parenthesised on purpose: infix `and` binds looser than `==` in Kotlin.
                    if (((idx[i] shr (10 - b)) and 1) == 1) {
                        val pos = i * 11 + b
                        bits[pos / 8] = (bits[pos / 8].toInt() or (0x80 ushr (pos % 8))).toByte()
                    }
                }
            }
            val ent = bits.copyOfRange(0, entBits / 8)
            val hash = MessageDigest.getInstance("SHA-256").digest(ent)
            ent.fill(0)
            var ok = true
            for (j in 0 until csBits) {
                val pos = entBits + j
                val got = (bits[pos / 8].toInt() shr (7 - pos % 8)) and 1
                val want = (hash[0].toInt() shr (7 - j)) and 1
                if (got != want) ok = false
            }
            return ok
        } finally {
            bits.fill(0)
        }
    }

    /** PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic" with an empty passphrase, 64 bytes. */
    private fun seedOf(password: ByteArray): ByteArray {
        val salt = "mnemonic".toByteArray(Charsets.UTF_8)
        try {
            val gen = PKCS5S2ParametersGenerator(SHA512Digest())
            gen.init(password, salt, PBKDF2_ROUNDS)
            return (gen.generateDerivedParameters(512) as KeyParameter).key
        } finally {
            salt.fill(0)
        }
    }

    /** BIP-32 private derivation along [PATH] from the master node of [seed]. */
    private fun pathKey(seed: ByteArray): ByteArray? {
        val master = hmac512("Bitcoin seed".toByteArray(Charsets.UTF_8), seed)
        var k = master.copyOfRange(0, 32)
        var c = master.copyOfRange(32, 64)
        master.fill(0)
        try {
            val first = BigInteger(1, k)
            if (first.signum() <= 0 || first >= N) {
                k.fill(0)
                return null
            }
            for (index in PATH) {
                val ser = byteArrayOf(
                    (index shr 24).toByte(),
                    (index shr 16).toByte(),
                    (index shr 8).toByte(),
                    index.toByte(),
                )
                val data = if (index >= HARDENED) {
                    byteArrayOf(0) + k + ser
                } else {
                    publicKeyCompressed(k) + ser
                }
                val out = try {
                    hmac512(c, data)
                } finally {
                    data.fill(0)
                }
                val il = BigInteger(1, out.copyOfRange(0, 32))
                val child = il.add(BigInteger(1, k)).mod(N)
                val nextC = out.copyOfRange(32, 64)
                out.fill(0)
                if (il >= N || child.signum() == 0) {
                    k.fill(0)
                    return null
                }
                k.fill(0)
                k = fixed32(child)
                c.fill(0)
                c = nextC
            }
            return k
        } finally {
            c.fill(0)
        }
    }

    private fun publicKeyCompressed(k: ByteArray): ByteArray =
        CURVE.g.multiply(BigInteger(1, k)).normalize().getEncoded(true)

    private fun hmac512(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(key, "HmacSHA512"))
        return mac.doFinal(data)
    }

    private fun fixed32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        val n = minOf(raw.size, 32)
        System.arraycopy(raw, raw.size - n, out, 32 - n, n)
        return out
    }
}
