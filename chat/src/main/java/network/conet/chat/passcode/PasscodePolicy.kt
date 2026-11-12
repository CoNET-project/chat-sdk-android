package network.conet.chat.passcode

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Passcode rules, KDF and cooldown (spec r3b 25.17.6, 25.17.7, 25.17.10). The numbers and the rule
 * order come from `spec/passcode-vectors.v1.json` (sha256 7993ad85…); the test checks every value
 * against that file. Native code never returns a passcode, a derived value or a salt over the bridge.
 */
object PasscodePolicy {
    const val MIN_DIGITS = 8
    const val MAX_DIGITS = 12

    /** The 10 common passcodes (vector `policy.common`). */
    val COMMON: Set<String> = setOf(
        "00000000", "11111111", "12345678", "87654321", "12341234",
        "12121212", "20202020", "10101010", "13131313", "11223344",
    )

    /** Reason codes, in the order the rules are checked (vector `policy.reasonCodes`). */
    enum class Reason(val code: String) {
        NON_DIGIT("non_digit"),
        TOO_SHORT("too_short"),
        TOO_LONG("too_long"),
        ALL_SAME("all_same"),
        REPEAT_PAIR("repeat_pair"),
        COMMON("common"),
        BIRTHDAY("birthday"),
        SEQUENCE("sequence"),
    }

    /** `null` when the passcode is accepted; otherwise the first rule it breaks. */
    fun reject(passcode: String): Reason? {
        if (passcode.any { it !in '0'..'9' }) return Reason.NON_DIGIT
        if (passcode.length < MIN_DIGITS) return Reason.TOO_SHORT
        if (passcode.length > MAX_DIGITS) return Reason.TOO_LONG
        if (passcode.all { it == passcode[0] }) return Reason.ALL_SAME
        // A two-digit cycle over the whole string, e.g. 12121212 (also 121212121).
        if (passcode.indices.all { passcode[it] == passcode[it % 2] }) return Reason.REPEAT_PAIR
        if (passcode in COMMON) return Reason.COMMON
        if (isBirthday(passcode)) return Reason.BIRTHDAY
        if (hasSixStep(passcode)) return Reason.SEQUENCE
        return null
    }

    /** 8 digits that read as a valid 1900–2099 date in YYYYMMDD, MMDDYYYY or DDMMYYYY. */
    private fun isBirthday(p: String): Boolean {
        if (p.length != 8) return false
        val n = { from: Int, to: Int -> p.substring(from, to).toInt() }
        return validDate(n(0, 4), n(4, 6), n(6, 8)) ||   // YYYYMMDD
            validDate(n(4, 8), n(0, 2), n(2, 4)) ||      // MMDDYYYY (year, month, day)
            validDate(n(4, 8), n(2, 4), n(0, 2))         // DDMMYYYY (year, month, day)
    }

    private fun validDate(year: Int, month: Int, day: Int): Boolean {
        if (year !in 1900..2099 || month !in 1..12 || day < 1) return false
        val days = when (month) {
            1, 3, 5, 7, 8, 10, 12 -> 31
            4, 6, 9, 11 -> 30
            else -> if ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) 29 else 28
        }
        return day <= days
    }

    /** Six consecutive digits, each one higher (or each one lower) than the one before. */
    private fun hasSixStep(p: String): Boolean {
        for (i in 0..p.length - 6) {
            val up = (1 until 6).all { p[i + it] - p[i + it - 1] == 1 }
            val down = (1 until 6).all { p[i + it - 1] - p[i + it] == 1 }
            if (up || down) return true
        }
        return false
    }
}

/** Wrapping KDF for the passcode layer: PBKDF2-HMAC-SHA256, 600000 iterations, 32-byte output (vector `kdf`). */
object PasscodeKdf {
    const val ITERATIONS = 600_000
    const val KEY_BITS = 256

    /** Derives the key. The caller zeroes [salt] and the returned key when done. */
    fun derive(passcode: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(passcode.toCharArray(), salt, ITERATIONS, KEY_BITS)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}

/** Cooldown after consecutive wrong passcodes (vector `backoff.schedule`): the last row not above the count applies. */
object PasscodeBackoff {
    private val SCHEDULE: List<Pair<Int, Int>> = listOf(
        0 to 0, 1 to 0, 2 to 0, 3 to 0, 4 to 0,
        5 to 30, 6 to 60, 7 to 300, 8 to 900, 9 to 3600, 12 to 3600,
    )

    fun cooldownSec(consecutiveFailures: Int): Int =
        SCHEDULE.last { it.first <= consecutiveFailures }.second

    /** The rows as written in the vector, for the test. */
    fun schedule(): List<Pair<Int, Int>> = SCHEDULE
}
