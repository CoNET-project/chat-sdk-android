package network.conet.chat.nativekey

import java.math.BigDecimal
import java.math.BigInteger

/**
 * One reading of an integer field that crosses the bridge (integers are judged by value, not by the carrier's type).
 * A JavaScript number reaches a native layer as whatever type the platform's JSON parser makes of it (iOS: always a double), so a field is an integer
 * when its VALUE is one: not a boolean, finite, no fractional part, and within `0..2^53−1`, the largest integer a JavaScript number holds exactly.
 * `5.0` is accepted as 5; `2.5`, `-1`, `2^53`, `NaN`, a string, a boolean, `null` and any non-number are not.
 */
internal object BridgeInteger {
    /** 2^53 − 1. */
    const val MAX_SAFE: Long = 9_007_199_254_740_991L

    /** The value, or null when [value] is not a non-negative safe integer. */
    fun nonNegativeSafe(value: Any?): Long? = when (value) {
        null, is Boolean -> null
        is Byte, is Short, is Int, is Long -> (value as Number).toLong().takeIf { it in 0..MAX_SAFE }
        is Double, is Float -> {
            val d = (value as Number).toDouble()
            if (d.isNaN() || d.isInfinite() || d != Math.floor(d) || d < 0.0 || d > MAX_SAFE.toDouble()) null else d.toLong()
        }
        is BigInteger -> value.takeIf { it.signum() >= 0 && it <= BigInteger.valueOf(MAX_SAFE) }?.toLong()
        is BigDecimal -> runCatching { value.toBigIntegerExact() }.getOrNull()?.let { nonNegativeSafe(it) }
        else -> null
    }
}
