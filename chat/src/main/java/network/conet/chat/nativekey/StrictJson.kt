package network.conet.chat.nativekey

import java.math.BigDecimal

/**
 * Minimal JSON reader for the gossip shape check. It follows RFC 8259 and reports duplicate keys in the
 * top-level object, which `org.json` would silently overwrite. Nested objects allow duplicate keys (last one
 * wins), which matches the reference generator (`gen-gossip-sign-vectors.mjs`).
 *
 * Values: `Map<String, Any?>` (objects), `List<Any?>` (arrays), `String`, [Num] (numbers, kept exact),
 * `Boolean`, and [Null].
 */
internal object StrictJson {
    class Invalid : Exception("invalid json")
    class DuplicateKey : Exception("duplicate key")

    class Num(val value: BigDecimal)

    object Null

    /** Parses one JSON value. [rejectTopLevelDuplicates] throws [DuplicateKey] for a repeated top-level key. */
    fun parse(text: String, rejectTopLevelDuplicates: Boolean): Any? {
        val p = Reader(text, rejectTopLevelDuplicates)
        p.skipWs()
        val v = p.value(depth = 0, top = true)
        p.skipWs()
        if (p.pos != text.length) throw Invalid()
        return v
    }

    private class Reader(private val s: String, private val rejectTop: Boolean) {
        var pos = 0

        fun skipWs() {
            while (pos < s.length && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) pos++
        }

        private fun peek(): Char = if (pos < s.length) s[pos] else throw Invalid()

        private fun expect(c: Char) {
            if (peek() != c) throw Invalid()
            pos++
        }

        fun value(depth: Int, top: Boolean = false): Any? {
            if (depth > 64) throw Invalid()
            return when (peek()) {
                '{' -> obj(depth, top)
                '[' -> arr(depth)
                '"' -> str()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", Null)
                else -> num()
            }
        }

        private fun literal(word: String, v: Any): Any {
            if (!s.startsWith(word, pos)) throw Invalid()
            pos += word.length
            return v
        }

        private fun obj(depth: Int, top: Boolean): Map<String, Any?> {
            expect('{')
            val out = LinkedHashMap<String, Any?>()
            skipWs()
            if (peek() == '}') {
                pos++
                return out
            }
            while (true) {
                skipWs()
                val key = str()
                if (top && rejectTop && out.containsKey(key)) throw DuplicateKey()
                skipWs()
                expect(':')
                skipWs()
                out[key] = value(depth + 1)
                skipWs()
                when (peek()) {
                    ',' -> pos++
                    '}' -> {
                        pos++
                        return out
                    }
                    else -> throw Invalid()
                }
            }
        }

        private fun arr(depth: Int): List<Any?> {
            expect('[')
            val out = ArrayList<Any?>()
            skipWs()
            if (peek() == ']') {
                pos++
                return out
            }
            while (true) {
                skipWs()
                out.add(value(depth + 1))
                skipWs()
                when (peek()) {
                    ',' -> pos++
                    ']' -> {
                        pos++
                        return out
                    }
                    else -> throw Invalid()
                }
            }
        }

        private fun str(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                val c = peek()
                pos++
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        when (peek()) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 5 > s.length) throw Invalid()
                                val hex = s.substring(pos + 1, pos + 5)
                                if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) throw Invalid()
                                sb.append(hex.toInt(16).toChar())
                                pos += 4
                            }
                            else -> throw Invalid()
                        }
                        pos++
                    }
                    c < ' ' -> throw Invalid()
                    else -> sb.append(c)
                }
            }
        }

        private fun num(): Num {
            val start = pos
            if (peek() == '-') pos++
            if (peek() == '0') {
                pos++
            } else if (peek() in '1'..'9') {
                while (pos < s.length && s[pos] in '0'..'9') pos++
            } else {
                throw Invalid()
            }
            if (pos < s.length && s[pos] == '.') {
                pos++
                if (pos >= s.length || s[pos] !in '0'..'9') throw Invalid()
                while (pos < s.length && s[pos] in '0'..'9') pos++
            }
            if (pos < s.length && (s[pos] == 'e' || s[pos] == 'E')) {
                pos++
                if (pos < s.length && (s[pos] == '+' || s[pos] == '-')) pos++
                if (pos >= s.length || s[pos] !in '0'..'9') throw Invalid()
                while (pos < s.length && s[pos] in '0'..'9') pos++
            }
            return try {
                Num(BigDecimal(s.substring(start, pos)))
            } catch (e: NumberFormatException) {
                throw Invalid()
            }
        }
    }
}
