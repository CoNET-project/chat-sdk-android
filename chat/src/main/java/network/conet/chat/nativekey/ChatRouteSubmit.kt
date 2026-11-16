package network.conet.chat.nativekey

import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * The shell's submission of the chat route registration (25.52Y.61 第 4 项). The registration is sent by the native layer, never by the page:
 * the request goes to the IP address first (HTTP POST), then to the domain (HTTPS POST). It is not a WebSocket of any kind.
 *
 * A reachable server that answers is final: a 2xx with `ok: true` is [Outcome.Submitted]; anything else is [Outcome.Refused] with the code
 * `chain_refused`. Only a transport failure (no answer) moves on to the next endpoint. When no endpoint answers, the result is
 * [Outcome.NetworkUnavailable]. The body (armor, backup, signature) is never logged and never returned to the caller.
 *
 * Not wired to the `chatRouteRegister` command yet: the page still takes the four-field answer until the PWA's submitted branch ships (25.52Y.61
 * 第 3 项, the enabling condition).
 */
internal object ChatRouteSubmit {
    const val PATH = "/api/regiestChatRoute"

    /** The fixed key order of the request body (25.52Y.61 第 6 项). */
    private val FIELDS = listOf("wallet", "keyID", "publicKeyArmored", "encrypKeyArmored", "routeKeyID", "timestamp", "nonce", "signature")

    sealed class Outcome {
        object Submitted : Outcome()
        class Refused(val code: String) : Outcome()
        object NetworkUnavailable : Outcome()
    }

    /** One POST attempt. [Transport.Unreachable] means no answer (connect, TLS or timeout); any HTTP answer is [Transport.Answer]. */
    sealed class Transport {
        class Answer(val status: Int, val body: String) : Transport()
        object Unreachable : Transport()
    }

    internal fun interface Poster {
        fun post(url: String, json: String, timeoutMs: Int): Transport
    }

    /** The request body as text, keys in the fixed order. [fields] must hold every key; a missing one is a bug, so it throws. */
    fun bodyJson(fields: Map<String, String>): String {
        val parts = FIELDS.map { k ->
            val v = requireNotNull(fields[k]) { "missing field $k" }
            "${JSONObject.quote(k)}:${JSONObject.quote(v)}"
        }
        return "{" + parts.joinToString(",") + "}"
    }

    /** Tries [bases] in order (IP first, then domain). Each base is an origin such as `https://beamio.ca`; [PATH] is appended. */
    fun submit(bases: List<String>, json: String, poster: Poster, timeoutMs: Int = 12_000): Outcome {
        for (base in bases) {
            when (val t = poster.post(base.trimEnd('/') + PATH, json, timeoutMs)) {
                is Transport.Unreachable -> continue
                is Transport.Answer -> {
                    val ok = t.status in 200..299 && runCatching { JSONObject(t.body).optBoolean("ok", false) }.getOrDefault(false)
                    return if (ok) Outcome.Submitted else Outcome.Refused("chain_refused")
                }
            }
        }
        return Outcome.NetworkUnavailable
    }

    /** The production poster: HttpURLConnection, JSON in and out. Used only by the submission path, never for another request. */
    internal object HttpPoster : Poster {
        override fun post(url: String, json: String, timeoutMs: Int): Transport {
            val conn = try {
                (URL(url).openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = timeoutMs
                    readTimeout = timeoutMs
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                }
            } catch (_: Exception) {
                return Transport.Unreachable
            }
            return try {
                OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(json) }
                val status = conn.responseCode
                val stream = if (status in 200..299) conn.inputStream else conn.errorStream
                val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
                Transport.Answer(status, text)
            } catch (_: Exception) {
                Transport.Unreachable
            } finally {
                conn.disconnect()
            }
        }
    }
}
