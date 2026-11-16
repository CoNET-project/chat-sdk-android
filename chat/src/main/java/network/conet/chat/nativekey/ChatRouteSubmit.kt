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

        /** 25.52Y.64 第 3 项: a success answer the chain does not show as registered. Not submitted; the page must not show success. */
        object UnverifiedSubmit : Outcome()
    }

    /** One POST attempt. [Transport.Unreachable] means no answer (connect, TLS or timeout); any HTTP answer is [Transport.Answer]. */
    sealed class Transport {
        class Answer(val status: Int, val body: String) : Transport()
        object Unreachable : Transport()

        /** The request may have reached the server (sent, then no answer or a read timeout). The chain decides, never a blind resend. */
        object Ambiguous : Transport()
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

    /**
     * The on-chain check of the registration (read only): `true` when the PGP directory holds the expected keyId, `false` when it does not,
     * `null` when the read failed (that is not "not registered").
     */
    internal fun interface ChainCheck {
        fun registered(): Boolean?
    }

    /** Retries after a 5xx or timeout whose chain check is not registered: once (25.52Y.64, IP-05, IP-06). Each retry is re-signed. */
    const val MAX_RETRIES = 1

    /**
     * Tries [bases] in order (IP first, then domain). [bodyFor] gives the body for an attempt (attempt 0 is the first; a retry is re-signed with a new
     * nonce by the caller, or returns null when signing fails).
     *
     * - 2xx with ok:true over the IP base is not trusted by itself: the chain must show the keyId ([chain] true) or the result is network_unavailable.
     * - 2xx over the domain base is Submitted.
     * - 5xx: the chain is read first. Registered → Submitted. Unreadable → network_unavailable. Not registered → re-sign and retry, at most
     *   [MAX_RETRIES] time with [backoffMs] between them (25.52Y.64); after that network_unavailable (retryable). A blind resend of the same signature is never made.
     * - Other non-2xx: chain_refused. Transport failure moves to the next base.
     * - No base answers: network_unavailable.
     */
    fun submit(
        bases: List<String>,
        bodyFor: (attempt: Int) -> String?,
        poster: Poster,
        chain: ChainCheck,
        timeoutMs: Int = 12_000,
        backoffMs: (retry: Int) -> Long = { 1_000L shl it },
        // Production callers run this on the module's io executor, never on the command or main thread (the default sleeps).
        pause: (Long) -> Unit = { Thread.sleep(it) },
    ): Outcome {
        var attempt = 0
        for (base in bases) {
            var retries = 0
            while (true) {
                val body = bodyFor(attempt) ?: return Outcome.Refused("sign_failed")
                attempt++
                val t = poster.post(base.trimEnd('/') + PATH, body, timeoutMs)
                // Retry path shared by 5xx and an ambiguous timeout (25.52Y.64): the chain decides first, a resend happens only when unregistered.
                val retryable: Boolean
                when (t) {
                    is Transport.Unreachable -> break
                    is Transport.Answer -> {
                        if (t.status in 200..299) {
                            if (!runCatching { JSONObject(t.body).optBoolean("ok", false) }.getOrDefault(false)) return Outcome.Refused("chain_refused")
                            // A success is never submitted on the answer alone (25.52Y.67 第 2 项), on either base. IP-01..03 for the IP base.
                            return when (chain.registered()) {
                                true -> Outcome.Submitted
                                false -> Outcome.UnverifiedSubmit
                                null -> Outcome.NetworkUnavailable
                            }
                        }
                        if (t.status !in 500..599) return Outcome.Refused("chain_refused")
                        retryable = true
                    }
                    is Transport.Ambiguous -> retryable = true
                }
                if (retryable) {
                    when (chain.registered()) {
                        true -> return Outcome.Submitted // IP-04
                        null -> return Outcome.NetworkUnavailable // IP-07
                        false -> Unit
                    }
                    if (retries >= MAX_RETRIES) return Outcome.NetworkUnavailable // IP-06
                    pause(backoffMs(retries))
                    retries++
                    continue
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
            var sent = false
            return try {
                OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(json) }
                sent = true
                val status = conn.responseCode
                val stream = if (status in 200..299) conn.inputStream else conn.errorStream
                val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
                Transport.Answer(status, text)
            } catch (_: Exception) {
                // Before the body is sent the server cannot have the request; after it, the outcome is unknown.
                if (sent) Transport.Ambiguous else Transport.Unreachable
            } finally {
                conn.disconnect()
            }
        }
    }
}
