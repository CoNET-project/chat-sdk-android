package network.conet.chat

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import android.os.Build
import android.webkit.JavascriptInterface
import android.webkit.RenderProcessGoneDetail
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.annotation.RequiresApi
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Ephemeral WebView host that loads bundled `ChatCrypto/openpgp.min.js` +
 * `ethers.umd.min.js` (shipped inside this AAR) for OpenPGP encrypt / decrypt and
 * EIP-191 verify without a live PWA. EIP-191 *signing* never happens here: the EOA key
 * stays in the PWA (see [BeamioConetChatSignBroker]).
 */
class BeamioOpenPgpHost private constructor(private val appContext: Context) {
    companion object {
        private const val TAG = "BeamioOpenPgp"
        @Volatile private var instance: BeamioOpenPgpHost? = null

        /**
         * OpenPGP.js 6 may return armor as string, thenable, or ReadableStream of strings.
         * Same semantics as SilentPassUI `vendor/beamio-chat-sdk` `armorToString`.
         */
        private const val JS_ARMOR_TO_STRING = """
              async function armorToString(encrypted) {
                if (encrypted == null) return '';
                if (typeof encrypted === 'string') return encrypted;
                if (typeof encrypted.then === 'function') {
                  return armorToString(await encrypted);
                }
                if (typeof encrypted.getReader === 'function') {
                  const reader = encrypted.getReader();
                  const chunks = [];
                  while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    if (typeof value === 'string') chunks.push(value);
                    else if (value != null) chunks.push(String(value));
                  }
                  return chunks.join('');
                }
                if (typeof encrypted[Symbol.asyncIterator] === 'function') {
                  const chunks = [];
                  for await (const chunk of encrypted) {
                    if (typeof chunk === 'string') chunks.push(chunk);
                    else if (chunk != null) chunks.push(String(chunk));
                  }
                  return chunks.join('');
                }
                return String(encrypted);
              }
        """

        fun shared(context: Context): BeamioOpenPgpHost {
            return instance ?: synchronized(this) {
                instance ?: BeamioOpenPgpHost(context.applicationContext).also { instance = it }
            }
        }
    }

    private data class JsJsonResult(
        val ok: Boolean,
        val armor: String = "",
        val text: String = "",
        val armorHash: String = "",
        val error: String = "",
        val value: String = "",
    )

    private fun parseJsJsonResult(raw: String?): JsJsonResult? {
        val out = unwrapJsString(raw)
        if (out.isBlank()) return null
        return try {
            val obj = JSONObject(out)
            JsJsonResult(
                ok = obj.optBoolean("ok", false),
                armor = obj.optString("armor", ""),
                text = obj.optString("text", ""),
                armorHash = obj.optString("armorHash", ""),
                error = obj.optString("error", ""),
                value = obj.optString("value", ""),
            )
        } catch (_: Exception) {
            // Legacy plain armor / ERROR: prefix
            if (out.startsWith("ERROR:")) {
                JsJsonResult(ok = false, error = out.removePrefix("ERROR:"))
            } else if (out.contains("BEGIN PGP MESSAGE")) {
                JsJsonResult(ok = true, armor = out)
            } else {
                JsJsonResult(ok = false, error = "unparseable_js_result")
            }
        }
    }

    private val main = Handler(Looper.getMainLooper())
    private var webView: WebView? = null
    private val ready = AtomicBoolean(false)
    private val bootstrapped = AtomicBoolean(false)
    private val pendingReady = ConcurrentLinkedQueue<(Boolean) -> Unit>()
    /** Primary delivery for async IIFE results (evaluateJavascript Promise return is flaky). */
    private val pendingJsResults = ConcurrentHashMap<String, (JsJsonResult) -> Unit>()
    private val jsRequestSeq = AtomicLong(0)
    /**
     * decrypt_inbound timing, diagnostics only: [start, main-thread dispatch, JS
     * result at the bridge] in elapsedRealtime ms. Tells a busy main thread from
     * slow JS. Durations only; no content or keys.
     */
    private val decryptTiming = ConcurrentHashMap<String, LongArray>()

    private fun nextJsRequestId(): String = "pgp_${jsRequestSeq.incrementAndGet()}"

    private fun logDecryptTiming(requestId: String) {
        val t = decryptTiming.remove(requestId) ?: return
        val now = SystemClock.elapsedRealtime()
        val dispatched = if (t[1] > 0L) t[1] else now
        val bridged = if (t[2] > 0L) t[2] else now
        Log.i(
            TAG,
            "decrypt_inbound: timing id=$requestId mainQueueMs=${dispatched - t[0]} jsMs=${bridged - dispatched} " +
                "deliverMs=${now - bridged} totalMs=${now - t[0]}",
        )
    }

    private fun registerJsResult(requestId: String, onResult: (JsJsonResult) -> Unit) {
        pendingJsResults[requestId] = onResult
        main.postDelayed({
            val stale = pendingJsResults.remove(requestId) ?: return@postDelayed
            Log.e(TAG, "js_bridge_timeout id=$requestId")
            // No answer in 25 s: the page is wedged or gone. Rebuild it for the next call.
            resetHost("js bridge timeout")
            stale(JsJsonResult(ok = false, error = "js_bridge_timeout"))
        }, 25_000L)
    }

    private fun deliverJsResult(requestId: String, parsed: JsJsonResult) {
        val cb = pendingJsResults.remove(requestId) ?: return
        try {
            cb(parsed)
        } catch (_: Exception) {
        }
    }

    fun encryptToRoute(
        routePublicArmor: String,
        plaintextJson: String,
        callback: (Result<String>) -> Unit,
    ) {
        ensureReady { ok ->
            if (!ok) {
                callback(Result.failure(IllegalStateException("openpgp host not ready")))
                return@ensureReady
            }
            val wv = webView
            if (wv == null) {
                callback(Result.failure(IllegalStateException("webview missing")))
                return@ensureReady
            }
            // SI peel: JSON.parse(Buffer.from(decrypted, 'base64')) — encrypt base64(JSON).
            val opaque = android.util.Base64.encodeToString(
                plaintextJson.toByteArray(Charsets.UTF_8),
                android.util.Base64.NO_WRAP,
            )
            val requestId = nextJsRequestId()
            registerJsResult(requestId) { parsed ->
                if (!parsed.ok || !parsed.armor.contains("BEGIN PGP MESSAGE")) {
                    Log.e(TAG, "encrypt_to_route: ${parsed.error.ifBlank { "bad_armor" }}")
                    callback(Result.failure(IllegalStateException(parsed.error.ifBlank { "encrypt_fail" })))
                } else {
                    callback(Result.success(parsed.armor))
                }
            }
            val js = """
            (async function(){
              $JS_ARMOR_TO_STRING
              const requestId = ${jsString(requestId)};
              function post(payload) {
                try { BeamioOpenPgpAndroid.postResult(requestId, payload); } catch (_) {}
                return payload;
              }
              try {
                const publicKey = await openpgp.readKey({ armoredKey: ${jsString(routePublicArmor)} });
                const message = await openpgp.createMessage({ text: ${jsString(opaque)} });
                const encrypted = await openpgp.encrypt({
                  message,
                  encryptionKeys: publicKey,
                  format: 'armored',
                  config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
                });
                const armor = await armorToString(encrypted);
                if (!armor || armor.indexOf('BEGIN PGP MESSAGE') < 0) {
                  return post(JSON.stringify({ ok: false, error: 'encrypt_produced_no_armor type=' + typeof encrypted }));
                }
                return post(JSON.stringify({ ok: true, armor: armor }));
              } catch (e) {
                const msg = (e && e.message) ? e.message : String(e);
                return post(JSON.stringify({ ok: false, error: msg }));
              }
            })()
            """.trimIndent()
            main.post {
                wv.evaluateJavascript(js) { raw ->
                    if (!pendingJsResults.containsKey(requestId)) return@evaluateJavascript
                    val parsed = parseJsJsonResult(raw)
                    if (parsed == null) {
                        Log.e(TAG, "encrypt_to_route: empty/null evaluateJavascript raw=${raw?.take(120)}")
                        deliverJsResult(requestId, JsJsonResult(ok = false, error = "encrypt_fail_null"))
                    } else {
                        deliverJsResult(requestId, parsed)
                    }
                }
            }
        }
    }

    /**
     * Encrypt already-built inner OpenPGP armor to an entry route public key.
     * Literal plaintext is the **raw inner armor** (SI `tryReadInnerPgpMessage`).
     * Returns the inner armor unchanged when wrap is unsafe or encrypt fails.
     */
    fun wrapArmorToEntryRoute(
        innerArmor: String,
        entryRoutePublicArmor: String,
        callback: (Result<String>) -> Unit,
    ) {
        if (!innerArmor.contains("BEGIN PGP MESSAGE") || entryRoutePublicArmor.isBlank()) {
            callback(Result.success(innerArmor))
            return
        }
        ensureReady { ok ->
            if (!ok) {
                callback(Result.success(innerArmor))
                return@ensureReady
            }
            val wv = webView
            if (wv == null) {
                callback(Result.success(innerArmor))
                return@ensureReady
            }
            val js = """
            (async function(){
              $JS_ARMOR_TO_STRING
              try {
                const innerArmor = ${jsString(innerArmor)};
                const entryArmor = ${jsString(entryRoutePublicArmor)};
                const entryKey = await openpgp.readKey({ armoredKey: entryArmor });
                const entryIds = new Set(entryKey.getKeyIDs().map(id => id.toHex().toUpperCase()));
                const innerMsg = await openpgp.readMessage({ armoredMessage: innerArmor });
                const innerIds = innerMsg.getEncryptionKeyIDs().map(id => id.toHex().toUpperCase());
                if (!innerIds.length || innerIds.some(id => entryIds.has(id))) return innerArmor;
                const pgpMsg = await openpgp.createMessage({ text: innerArmor });
                const encrypted = await openpgp.encrypt({
                  message: pgpMsg,
                  encryptionKeys: entryKey,
                  format: 'armored',
                  config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
                });
                const out = await armorToString(encrypted);
                return out.includes('BEGIN PGP MESSAGE') ? out : innerArmor;
              } catch (e) {
                return ${jsString(innerArmor)};
              }
            })()
            """.trimIndent()
            main.post {
                wv.evaluateJavascript(js) { raw ->
                    val armor = unwrapJsString(raw)
                    callback(Result.success(if (armor.contains("BEGIN PGP MESSAGE")) armor else innerArmor))
                }
            }
        }
    }

    /**
     * Decrypt inbound user-PGP business armor → UTF-8 plaintext (base64 JSON or raw JSON).
     * Also returns keccak256(utf8(armor)) for delivery ACK parity with the TS worker.
     *
     * Uses [BeamioOpenPgpAndroid.postResult] — same as encrypt — because Chromium
     * `evaluateJavascript` often never delivers async IIFE Promise results, which left
     * inbound frames stuck after `inbound frame` with no decrypt ok/fail.
     */
    // ---- Module crypto (model 1B: the PWA signs, this host only encrypts / verifies) ----

    /**
     * Runs an async JS body in the host WebView. The body must `return post(JSON.stringify({ ok, … }))`;
     * [JS_ARMOR_TO_STRING] / `armorToString` is in scope. Results arrive over the
     * `BeamioOpenPgpAndroid.postResult` channel (Promise returns from `evaluateJavascript` are flaky).
     */
    /** Times the host was rebuilt (diagnostics only). */
    @Volatile var resetCount = 0
        private set

    /**
     * The hidden WebView died (renderer gone) or stopped answering. Without this,
     * `ready` stayed true and every later sign / encrypt / decrypt failed until
     * the app restarted, while inbound messages were dropped. The next call boots
     * a fresh WebView; calls still waiting fail now instead of after 25 s.
     */
    private fun resetHost(reason: String) {
        val run = Runnable {
            resetCount += 1
            Log.w(TAG, "host reset #$resetCount: $reason")
            webView?.let { wv ->
                try {
                    wv.removeJavascriptInterface("BeamioOpenPgpAndroid")
                    wv.destroy()
                } catch (_: Exception) {
                }
            }
            webView = null
            ready.set(false)
            bootstrapped.set(false)
            val waiting = pendingJsResults.keys.toList()
            for (id in waiting) deliverJsResult(id, JsJsonResult(ok = false, error = "host_reset"))
        }
        if (Looper.myLooper() == Looper.getMainLooper()) run.run() else main.post(run)
    }

    private fun runJsPost(body: String, callback: (JsJsonResult) -> Unit) {
        runJsPostOnce(body) { result ->
            // The host was rebuilt under this call: run it once more on the new one.
            if (!result.ok && (result.error == "host_reset" || result.error == "js_bridge_timeout")) {
                runJsPostOnce(body, callback)
            } else {
                callback(result)
            }
        }
    }

    private fun runJsPostOnce(body: String, callback: (JsJsonResult) -> Unit) {
        ensureReady { ok ->
            if (!ok) {
                callback(JsJsonResult(ok = false, error = "openpgp host not ready"))
                return@ensureReady
            }
            val wv = webView
            if (wv == null) {
                callback(JsJsonResult(ok = false, error = "webview missing"))
                return@ensureReady
            }
            val requestId = nextJsRequestId()
            registerJsResult(requestId, callback)
            val js = """
            (async function(){
              $JS_ARMOR_TO_STRING
              const requestId = ${jsString(requestId)};
              function post(payload) {
                try { BeamioOpenPgpAndroid.postResult(requestId, payload); } catch (_) {}
                return payload;
              }
              try {
                $body
              } catch (e) {
                const msg = (e && e.message) ? e.message : String(e);
                return post(JSON.stringify({ ok: false, error: msg }));
              }
            })()
            """.trimIndent()
            main.post {
                wv.evaluateJavascript(js) { raw ->
                    if (!pendingJsResults.containsKey(requestId)) return@evaluateJavascript
                    val parsed = parseJsJsonResult(raw) ?: return@evaluateJavascript
                    deliverJsResult(requestId, parsed)
                }
            }
        }
    }

    private fun armorOrError(parsed: JsJsonResult): Result<String> =
        if (parsed.ok && parsed.armor.contains("BEGIN PGP MESSAGE")) {
            Result.success(parsed.armor)
        } else {
            Result.failure(IllegalStateException(parsed.error.ifBlank { "encrypt_fail" }))
        }

    /** OpenPGP-encrypt [text] (already base64 / opaque) to [publicKeyArmor]. */
    fun encryptLiteral(
        text: String,
        publicKeyArmor: String,
        callback: (Result<String>) -> Unit,
    ) {
        if (!publicKeyArmor.contains("BEGIN PGP PUBLIC KEY")) {
            callback(Result.failure(IllegalStateException("missing_public_key")))
            return
        }
        runJsPost(
            """
            const publicKey = await openpgp.readKey({ armoredKey: ${jsString(publicKeyArmor)} });
            const pgpMsg = await openpgp.createMessage({ text: ${jsString(text)} });
            const encrypted = await openpgp.encrypt({
              message: pgpMsg,
              encryptionKeys: publicKey,
              format: 'armored',
              config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
            });
            const armor = await armorToString(encrypted);
            if (!armor || armor.indexOf('BEGIN PGP MESSAGE') < 0) {
              return post(JSON.stringify({ ok: false, error: 'encrypt_produced_no_armor' }));
            }
            return post(JSON.stringify({ ok: true, armor: armor }));
            """.trimIndent(),
        ) { callback(armorOrError(it)) }
    }

    /** Base64(UTF-8(JSON)) then encrypt to the recipient **user PGP** (outbound chat envelope). */
    fun encryptUtf8JsonBase64(
        jsonText: String,
        recipientPublicArmor: String,
        callback: (Result<String>) -> Unit,
    ) {
        val b64 = ConetChatCryptoUtil.base64Encode(jsonText.toByteArray(Charsets.UTF_8))
        encryptLiteral(b64, recipientPublicArmor, callback)
    }

    /**
     * 1B: the PWA already EIP-191-signed [message]; encrypt `{ message, signMessage }`
     * (base64) to a mailbox / entry **route** public key.
     */
    fun encryptSignedRouteCommand(
        message: String,
        signMessage: String,
        routePublicArmor: String,
        callback: (Result<String>) -> Unit,
    ) {
        if (!routePublicArmor.contains("BEGIN PGP PUBLIC KEY")) {
            callback(Result.failure(IllegalStateException("missing_route_public_key")))
            return
        }
        runJsPost(
            """
            const message = ${jsString(message)};
            const signMessage = ${jsString(signMessage)};
            const literal = btoa(unescape(encodeURIComponent(JSON.stringify({ message, signMessage }))));
            const publicKey = await openpgp.readKey({ armoredKey: ${jsString(routePublicArmor)} });
            const pgpMsg = await openpgp.createMessage({ text: literal });
            const encrypted = await openpgp.encrypt({
              message: pgpMsg,
              encryptionKeys: publicKey,
              format: 'armored',
              config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
            });
            const armor = await armorToString(encrypted);
            if (!armor || armor.indexOf('BEGIN PGP MESSAGE') < 0) {
              return post(JSON.stringify({ ok: false, error: 'encrypt_produced_no_armor' }));
            }
            return post(JSON.stringify({ ok: true, armor: armor }));
            """.trimIndent(),
        ) { callback(armorOrError(it)) }
    }

    /** Mailbox work: `{ data: innerArmor, NoPush?: true }` encrypted to the **B route** PGP. */
    fun wrapArmorToMailboxWork(
        innerArmor: String,
        mailboxRoutePublicArmor: String,
        noPush: Boolean,
        callback: (Result<String>) -> Unit,
    ) {
        if (!mailboxRoutePublicArmor.contains("BEGIN PGP PUBLIC KEY")) {
            callback(Result.failure(IllegalStateException("missing_mailbox_route_key")))
            return
        }
        runJsPost(
            """
            const innerArmor = ${jsString(innerArmor)};
            const mailboxKey = await openpgp.readKey({ armoredKey: ${jsString(mailboxRoutePublicArmor)} });
            const payload = { data: innerArmor };
            if (${if (noPush) "true" else "false"}) payload.NoPush = true;
            const pgpMsg = await openpgp.createMessage({ text: JSON.stringify(payload) });
            const encrypted = await openpgp.encrypt({
              message: pgpMsg,
              encryptionKeys: mailboxKey,
              format: 'armored',
              config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
            });
            const armor = await armorToString(encrypted);
            if (!armor || armor.indexOf('BEGIN PGP MESSAGE') < 0) {
              return post(JSON.stringify({ ok: false, error: 'encrypt_produced_no_armor' }));
            }
            return post(JSON.stringify({ ok: true, armor: armor }));
            """.trimIndent(),
        ) { callback(armorOrError(it)) }
    }

    /** Recovers the EIP-191 signer (`ethers.verifyMessage`). The recovered address is the only trusted sender. */
    fun verifyMessage(
        text: String,
        signature: String,
        callback: (Result<String>) -> Unit,
    ) {
        runJsPost(
            """
            const addr = ethers.verifyMessage(${jsString(text)}, ${jsString(signature)});
            return post(JSON.stringify({ ok: true, value: String(addr || '') }));
            """.trimIndent(),
        ) { parsed ->
            if (parsed.ok && parsed.value.isNotBlank()) {
                callback(Result.success(parsed.value))
            } else {
                callback(Result.failure(IllegalStateException(parsed.error.ifBlank { "verify_fail" })))
            }
        }
    }

    // The wallet signing functions (EIP-191, EIP-712, address) were removed from this host. They run in native code
    // in nativekey (Eip191Signer, Eip712, WalletAddress), so the wallet key never enters the WebView (AND-K-c2, A-4).

    /** Boots the hidden WebView (OpenPGP.js + ethers) once; [callback] gets `true` when usable. */
    fun ensureReady(callback: (Boolean) -> Unit) {
        if (ready.get()) {
            callback(true)
            return
        }
        pendingReady.add(callback)
        bootstrapIfNeeded()
    }

    private fun bootstrapIfNeeded() {
        if (!bootstrapped.compareAndSet(false, true)) return
        main.post {
            try {
                val wv = WebView(appContext).apply {
                    settings.javaScriptEnabled = true
                    addJavascriptInterface(Bridge(), "BeamioOpenPgpAndroid")
                    webViewClient = object : WebViewClient() {
                        // Without this the whole app is killed when the renderer dies.
                        @RequiresApi(Build.VERSION_CODES.O)
                        override fun onRenderProcessGone(view: WebView?, detail: RenderProcessGoneDetail?): Boolean {
                            resetHost("render process gone crashed=${detail?.didCrash()}")
                            return true
                        }
                    }
                }
                webView = wv
                val openpgp = loadAsset("ChatCrypto/openpgp.min.js")
                    ?: loadAsset("openpgp.min.js")
                val ethers = loadAsset("ChatCrypto/ethers.umd.min.js")
                    ?: loadAsset("ethers.umd.min.js")
                // The WebSocket guard runs first. Without it the host does not start (fail closed).
                val wsGuard = loadAsset("ChatCrypto/ws-guard.js")
                if (openpgp.isNullOrBlank() || ethers.isNullOrBlank() || wsGuard.isNullOrBlank()) {
                    Log.e(TAG, "missing bundled openpgp/ethers/ws-guard scripts")
                    flushReady(false)
                    return@post
                }
                val html = """
                <!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>
                <script>$wsGuard</script>
                <script>$ethers</script>
                <script>$openpgp</script>
                <script>
                (function(){
                  try {
                    if (typeof openpgp === 'undefined' || typeof ethers === 'undefined') {
                      BeamioOpenPgpAndroid.onReady(false);
                      return;
                    }
                    BeamioOpenPgpAndroid.onReady(true);
                  } catch (e) {
                    BeamioOpenPgpAndroid.onReady(false);
                  }
                })();
                </script>
                </body></html>
                """.trimIndent()
                wv.loadDataWithBaseURL(
                    "https://appassets.androidplatform.net/",
                    html,
                    "text/html",
                    "utf-8",
                    null,
                )
            } catch (error: Exception) {
                Log.e(TAG, "bootstrap failed: ${error.message}")
                flushReady(false)
            }
        }
    }

    private fun loadAsset(path: String): String? = try {
        appContext.assets.open(path).bufferedReader().use { it.readText() }
    } catch (_: Exception) {
        null
    }

    private fun flushReady(ok: Boolean) {
        ready.set(ok)
        while (true) {
            val cb = pendingReady.poll() ?: break
            try {
                cb(ok)
            } catch (_: Exception) {
            }
        }
    }

    private inner class Bridge {
        @JavascriptInterface
        fun onReady(ok: Boolean) {
            Log.i(TAG, "host ready=$ok")
            main.post { flushReady(ok) }
        }

        /** Primary async result channel for encrypt IIFEs (avoids flaky Promise→evaluateJavascript). */
        @JavascriptInterface
        fun postResult(requestId: String, json: String) {
            // Bridge thread, before the hop to main: when the JS finished.
            decryptTiming[requestId]?.let { if (it[2] == 0L) it[2] = SystemClock.elapsedRealtime() }
            main.post {
                val parsed = parseJsJsonResult(json)
                    ?: JsJsonResult(ok = false, error = "bad_bridge_json")
                deliverJsResult(requestId, parsed)
            }
        }
    }

    private fun jsString(raw: String): String {
        val escaped = raw
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        return "'$escaped'"
    }

    private fun unwrapJsString(raw: String?): String {
        if (raw.isNullOrBlank() || raw == "null") return ""
        var s = raw.trim()
        if (s.startsWith("\"") && s.endsWith("\"") && s.length >= 2) {
            s = s.substring(1, s.length - 1)
                .replace("\\\"", "\"")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\\\", "\\")
        }
        return s
    }
}
