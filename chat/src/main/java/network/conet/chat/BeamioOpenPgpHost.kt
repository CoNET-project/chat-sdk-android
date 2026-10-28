package network.conet.chat

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
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

    private fun nextJsRequestId(): String = "pgp_${jsRequestSeq.incrementAndGet()}"

    private fun registerJsResult(requestId: String, onResult: (JsJsonResult) -> Unit) {
        pendingJsResults[requestId] = onResult
        main.postDelayed({
            val stale = pendingJsResults.remove(requestId) ?: return@postDelayed
            Log.e(TAG, "js_bridge_timeout id=$requestId")
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

    fun decryptAndVerifyOffer(
        privateKeyArmor: String,
        offerArmor: String,
        callback: (Result<JSONObject>) -> Unit,
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
            val js = """
            (async function(){
              try {
                const message = await openpgp.readMessage({ armoredMessage: ${jsString(offerArmor)} });
                const privateKey = await openpgp.readPrivateKey({ armoredKey: ${jsString(privateKeyArmor)} });
                const { data } = await openpgp.decrypt({ message, decryptionKeys: privateKey });
                const text = typeof data === 'string' ? data : new TextDecoder().decode(data);
                let payload = null;
                try { payload = JSON.parse(text); } catch (_) {
                  try {
                    const b64 = atob(text.replace(/\s+/g,''));
                    payload = JSON.parse(b64);
                  } catch (e2) {
                    return JSON.stringify({ ok:false, error:'parse_fail' });
                  }
                }
                if (!payload || typeof payload !== 'object') {
                  return JSON.stringify({ ok:false, error:'empty_payload' });
                }
                const type = String(payload.type || '');
                if (type !== 'voice_call_offer_v1') {
                  return JSON.stringify({ ok:false, error:'not_offer' });
                }
                const from = String(payload.from || '').toLowerCase();
                const callerSignature = String(payload.callerSignature || '');
                const callId = String(payload.callId || '');
                const sessionId = String(payload.sessionId || '');
                const to = String(payload.to || '').toLowerCase();
                const createdAt = String(payload.createdAt || '');
                const expiresAt = String(payload.expiresAt || '');
                const timestamp = String(payload.timestamp || '');
                const sessionKey = String(payload.sessionKey || '');
                const tempWalletAddress = String(payload.tempWalletAddress || '').toLowerCase();
                const entryDomains = Array.isArray(payload.entryDomains)
                  ? payload.entryDomains.map(String).join(',')
                  : String(payload.entryDomains || '');
                const codec = String(payload.codec || '');
                const lines = [
                  'CoNET voice_call_offer_v1',
                  'callId:' + callId,
                  'sessionId:' + sessionId,
                  'to:' + to,
                  'createdAt:' + createdAt,
                  'expiresAt:' + expiresAt,
                  'timestamp:' + timestamp,
                  'sessionKey:' + sessionKey,
                  'tempWalletAddress:' + tempWalletAddress,
                  'entryDomains:' + entryDomains,
                  'codec:' + codec,
                ].join('\\n');
                let recovered = '';
                try {
                  recovered = String(ethers.verifyMessage(lines, callerSignature) || '').toLowerCase();
                } catch (e) {
                  return JSON.stringify({ ok:false, error:'verify_fail', detail:String(e) });
                }
                if (!recovered || !from || recovered !== from) {
                  return JSON.stringify({
                    ok:false,
                    error:'caller_mismatch',
                    recovered: recovered,
                    claimed: from,
                  });
                }
                return JSON.stringify({
                  ok:true,
                  callerEoa: recovered,
                  callId: callId,
                  sessionId: sessionId,
                  sessionKey: sessionKey,
                  to: to,
                  claimedTag: String(payload.beamioTag || payload.tag || ''),
                });
              } catch (e) {
                return JSON.stringify({ ok:false, error:String(e) });
              }
            })()
            """.trimIndent()
            main.post {
                wv.evaluateJavascript(js) { raw ->
                    try {
                        val unquoted = unwrapJsString(raw)
                        val obj = JSONObject(unquoted.ifBlank { "{}" })
                        if (obj.optBoolean("ok", false)) {
                            callback(Result.success(obj))
                        } else {
                            callback(
                                Result.failure(
                                    IllegalStateException(obj.optString("error", "decrypt_fail")),
                                ),
                            )
                        }
                    } catch (error: Exception) {
                        callback(Result.failure(error))
                    }
                }
            }
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
    fun decryptInboundArmor(
        privateKeyArmor: String,
        passphrase: String,
        armoredMessage: String,
        callback: (Result<DecryptInbound>) -> Unit,
    ) {
        ensureReady { ok ->
            if (!ok) {
                Log.e(TAG, "decrypt_inbound: openpgp host not ready")
                callback(Result.failure(IllegalStateException("openpgp host not ready")))
                return@ensureReady
            }
            val wv = webView
            if (wv == null) {
                Log.e(TAG, "decrypt_inbound: webview missing")
                callback(Result.failure(IllegalStateException("webview missing")))
                return@ensureReady
            }
            if (!privateKeyArmor.contains("BEGIN PGP PRIVATE KEY")) {
                Log.e(TAG, "decrypt_inbound: missing private key armor")
                callback(Result.failure(IllegalStateException("missing_private_key")))
                return@ensureReady
            }
            if (!armoredMessage.contains("BEGIN PGP MESSAGE")) {
                Log.e(TAG, "decrypt_inbound: missing message armor")
                callback(Result.failure(IllegalStateException("missing_message_armor")))
                return@ensureReady
            }
            val requestId = nextJsRequestId()
            Log.i(
                TAG,
                "decrypt_inbound: start id=$requestId armorChars=${armoredMessage.length}",
            )
            registerJsResult(requestId) { parsed ->
                if (!parsed.ok) {
                    Log.e(TAG, "decrypt_inbound: ${parsed.error.ifBlank { "decrypt_fail" }}")
                    callback(
                        Result.failure(
                            IllegalStateException(parsed.error.ifBlank { "decrypt_fail" }),
                        ),
                    )
                    return@registerJsResult
                }
                Log.i(
                    TAG,
                    "decrypt_inbound: ok id=$requestId textChars=${parsed.text.length} hash=${parsed.armorHash.take(18)}",
                )
                callback(
                    Result.success(
                        DecryptInbound(
                            text = parsed.text,
                            armorHash = parsed.armorHash,
                        ),
                    ),
                )
            }
            val js = """
            (async function(){
              const requestId = ${jsString(requestId)};
              function post(payload) {
                try { BeamioOpenPgpAndroid.postResult(requestId, payload); } catch (_) {}
                return payload;
              }
              try {
                const armoredMessage = ${jsString(armoredMessage)};
                const passphrase = ${jsString(passphrase)};
                let pk = await openpgp.readPrivateKey({ armoredKey: ${jsString(privateKeyArmor)} });
                if (!pk.isDecrypted() && passphrase.length) {
                  pk = await openpgp.decryptKey({ privateKey: pk, passphrase: passphrase });
                }
                const msg = await openpgp.readMessage({ armoredMessage: armoredMessage });
                const { data } = await openpgp.decrypt({ message: msg, decryptionKeys: pk });
                const text = typeof data === 'string' ? data : String(data);
                const armorHash = ethers.keccak256(ethers.toUtf8Bytes(armoredMessage));
                return post(JSON.stringify({ ok: true, text: text, armorHash: armorHash }));
              } catch (e) {
                const msg = (e && e.message) ? e.message : String(e);
                return post(JSON.stringify({ ok: false, error: msg }));
              }
            })()
            """.trimIndent()
            main.post {
                wv.evaluateJavascript(js) { raw ->
                    // Secondary path: Bridge.postResult is primary.
                    if (!pendingJsResults.containsKey(requestId)) return@evaluateJavascript
                    val parsed = parseJsJsonResult(raw)
                    if (parsed == null) {
                        Log.e(
                            TAG,
                            "decrypt_inbound: empty/null evaluateJavascript raw=${raw?.take(120)}",
                        )
                        // Do not fail yet — Bridge.postResult may still arrive.
                        return@evaluateJavascript
                    }
                    deliverJsResult(requestId, parsed)
                }
            }
        }
    }

    // ---- Module crypto (model 1B: the PWA signs, this host only encrypts / verifies) ----

    /**
     * Runs an async JS body in the host WebView. The body must `return post(JSON.stringify({ ok, … }))`;
     * [JS_ARMOR_TO_STRING] / `armorToString` is in scope. Results arrive over the
     * `BeamioOpenPgpAndroid.postResult` channel (Promise returns from `evaluateJavascript` are flaky).
     */
    private fun runJsPost(body: String, callback: (JsJsonResult) -> Unit) {
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

    data class DecryptInbound(
        val text: String,
        val armorHash: String,
    )

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
                    webViewClient = object : WebViewClient() {}
                }
                webView = wv
                val openpgp = loadAsset("ChatCrypto/openpgp.min.js")
                    ?: loadAsset("openpgp.min.js")
                val ethers = loadAsset("ChatCrypto/ethers.umd.min.js")
                    ?: loadAsset("ethers.umd.min.js")
                if (openpgp.isNullOrBlank() || ethers.isNullOrBlank()) {
                    Log.e(TAG, "missing bundled openpgp/ethers scripts")
                    flushReady(false)
                    return@post
                }
                val html = """
                <!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>
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
