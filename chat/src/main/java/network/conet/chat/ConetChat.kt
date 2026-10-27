package network.conet.chat

import android.content.Context
import org.json.JSONObject

/**
 * Independent **Conet Chat Android module**.
 *
 * Host apps install this library (Gradle AAR / `:conet-chat` project), call
 * [install] once with crypto (+ optional persistence), then [start] / [stop].
 * Events are delivered via [bindEmitter] — hosts map them to WebView /
 * Broadcast / their own bus.
 *
 * TypeScript parity: `@conet.project/chat-sdk` mailbox `mailbox_listen`
 * (encrypt to B route PGP, HTTP via entry C ≠ B).
 */
object ConetChat {
    const val VERSION = "0.1.0"
    const val EVENT_ACTION = "conetChat"

    @Volatile
    private var crypto: ConetChatCrypto? = null

    @Volatile
    private var persistence: ConetChatPersistence? = null

    private val engine = ConetChatEngine()

    /**
     * Bind host crypto (required) and optional persistence before [start].
     * Safe to call multiple times; last install wins.
     */
    @JvmStatic
    fun install(crypto: ConetChatCrypto, persistence: ConetChatPersistence? = null) {
        this.crypto = crypto
        this.persistence = persistence
        engine.bindDeps(
            cryptoProvider = { this.crypto },
            persistenceProvider = { this.persistence },
        )
    }

    @JvmStatic
    fun isInstalled(): Boolean = crypto != null

    @JvmStatic
    fun isAvailable(): Boolean = isInstalled()

    @JvmStatic
    fun isRunning(): Boolean = engine.isRunning()

    @JvmStatic
    fun bindEmitter(emitter: ConetChatEmitter?) {
        engine.bindEmitter(emitter)
    }

    /**
     * Start (or replace) mailbox listen.
     * [initJson] fields: privateKeyHex, pgpPrivateKeyArmored, ownRouteArmoredPublicKey,
     * nodes[], mailboxIp?, eoa?, pgpPublicKeyArmored?, pgpPassphrase?
     */
    @JvmStatic
    fun start(context: Context, initJson: String): Boolean {
        if (crypto == null) {
            engine.emitStatus("error", "not_installed")
            return false
        }
        return engine.start(context, initJson)
    }

    @JvmStatic
    fun stop() {
        engine.stop()
    }

    @JvmStatic
    fun destroy() {
        engine.destroy()
    }

    @JvmStatic
    fun updateNodes(nodesJson: String): Boolean = engine.updateNodes(nodesJson)

    fun interface ConetChatEmitter {
        fun emit(detail: JSONObject)
    }
}
