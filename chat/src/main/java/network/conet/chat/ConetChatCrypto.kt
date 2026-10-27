package network.conet.chat

/**
 * Host-provided OpenPGP + EIP-191 crypto.
 *
 * The library never embeds OpenPGP.js / WebView — the host app installs an
 * implementation (e.g. Beamio [BeamioOpenPgpHost] adapter) when calling
 * [ConetChat.install].
 */
interface ConetChatCrypto {
    /**
     * EIP-191 sign [commandJson] then encrypt `{ message, signMessage }` to
     * mailbox **B route PGP**. Returns OpenPGP armor or failure.
     */
    fun encryptRouteCommand(
        privateKeyHex: String,
        commandJson: String,
        routePublicArmor: String,
        callback: (Result<String>) -> Unit,
    )

    /**
     * Wrap inner mailbox armor to entry **C** route PGP (or return inner unchanged).
     */
    fun wrapArmorToEntryRoute(
        innerArmor: String,
        entryRoutePublicArmor: String,
        callback: (Result<String>) -> Unit,
    )

    /**
     * Decrypt inbound user-PGP business armor → plaintext + armorHash.
     */
    fun decryptInboundArmor(
        privateKeyArmor: String,
        passphrase: String,
        armoredMessage: String,
        callback: (Result<ConetChatDecryptInbound>) -> Unit,
    )
}

data class ConetChatDecryptInbound(
    val text: String,
    val armorHash: String,
)
