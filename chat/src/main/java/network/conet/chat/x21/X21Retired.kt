package network.conet.chat.x21

/**
 * X-21 one-time wallet transfer is retired (project owner decision, 2026-11-12): no key crosses the
 * bridge in either direction, and no native import is done by transfer. The three commands are answered
 * with `not_supported` and produce no events. Key intake is native-only (see `nativekey`).
 */
object X21Retired {
    const val ERROR = "not_supported"

    val COMMANDS: Set<String> = setOf("walletTransferOnce", "walletTransferStatus", "walletTransferSwitched")

    fun handles(type: String): Boolean = type in COMMANDS
}
