package network.conet.chat

/**
 * Optional host persistence for mailbox IP / PGP armor used by killed-app paths
 * (voice, offline). The listen session itself keeps secrets **in memory only**.
 * Never persist EOA private-key hex.
 */
interface ConetChatPersistence {
    fun loadMailboxIp(): String?

    fun upsertIdentity(
        pgpPrivateArmor: String,
        pgpPublicArmor: String,
        routePublicArmor: String,
        eoa: String,
    )

    fun storeRoster(nodes: List<ConetChatNode>, mailboxIp: String)
}

data class ConetChatNode(
    val ip: String,
    val domain: String = "",
    val region: String = "",
    val armoredPublicKey: String = "",
)
