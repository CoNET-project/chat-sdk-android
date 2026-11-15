package network.conet.chat.nativekey

/**
 * The nodes rule of `init` (PM R1841; the 930988d follow-up). A native init must not answer `ready` without a node roster,
 * because the page would then run with no chat route.
 *
 * - The payload has a `nodes` array and it is empty: `nodes_unavailable`. The session keeps the nodes it has.
 * - The payload has no `nodes` key and this device stores nodes: the stored nodes are used, and `ready` follows.
 * - The payload has no `nodes` key and this device stores no nodes: `nodes_unavailable`.
 * - Otherwise (a non-empty `nodes` array): the roster is taken from the payload, and `ready` follows.
 *
 * The EOA checks (`address_mismatch`) run before this rule. The function reads no state: the caller passes the counts.
 */
object InitNodesGate {
    const val NODES_UNAVAILABLE = "nodes_unavailable"

    /**
     * True when `init` must answer [NODES_UNAVAILABLE]. [nodesKeyPresent] is whether the payload carries a `nodes` key;
     * [payloadNodeCount] is its length (0 when absent); [storedNodeCount] is the number of nodes stored on this device.
     * [storedNodeCount] is read only when the key is absent.
     */
    fun unavailable(nodesKeyPresent: Boolean, payloadNodeCount: Int, storedNodeCount: Int): Boolean =
        if (nodesKeyPresent) payloadNodeCount == 0 else storedNodeCount == 0
}
