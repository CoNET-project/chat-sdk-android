package network.conet.chat

/**
 * Zeroizes key buffers in place (spec T-49: after the wipe every byte is zero). A null buffer is skipped. Used by the teardown paths so a
 * key is never left in memory after its owner drops the reference.
 */
internal object KeyWipe {
    fun wipe(vararg buffers: ByteArray?) {
        for (b in buffers) b?.fill(0)
    }
}
