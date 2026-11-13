package network.conet.chat.nativekey

/**
 * The native account-creation page (spec r3x §25.46). `nativeAccountCreateOpen` opens it in G0 only, and the decision is
 * [NativeOpenRules.accountCreateOpen]. The shell sets [launcher] to show its page. Not registered is `not_supported`;
 * registered but refused is `not_available`. The page itself is the shell's, and nothing from it passes through here.
 */
object NativeAccountCreateHost {
    @Volatile
    var launcher: (() -> Boolean)? = null

    /** `true` when the page opened. A launcher that throws counts as refused. */
    fun open(): Boolean = try {
        launcher?.invoke() == true
    } catch (_: Exception) {
        false
    }
}
