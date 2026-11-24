package network.conet.chat.nativekey

/**
 * What a command that needs the vault's gate reads, without waiting and without the keystore.
 *
 * `pgpMigrate` and `pgpDecryptInbound` used `vault.state()` (the monitor, which a cold compute holds for seconds) and then `keyOnlyLive()` (a live
 * compute: PRESENCE and two StrongBox decrypts, ~10 s on the S25). The first `pgpMigrate` of a cold start held the single chat-command queue for 36.8 s,
 * so `hello` was not answered and the page showed "wallet not ready"; every inbound message paid two more decrypts.
 *
 *  - [state]: the snapshot after the discard-intent check ([NativeWalletVault.stateIfKnown]); null when it is not known yet, which the caller answers
 *    as unknown (`not_ready`) after asking for a refresh. Never the monitor.
 *  - [keyOnly]: asked only when it can change the gate. [NoKeyGate.gateOf] reads it only for a Ready state with a ready session (a key-only record
 *    is no account, so it never reaches G2); for every other state or session it is false and not read. When it is read, it is the snapshot's flag
 *    VOUCHED by the records' signature ([NativeWalletVault.keyOnlyIfVerified]); if the files changed outside the vault it is read live, exactly as
 *    before ([NativeWalletVault.keyOnlyLive]), so a key-only account is never taken for an account.
 */
internal class VaultGateRead(val state: NativeWalletVault.State?, val keyOnly: Boolean)

internal object VaultGateReader {
    fun read(vault: NativeWalletVault, sessionReady: Boolean): VaultGateRead {
        val state = vault.stateIfKnown()
        val keyOnly = if (state is NativeWalletVault.State.Ready && sessionReady) vault.keyOnlyChecked() else false
        return VaultGateRead(state, keyOnly)
    }
}
