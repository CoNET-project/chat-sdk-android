package network.conet.chat.nativekey

/**
 * The production source of `identityPublic`: the public facts come from [PublicIdentitySnapshot] only. [factsOf] returns the valid entry
 * of the session's account or null (and has asked for one refresh); it is read once per call. With no valid entry [pgpAvailable] is false, so the
 * answer is `not_ready` and never the older record path (`pgp()` answers NotRead, which would read as a confirmed "no key": `pgpReady:false`).
 * Nothing here opens the Keystore.
 */
internal class SnapshotIdentitySource(
    private val eoaOf: () -> String?,
    factsOf: () -> PublicIdentitySnapshot.Facts?,
    /** The route's public armor (plain store reads, no Keystore). */
    private val routeArmorOf: () -> String?,
    private val kPresentOf: () -> Boolean?,
) : IdentityPublic.Source {
    private val facts: PublicIdentitySnapshot.Facts? by lazy(factsOf)

    override fun eoa(): String? = eoaOf()

    override fun pgp(): IdentityPublic.PgpRecord = IdentityPublic.PgpRecord.NotRead

    override fun pgpAvailable(): Boolean = facts != null

    override fun pgpState(): IdentityPublic.PgpState? = when (facts?.kind) {
        PublicIdentitySnapshot.Kind.READY -> IdentityPublic.PgpState.READY
        PublicIdentitySnapshot.Kind.NO_KEY -> IdentityPublic.PgpState.NOT_READY
        PublicIdentitySnapshot.Kind.UNKNOWN -> IdentityPublic.PgpState.UNKNOWN
        null -> null
    }

    override fun pgpKeyId(): String? = facts?.keyId

    /** The key's public armor, from the snapshot (derived in the single read that gave the key id; public part only). */
    override fun pgpPublicArmor(): String? = facts?.publicArmor

    override fun ownRouteArmor(): String? = routeArmorOf()

    override fun kPresent(): Boolean? = kPresentOf()
}
