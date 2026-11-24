package network.conet.chat.nativekey

import java.util.concurrent.ConcurrentHashMap

/**
 * The public part of an account's native PGP identity, kept in memory so `identityPublic` answers without opening the record.
 *
 * Why: the record is sealed by a StrongBox key whose single operation takes seconds on the S25, and the old answer opened it twice per call
 * (state, then identity). A call that waited behind other Keystore work was late, the page gave up after six tries, and the chat showed
 * "temporarily unavailable". Now one background read fills this snapshot; the command only reads it.
 *
 * What it holds: the account, whether the vault key is READY, NO_KEY or UNKNOWN, the uppercase master fingerprint, the key id of the first
 * subkey and the key's public armor. All of these are public (the key id is already in the `identityPublic` answer; the fingerprint names the public key). It holds NO private
 * armor, passphrase, sealed bytes or key of any kind, and it has no place to put one: [Facts] has only strings. A read that could not tell is UNKNOWN
 * and is recomputed.
 *
 * Validity: an entry belongs to ONE account (the key of the map) and is valid only while the record and marker files still have the signature
 * they had when it was read ([NativePgpVault.fileSignature], a plain-file digest, no Keystore). So a write, a restore, a clear, an erase or a
 * replacement by any code path makes the next lookup a miss, even when that code never called [invalidate]. [invalidate] is also called by the
 * vault's own `put` and `forget` before and after they act, and [invalidateAll] by account clear and switch. A miss is never answered from an old
 * value: the caller answers `not_ready` and asks for a refresh.
 *
 * A READY or NO_KEY entry stays valid as long as the files are unchanged; an UNKNOWN entry is a short-lived "could not tell" ([UNKNOWN_TTL_MS]),
 * after which a refresh is wanted (a transient Keystore failure must not stick).
 */
internal object PublicIdentitySnapshot {
    enum class Kind { READY, NO_KEY, UNKNOWN }

    /** Strings only, by design: no byte array, no key. */
    class Facts internal constructor(
        val account: String,
        val kind: Kind,
        /** The first subkey's key id (16 upper-case hex), or null when it could not be parsed. */
        val keyId: String?,
        /** The master fingerprint, upper case, or null. */
        val fingerprint: String?,
        /** The key's PUBLIC armor (what the registry holds), derived from the record in the same read, or null. Never the private armor. */
        val publicArmor: String?,
        internal val signature: String,
        internal val atMs: Long,
    )

    sealed class Lookup {
        class Hit(val facts: Facts) : Lookup()

        /** Nothing valid: the caller answers `not_ready` and asks for a refresh. */
        object Miss : Lookup()
    }

    const val UNKNOWN_TTL_MS = 5_000L

    private val map = ConcurrentHashMap<String, Facts>()

    /** The clock; tests move it. */
    @Volatile
    internal var nowMs: () -> Long = { System.currentTimeMillis() }

    /**
     * The entry for [account], valid against [signature] (the current file signature, from plain reads; null means the files cannot be read, so
     * nothing is valid). An entry whose signature differs is dropped. An UNKNOWN entry older than [UNKNOWN_TTL_MS] is a miss.
     */
    fun lookup(account: String, signature: String?): Lookup {
        val key = account.lowercase()
        val f = map[key] ?: return Lookup.Miss
        if (signature == null || f.signature != signature) {
            map.remove(key, f)
            return Lookup.Miss
        }
        if (f.kind == Kind.UNKNOWN && nowMs() - f.atMs >= UNKNOWN_TTL_MS) return Lookup.Miss
        return Lookup.Hit(f)
    }

    /** Drops the entry of [account]. */
    fun invalidate(account: String) {
        map.remove(account.lowercase())
    }

    /** Drops every entry (account clear and switch). */
    fun invalidateAll() {
        map.clear()
    }

    /**
     * Stores what one open of the record gave and returns the kind stored. The armor in [read], if any, is not touched and not kept.
     *
     * A READY record whose stored fingerprint differs from the fingerprint of the key it holds is stored as a short-lived UNKNOWN entry (no key id,
     * fingerprint or armor), never as READY, and it replaces any older entry of the account: the reconcile compares the two and answers RetryLater for
     * it, but with a READY entry the identity it would take is the key's own, so that comparison would be skipped and a record refused once would be
     * accepted afterwards. A normal write cannot make such a record; an outside rewrite can. UNKNOWN is not READY, so the reconcile never uses it; it
     * answers `identityPublic` as unknown (pgpReady false, pgpReadyKnown false), and lives [UNKNOWN_TTL_MS], so the record is read and compared again
     * only after that time, not on every page retry.
     */
    internal fun store(account: String, read: NativePgpVault.Read): Kind {
        val state = read.state
        val identity = read.identity
        if (state is NativePgpVault.State.Ready && identity != null && !state.fingerprint.equals(identity.fingerprint, ignoreCase = true)) {
            map[account.lowercase()] = Facts(account.lowercase(), Kind.UNKNOWN, null, null, null, read.signature, nowMs())
            return Kind.UNKNOWN
        }
        val kind = when (state) {
            is NativePgpVault.State.Ready -> Kind.READY
            is NativePgpVault.State.NoKey -> Kind.NO_KEY
            is NativePgpVault.State.Locked -> Kind.UNKNOWN
        }
        val fp = (state as? NativePgpVault.State.Ready)?.let { identity?.fingerprint ?: it.fingerprint.uppercase() }
        map[account.lowercase()] = Facts(account.lowercase(), kind, identity?.subkeyKeyId, fp, read.publicArmor, read.signature, nowMs())
        return kind
    }

    /**
     * Reads the record ONCE ([NativePgpVault.readOnce], one Keystore decrypt at most) and stores the public facts. Runs on the warm-up thread, never
     * on a command's thread. Returns the stored kind, or UNKNOWN when the read threw (nothing is stored then, so the next lookup misses).
     */
    fun refresh(vault: NativePgpVault): Kind {
        return try {
            store(vault.account, vault.readOnce(wantArmor = false))
        } catch (_: Exception) {
            Kind.UNKNOWN
        }
    }

    internal fun resetForTests() {
        map.clear()
        nowMs = { System.currentTimeMillis() }
    }
}
