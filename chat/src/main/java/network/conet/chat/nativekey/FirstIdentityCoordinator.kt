package network.conet.chat.nativekey

import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

/**
 * The label of the native OpenPGP key generation for a new account, on the confirmed-no-record branch only. It is a
 * log label, not a switch: the global flag [PgpMigrationPolicy.OPENPGP_APPROVED] stays false and nothing else generates a key.
 */
internal const val FIRST_IDENTITY_APPROVAL = "confirmed-no-record"

/**
 * The route a first identity was registered on and read back: `identityPublic` gives the route armor only from a route that
 * was read back. The coordinator records the route key id here once the readback matched; the armor is the roster node's public key of that id.
 */
internal object FirstIdentityRegistered {
    private val routeOf = java.util.concurrent.ConcurrentHashMap<String, String>()

    fun record(eoa: String, routeKeyId: String) {
        routeOf[eoa.lowercase()] = routeKeyId
    }

    /** The public armor of the route [eoa] was registered on, from [roster] (route key id to armor); null when none was recorded or it is not in the roster. */
    fun routeArmor(eoa: String, roster: List<Pair<String, String>>): String? {
        val id = routeOf[eoa.lowercase()] ?: return null
        return roster.firstOrNull { it.first.equals(id, ignoreCase = true) }?.second?.takeIf { it.contains("BEGIN PGP PUBLIC KEY BLOCK") }
    }

    internal fun resetForTests() = routeOf.clear()
}

/** The mailbox node the SDK registers the account on: one that AddressPGP and GuardianNodesInfoV6 both record, none, or a check that failed. */
internal sealed class RouteChoice {
    class Ok(val routeKeyId: String) : RouteChoice()
    object None : RouteChoice()
    object Unreadable : RouteChoice()
}

/**
 * Whether the material the account's key needs is available now. [LOCKED] is only "the passcode package is not provided" (a store v3 set the session has
 * no key for); [UNKNOWN] is a storage state that cannot be read. No UI lock or application lock is a state here, and none is read.
 */
internal enum class LockState { UNLOCKED, LOCKED, UNKNOWN }

/**
 * The first identity of an account: the SDK checks the local PGP, reads the registry (both endpoints at one block), and only on
 * a confirmed "no record" generates a native OpenPGP key, keeps it pending, registers it (the existing EIP-191 route, one submission per account) and
 * reads it back before the key becomes the active identity. Nothing here overwrites a registered key.
 *
 *  S0 local: an active key (not this coordinator's case), a pending key with its metadata (resume at S3, never regenerate), a locked or unreadable
 *     slot (retry), a K-only account (see S2). S1 chain: unreadable or divergent = retry; registered = recovery (the recovery flow, not here);
 *     no record = S2. S2 generate (only here): discard a K-only old key (never registered, never on the chain), generate, put it pending with its
 *     metadata. S3 before submit: read again; empty = continue, our key = S5, another key = conflict (pending erased, nothing submitted). S4 write the
 *     registering marker, sign and submit (one in flight per account). S5 read back (bounded poll) the key and the route. S6 activate (pending to
 *     active), mirror K, clear the marker and the pending key. The three reads (before generating, before submitting, after submitting) shrink the
 *     window in which another device could register the same account; the contract does not check existence, so this stays a client rule.
 */
internal class FirstIdentityCoordinator(
    private val eoa: String,
    private val dev: PgpRestoreDevice,
    private val k: AccountPgpK,
    /** The authoritative read of the registered key (both endpoints at one block). */
    private val readKey: () -> RegisteredKeyRead,
    /** The chain identity (key and route) for the readback. */
    private val readIdentity: () -> ChainIdentityRead,
    /** True when an older build left a private key for this account in the SDK store, null when that cannot be read. */
    private val legacyKeyPresent: () -> Boolean?,
    private val generate: () -> NativePgpKeyGen.Generated = { NativePgpKeyGen.generate(eoa, SecureRandom()) },
    /** The mailbox node the SDK picks (read-only precheck done), memoized by the caller so one run uses one route. */
    private val chooseRoute: () -> RouteChoice,
    /** The account key (the wallet key or the store account's key); the caller zeroes nothing, the coordinator zeroes its copy. */
    private val eoaKey: () -> ByteArray?,
    private val bases: List<String>,
    private val poster: ChatRouteSubmit.Poster,
    private val sleep: (Long) -> Boolean = { Thread.sleep(it); true },
    private val pollDelaysMs: LongArray = RegistrationReadback.POLL_DELAYS_MS,
    private val nowMs: () -> Long = { System.currentTimeMillis() },
    private val newIdemKey: () -> String = { UUID.randomUUID().toString() },
    private val flightEnter: (String) -> Boolean = IdentityRegisterFlight::tryEnter,
    private val flightExit: (String) -> Unit = IdentityRegisterFlight::exit,
    private val log: (String) -> Unit = {},
    /** Status events (registering, registered, retry_later, identity_pending, failed), with their reason, attempt and retry delay. */
    private val emit: (FirstIdentityStatus) -> Unit = {},
    private val submitTimeoutMs: Int = 12_000,
    /** The lock of the account's key now. Checked before every generation, decision, submission and activation write. */
    private val lockState: () -> LockState = { LockState.UNLOCKED },
    /** What this run may do. The default build runs [Mode.RECONCILE_ONLY]; the full first-identity machine is a QA build's ([Mode.FULL]). */
    private val mode: Mode = Mode.FULL,
) {
    /**
     * [FULL]: every step below (S0 to S6): pending resume, generation, discard of a K-only key, submission, activation.
     * [RECONCILE_ONLY] (the default build): only an ACTIVE key's registration is reconciled with the same key
     * (S0 for an active key, [reconcileActive]); a run with no active key is [Result.NotApplicable] and reads or writes nothing: no generation, no
     * pending key, no K-only discard, no activation, no cleanup of a pending key.
     */
    enum class Mode { FULL, RECONCILE_ONLY }

    sealed class Result(val code: String) {
        /** Not this coordinator's case: the vault already holds an active key, or the chain holds a registration (the recovery takes over). */
        class Recovery(code: String) : Result(code)
        class NotApplicable : Result("not_applicable")
        class RetryLater(val reason: String) : Result("retry_later:$reason")
        object Registered : Result("registered")
        object Conflict : Result("conflict")
        class Failed(val reason: String) : Result("failed:$reason")
    }

    private val account = eoa.lowercase()

    /** null when the account is unlocked; otherwise the retry answer (nothing may be generated, written or submitted). */
    private fun notUnlocked(): Result.RetryLater? = when (lockState()) {
        LockState.UNLOCKED -> null
        LockState.LOCKED -> Result.RetryLater("passcode_not_provided")
        LockState.UNKNOWN -> Result.RetryLater("not_ready")
    }

    fun run(): Result {
        val result = try {
            runLocked()
        } catch (e: Exception) {
            Result.RetryLater("exception:" + e.javaClass.simpleName)
        }
        log(result.code)
        statusOf(result)?.let { emit(it) }
        if (result is Result.Registered) attempts.remove(account)
        return result
    }

    /**
     * The status the page sees for a run's result. A run that stopped because the material is unavailable (passcode package,
     * unreadable storage) or because another registration is in flight sends nothing. A readback that did not show the key in the window is retry_later
     * (readback_timeout) twice, then identity_pending (the pending key is kept, never regenerated); a read that failed is retry_later (read_unavailable).
     */
    private fun statusOf(result: Result): FirstIdentityStatus? = when (result) {
        is Result.Registered -> FirstIdentityStatus("registered")
        is Result.Conflict -> FirstIdentityStatus("failed", "conflict_other_key")
        is Result.Failed -> FirstIdentityStatus("failed", "submit_4xx")
        is Result.RetryLater -> when (result.reason) {
            "passcode_not_provided", "not_ready", "busy", "vault_locked", "pending_locked" -> null
            else -> {
                val n = attempts.merge(account, 1) { a, b -> a + b } ?: 1
                when (result.reason) {
                    "not_confirmed_in_window" ->
                        if (n >= IDENTITY_PENDING_AFTER) FirstIdentityStatus("identity_pending", "readback_timeout", n)
                        else FirstIdentityStatus("retry_later", "readback_timeout", n, KpgpUpgradeTrigger.delayMs(n))
                    "chain_unreadable", "route_check_failed" -> FirstIdentityStatus("retry_later", "read_unavailable", n, KpgpUpgradeTrigger.delayMs(n))
                    "network_unavailable" -> FirstIdentityStatus("retry_later", "submit_5xx", n, KpgpUpgradeTrigger.delayMs(n))
                    else -> FirstIdentityStatus("retry_later", null, n, KpgpUpgradeTrigger.delayMs(n))
                }
            }
        }
        else -> null
    }

    private fun runLocked(): Result {
        if (mode == Mode.RECONCILE_ONLY) return runReconcileOnly()
        // ---- S0: the local state --------------------------------------------------------------------------------------------------------------
        val active = dev.active.state()
        val pendingState = dev.pending.state()
        if (active is NativePgpVault.State.Ready) {
            // An interrupted S6 (the active key is written, the cleanup is not): finish it. Anything else is the existing flows' case.
            val meta = try { dev.pendingMeta() } catch (_: Exception) { return Result.RetryLater("pending_meta_unreadable") }
            if (pendingState is NativePgpVault.State.Ready && meta != null && active.fingerprint.equals(pendingFingerprint(), ignoreCase = true)) {
                notUnlocked()?.let { return it }
                return finish(meta)
            }
            return reconcileActive(active.fingerprint)
        }
        if (active is NativePgpVault.State.Locked) return Result.RetryLater("vault_locked")
        var meta: PendingMeta? = null
        when (pendingState) {
            is NativePgpVault.State.Locked -> return Result.RetryLater("pending_locked")
            is NativePgpVault.State.Ready -> {
                meta = try { dev.pendingMeta() } catch (_: Exception) { return Result.RetryLater("pending_meta_unreadable") }
                if (meta == null) {
                    // A pending key without its metadata is an orphan (a failed erase): never used, erased first.
                    if (!dev.clearPending()) return Result.RetryLater("orphan_erase_failed")
                }
            }
            is NativePgpVault.State.NoKey -> Unit
        }
        if (meta != null && dev.pendingDisabled()) return Result.RetryLater("pending_disabled")

        if (meta != null) return submitFlow(meta, resume = true)

        // ---- S1: the authoritative chain read -----------------------------------------------------------------------------------------------
        val kOnly = try { k.existsFor(account, PgpMigrationPolicy.WORKSPACE) } catch (_: Exception) { return Result.RetryLater("k_unreadable") }
        when (readKey()) {
            is RegisteredKeyRead.Unknown -> return Result.RetryLater("chain_unreadable")
            is RegisteredKeyRead.Present -> return Result.Recovery("registered")
            is RegisteredKeyRead.Absent -> Unit
        }
        // A key an older build left in the SDK store is not replaced by a generated one (local PGP, unknown, or present: no generation).
        when (legacyKeyPresent()) {
            null -> return Result.RetryLater("legacy_unreadable")
            true -> return Result.RetryLater("legacy_key_present")
            false -> Unit
        }
        when (chooseRoute()) {
            is RouteChoice.Ok -> Unit
            is RouteChoice.None -> return Result.RetryLater("no_route")
            is RouteChoice.Unreadable -> return Result.RetryLater("route_check_failed")
        }

        // ---- S2: generate (only here) --------------------------------------------------------------------------------------------------------
        notUnlocked()?.let { return it }
        // The old K-only key was never registered and is not on the chain (the read above): it is discarded, not adopted.
        if (kOnly && !k.discard(account, PgpMigrationPolicy.WORKSPACE)) return Result.RetryLater("k_discard_failed")
        val generated = generate()
        log("generate approval=$FIRST_IDENTITY_APPROVAL")
        val put = dev.pending.put(account, generated.privateArmor, "")
        if (put != NativePgpVault.Put.OK) return Result.RetryLater("pending_put_" + put.code)
        val newMeta = PendingMeta(newIdemKey(), 0L, "first")
        try {
            dev.writePendingMeta(newMeta)
        } catch (_: Exception) {
            dev.clearPending()
            return Result.RetryLater("pending_meta_write_failed")
        }
        return submitFlow(newMeta, resume = false)
    }

    /**
     * The default build's whole run: read the active slot and reconcile its key, or do nothing. The slot was opened twice
     * for this (`state()`, then `identity()`: two StrongBox decrypts, ~4 s each on the S25). Now: the public identity snapshot when it has a valid entry
     * (the record and marker files still have the signature they had when it was read: no decrypt at all), else ONE read ([NativePgpVault.readOnce]),
     * which also fills the snapshot. A snapshot entry without both the fingerprint and the key id, or one that does not say READY, is not used. Only
     * public values are taken from it; signing a registration (a missing route) still opens the key, as before. The full mode never takes this path.
     */
    private fun runReconcileOnly(): Result {
        activeIdentityFromSnapshot()?.let { return reconcileActive(it.fingerprint, it) }
        val read = dev.active.readOnce(wantArmor = false)
        PublicIdentitySnapshot.store(dev.active.account, read)
        val state = read.state
        if (state !is NativePgpVault.State.Ready) return Result.NotApplicable()
        val identity = read.identity ?: return Result.RetryLater("active_unreadable")
        return reconcileActive(state.fingerprint, identity)
    }

    /** The active key's identity from a valid READY snapshot entry that holds both the fingerprint and the key id; null otherwise (never a decrypt). */
    private fun activeIdentityFromSnapshot(): PgpIdentity? {
        val signature = dev.active.fileSignature() ?: return null
        val hit = PublicIdentitySnapshot.lookup(dev.active.account, signature) as? PublicIdentitySnapshot.Lookup.Hit ?: return null
        val facts = hit.facts
        if (facts.kind != PublicIdentitySnapshot.Kind.READY) return null
        val fingerprint = facts.fingerprint?.takeIf { it.isNotEmpty() } ?: return null
        val keyId = facts.keyId?.takeIf { it.isNotEmpty() } ?: return null
        return PgpIdentity(fingerprint, keyId)
    }

    /**
     * S0 for an active key: the same key's registration is reconciled, never replaced. Done = our key and a route on the chain. A missing route or no
     * record submits this key once; another key is a conflict (nothing written). The lock is checked before the decision and before the submission.
     */
    private fun reconcileActive(activeFingerprint: String, known: PgpIdentity? = null): Result {
        val identity = known ?: (try { dev.active.identity() } catch (_: Exception) { null }) ?: return Result.RetryLater("active_unreadable")
        if (!identity.fingerprint.equals(activeFingerprint, ignoreCase = true)) return Result.RetryLater("active_unreadable")
        notUnlocked()?.let { return it }
        val read = readIdentity()
        var route: String? = null
        when (read) {
            is ChainIdentityRead.Unknown -> return Result.RetryLater("chain_unreadable")
            is ChainIdentityRead.Absent -> Unit
            is ChainIdentityRead.Present -> {
                val v = read.view
                if (!v.fingerprint.equals(identity.fingerprint, ignoreCase = true) || !v.subkeyKeyId.equals(identity.subkeyKeyId, ignoreCase = true)) {
                    // Another key is registered: nothing is written from here (the page or the recovery decides).
                    return Result.Conflict
                }
                if (!v.routeKeyId.isNullOrBlank()) {
                    FirstIdentityRegistered.record(account, v.routeKeyId)
                    return Result.Registered
                }
                route = null
            }
        }
        val routeKeyId = route ?: when (val c = chooseRoute()) {
            is RouteChoice.Ok -> c.routeKeyId
            is RouteChoice.None -> return Result.RetryLater("no_route")
            is RouteChoice.Unreadable -> return Result.RetryLater("route_check_failed")
        }
        val expected = RegistrationReadback.Expected(identity.fingerprint, identity.subkeyKeyId, routeKeyId)
        notUnlocked()?.let { return it }
        if (!flightEnter(account)) return Result.RetryLater("busy")
        try {
            emit(FirstIdentityStatus("registering"))
            val key = eoaKey() ?: return Result.RetryLater("account_key_unavailable")
            val outcome = try {
                submit(key, identity, routeKeyId, expected, dev.active)
            } finally {
                key.fill(0)
            }
            return when (outcome) {
                is ChatRouteSubmit.Outcome.Submitted -> { FirstIdentityRegistered.record(account, routeKeyId); Result.Registered }
                is ChatRouteSubmit.Outcome.Conflict -> Result.Conflict
                is ChatRouteSubmit.Outcome.UnverifiedSubmit -> Result.RetryLater("not_confirmed_in_window")
                is ChatRouteSubmit.Outcome.NetworkUnavailable -> Result.RetryLater("network_unavailable")
                is ChatRouteSubmit.Outcome.Refused -> Result.Failed(outcome.code)
            }
        } finally {
            flightExit(account)
        }
    }

    private fun pendingFingerprint(): String? = try {
        (dev.pending.state() as? NativePgpVault.State.Ready)?.fingerprint
    } catch (_: Exception) {
        null
    }

    // ---- S3 to S5 ----------------------------------------------------------------------------------------------------------------------------
    private fun submitFlow(meta: PendingMeta, resume: Boolean): Result {
        notUnlocked()?.let { return it }
        val pendingIdentity = pendingIdentity() ?: return Result.RetryLater("pending_unreadable")
        val routeKeyId = when (val c = chooseRoute()) {
            is RouteChoice.Ok -> c.routeKeyId
            is RouteChoice.None -> return Result.RetryLater("no_route")
            is RouteChoice.Unreadable -> return Result.RetryLater("route_check_failed")
        }
        val expected = RegistrationReadback.Expected(pendingIdentity.fingerprint, pendingIdentity.subkeyKeyId, routeKeyId)
        // S3: read again before signing.
        when (val before = RegistrationReadback.verdict(expected, readIdentity())) {
            ChainState.UNKNOWN -> return Result.RetryLater("chain_unreadable")
            ChainState.CONFLICT -> return conflict()
            ChainState.MATCH -> { FirstIdentityRegistered.record(account, routeKeyId); return activate(meta) }
            ChainState.ABSENT -> Unit
        }
        // The reads took time: the lock is checked again before the marker and the submission.
        notUnlocked()?.let { return it }
        if (!flightEnter(account)) return Result.RetryLater("busy")
        try {
            // S4: the registering marker is written before the submission and cleared only after the active key is written.
            runCatching { dev.markRegistering(null) }.onFailure { return Result.RetryLater("marker_write_failed") }
            // A key generated in this run follows a confirmed no-record read; a resumed key does not say so.
            emit(FirstIdentityStatus("registering", if (resume) null else "no_record_confirmed"))
            val key = eoaKey() ?: return Result.RetryLater("account_key_unavailable")
            val outcome = try {
                submit(key, pendingIdentity, routeKeyId, expected)
            } finally {
                key.fill(0)
            }
            return when (outcome) {
                is ChatRouteSubmit.Outcome.Submitted -> { FirstIdentityRegistered.record(account, routeKeyId); activate(meta) }
                is ChatRouteSubmit.Outcome.Conflict -> conflict()
                is ChatRouteSubmit.Outcome.UnverifiedSubmit -> Result.RetryLater("not_confirmed_in_window")
                is ChatRouteSubmit.Outcome.NetworkUnavailable -> Result.RetryLater("network_unavailable")
                is ChatRouteSubmit.Outcome.Refused -> Result.Failed(outcome.code)
            }
        } finally {
            flightExit(account)
        }
    }

    private fun pendingIdentity(): PgpIdentity? {
        val bytes = dev.pending.armorForMove() ?: return null
        return try {
            NativePgpKeyGen.publicArmorOf(String(bytes, Charsets.UTF_8))?.let { PgpPublicIdentity.parse(it) }
        } finally {
            bytes.fill(0)
        }
    }

    private fun submit(
        accountKey: ByteArray,
        identity: PgpIdentity,
        routeKeyId: String,
        expected: RegistrationReadback.Expected,
        vault: NativePgpVault = dev.pending,
    ): ChatRouteSubmit.Outcome {
        val armor = vault.armorForMove() ?: return ChatRouteSubmit.Outcome.Refused("no_pgp_key")
        val publicArmor = try {
            NativePgpKeyGen.publicArmorOf(String(armor, Charsets.UTF_8))
        } catch (_: Exception) {
            null
        }
        if (publicArmor == null) {
            armor.fill(0)
            return ChatRouteSubmit.Outcome.Refused("no_pgp_key")
        }
        val request = ChatRouteRegister.Request(
            identity.subkeyKeyId,
            Base64.getEncoder().encodeToString(publicArmor.toByteArray(Charsets.UTF_8)),
            routeKeyId,
        )
        val random = SecureRandom()
        return try {
            ChatRouteSubmit.submit(
                bases = bases,
                bodyFor = { _ ->
                    val nonce = "0x" + ByteArray(16).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                    val iv = ByteArray(12).also { random.nextBytes(it) }
                    when (val built = ChatRouteRegister.build(request, account, accountKey, armor, nowMs(), nonce, iv)) {
                        is ChatRouteRegister.Built.Ok -> ChatRouteSubmit.bodyOf(built)
                        is ChatRouteRegister.Built.Refused -> null
                    }
                },
                poster = poster,
                chain = RegistrationReadback.check(expected, readIdentity, sleep, pollDelaysMs),
                timeoutMs = submitTimeoutMs,
                pause = { sleep(it) },
            )
        } finally {
            armor.fill(0)
        }
    }

    private fun conflict(): Result {
        // The chain holds another key: the pending key was never registered and is erased; nothing is submitted. The recovery takes over.
        dev.clearPending()
        runCatching { dev.clearRegistering() }
        return Result.Conflict
    }

    // ---- S6 --------------------------------------------------------------------------------------------------------------------------------------
    private fun activate(meta: PendingMeta): Result {
        notUnlocked()?.let { return it }
        val armorBytes = dev.pending.pendingArmorForActivation() ?: return Result.RetryLater("pending_unreadable")
        val armor = try {
            String(armorBytes, Charsets.UTF_8)
        } finally {
            armorBytes.fill(0)
        }
        val put = dev.active.put(account, armor, "")
        val holds = put == NativePgpVault.Put.OK ||
            (dev.active.state() is NativePgpVault.State.Ready && (dev.active.state() as NativePgpVault.State.Ready).fingerprint.equals(pendingFingerprint(), ignoreCase = true))
        if (!holds) return Result.RetryLater("activate_failed")
        return finish(meta)
    }

    /** The active key is written: mirror K (a failure keeps the pending key and retries only this), then clear the marker and the pending key. */
    private fun finish(meta: PendingMeta): Result {
        notUnlocked()?.let { return it }
        val armorBytes = dev.pending.armorForMove() ?: return Result.RetryLater("pending_unreadable")
        val armor = try { String(armorBytes, Charsets.UTF_8) } finally { armorBytes.fill(0) }
        val publicArmor = NativePgpKeyGen.publicArmorOf(armor) ?: return Result.RetryLater("pending_unreadable")
        val identity = PgpPublicIdentity.parse(publicArmor) ?: return Result.RetryLater("pending_unreadable")
        val written = try {
            k.writeIfAbsent(account, PgpMigrationPolicy.WORKSPACE, identity.subkeyKeyId, publicArmor, armor, nowMs() / 1000L)
        } catch (_: Exception) {
            null
        }
        if (written != AccountPgpKWrite.WRITTEN && written != AccountPgpKWrite.EXISTS) return Result.RetryLater("k_mirror_failed")
        runCatching { dev.setCompletedIdem(meta.idemKey) }
        runCatching { dev.clearRegistering() }
        if (!dev.clearPending()) return Result.RetryLater("pending_clear_failed")
        return Result.Registered
    }

    companion object {
        /** After this many windows without a readback the status is identity_pending instead of retry_later. */
        const val IDENTITY_PENDING_AFTER = 3

        private val attempts = java.util.concurrent.ConcurrentHashMap<String, Int>()

        internal fun resetAttemptsForTests() = attempts.clear()
    }
}
